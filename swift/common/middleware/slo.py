# Copyright (c) 2013 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from xml.etree import ElementTree
from xml.parsers.expat import ExpatError
from xml.sax import saxutils
from urllib import quote
from cStringIO import StringIO
from datetime import datetime
import mimetypes
from swift.common.swob import Request, HTTPBadRequest, HTTPNotAcceptable, \
    HTTPServerError, HTTPMethodNotAllowed, HTTPRequestEntityTooLarge, wsgify
from swift.common.wsgi import WSGIContext
from swift.common.utils import split_path, TRUE_VALUES, json, get_logger
from swift.common.constraints import check_metadata
from swift.common.middleware.bulk import get_response_body, \
    ACCEPTABLE_FORMATS, Bulk


def format_manifest(data, data_format):
    """
    Builds manifest response body out of data in given data_format
    :raises KeyError or TypeError if manifest file is invalid
    """
    if data_format == 'xml':
        output = \
            '<?xml version="1.0" encoding="UTF-8"?>\n<static_large_object>\n'
        for data_dict in data:
            output += '<object_segment>\n'
            for data_key, tag in [('name', 'path'),
                                  ('hash', 'etag'),
                                  ('bytes', 'size_bytes')]:
                output += \
                    '<%s>%s</%s>\n' % (
                    tag, saxutils.escape(str(data_dict[data_key])), tag)
            output += '</object_segment>\n'
        output += '</static_large_object>\n'
        return output

    elif data_format == 'json':
        return json.dumps([{'path': o['name'],
                            'etag': o['hash'],
                            'size_bytes': o['bytes']} for o in data])
    else:
        raise HTTPBadRequest("Invalid manifest format, accepts "
                             "query parameter format=json or format=xml")


def parse_input(raw_data, data_format):
    """
    Given a request will parse the body and return a list of dictionaries
    :raises: HTTPException on parse errors
    :returns: a list of dictionaries on success
    """
    parsed_data = []
    if data_format == 'json':
        parsed_data = json.loads(raw_data)
    elif data_format == 'xml':
        try:
            xml_tree_root = ElementTree.fromstring(raw_data)
        except ExpatError:
            raise HTTPBadRequest('Invalid XML document')
        if xml_tree_root.tag != 'static_large_object':
            raise HTTPBadRequest('Invalid XML document')
        for obj_segment in xml_tree_root:
            if obj_segment.tag != 'object_segment':
                raise HTTPBadRequest('Invalid XML document')
            seg_dict = dict(
                [(elem.tag, elem.text) for elem in obj_segment])
            parsed_data.append(seg_dict)
    else:
        raise HTTPBadRequest("Invalid manifest format, accepts "
                             "query parameter format=json or format=xml")

    req_keys = set(['path', 'etag', 'size_bytes'])
    for seg_dict in parsed_data:
        if set(seg_dict.keys()) != req_keys:
            raise HTTPBadRequest('Invalid Manifest File')

    return parsed_data


class StaticLargeObject(object):

    def __init__(self, app, conf):
        self.conf = conf
        self.app = app
        self.logger = get_logger(conf, log_route='slo')
        self.max_manifest_segments = int(self.conf.get('max_manifest_segments',
                                         1000))
        self.max_manifest_size = int(self.conf.get('max_manifest_size',
                                     1024 * 1024 * 2))
        self.bulk_deleter = Bulk(
            app, {'max_deletes_per_request': self.max_manifest_segments})

    def handle_multipart_put(self, req):
        """
        Will handle the PUT of a SLO manifest.
        Heads every object in manifest to check if is valid and if so will
        allow the request to proceed normally with some modified headers.
        :params req: a swob.Request with an obj in path
        """
        if req.content_length > self.max_manifest_size:
            raise HTTPRequestEntityTooLarge(
                "Manifest File > %d bytes" % self.max_manifest_size)
        if req.headers.get('X-Copy-From'):
            raise HTTPMethodNotAllowed(
                'Multipart Manifest PUTs cannot be Copy requests')
        raw_data = req.body_file.read(self.max_manifest_size)
        incoming_format = req.params.get('format')
        parsed_data = parse_input(raw_data, incoming_format)
        problem_segments = []

        if len(parsed_data) > self.max_manifest_segments:
            raise HTTPRequestEntityTooLarge(
                'Number segments must be <= %d' % self.max_manifest_segments)
        try:
            vrs, account, container, obj = req.split_path(1, 4, True)
        except ValueError:
            return self.app
        total_size = 0
        out_content_type = req.accept.best_match(ACCEPTABLE_FORMATS)
        if not out_content_type:
            out_content_type = 'text/plain'
        data_for_storage = []
        for seg_dict in parsed_data:
            obj_path = '/'.join(
                ['', vrs, account, seg_dict['path'].lstrip('/')])
            new_env = req.environ.copy()
            new_env['PATH_INFO'] = obj_path
            new_env['REQUEST_METHOD'] = 'HEAD'
            del(new_env['wsgi.input'])
            del(new_env['QUERY_STRING'])
            new_env['CONTENT_LENGTH'] = 0
            new_env['HTTP_USER_AGENT'] = \
                '%s MultipartPUT' % req.environ.get('HTTP_USER_AGENT')
            head_seg_resp = \
                Request.blank(obj_path, new_env).get_response(self.app)
            if head_seg_resp.status_int // 100 == 2:
                try:
                    seg_size = int(seg_dict['size_bytes'])
                except (ValueError, TypeError):
                    raise HTTPBadRequest('Invalid Manifest File')
                total_size += seg_size
                if seg_size != head_seg_resp.content_length:
                    problem_segments.append([quote(obj_path), 'Size Mismatch'])
                if seg_dict['etag'] != head_seg_resp.etag:
                    problem_segments.append([quote(obj_path), 'Etag Mismatch'])
                if head_seg_resp.last_modified:
                    last_modified = head_seg_resp.last_modified
                else:
                    # shouldn't happen
                    last_modified = datetime.now()

                last_modified_formatted = \
                    last_modified.strftime('%Y-%m-%dT%H:%M:%S.%f')
                data_for_storage.append(
                    {'name': '/' + seg_dict['path'].lstrip('/'),
                     'bytes': seg_size,
                     'hash': seg_dict['etag'],
                     'content_type': head_seg_resp.content_type,
                     'last_modified': last_modified_formatted})

            else:
                problem_segments.append([quote(obj_path),
                                         head_seg_resp.status])
        if problem_segments:
            resp_body = get_response_body(
                out_content_type, {}, problem_segments)
            raise HTTPBadRequest(resp_body, content_type=out_content_type)
        env = req.environ

        if not env.get('CONTENT_TYPE'):
            guessed_type, _junk = mimetypes.guess_type(req.path_info)
            env['CONTENT_TYPE'] = guessed_type or 'application/octet-stream'
        env['CONTENT_TYPE'] += ";swift_bytes=%d" % total_size

        # TODO: should I do this or just hard code X-Static-Large-Object ?
        env['swift.extra_allowed_headers'] = \
            env.get('swift.extra_allowed_headers',
                    []).append('X-Static-Large-Object')
        env['HTTP_X_STATIC_LARGE_OBJECT'] = 'True'
        json_data = json.dumps(data_for_storage)
        env['CONTENT_LENGTH'] = str(len(json_data))
        env['wsgi.input'] = StringIO(json_data)
        return self.app

    def handle_multipart_delete(self, req):
        """
        Will delete all the segments in the SLO manifest and then, if
        successful, will delete the manifest file.
        """
        new_env = req.environ.copy()
        new_env['REQUEST_METHOD'] = 'GET'
        del(new_env['wsgi.input'])
        new_env['QUERY_STRING'] = 'multipart-manifest=get'
        new_env['CONTENT_LENGTH'] = 0
        new_env['HTTP_USER_AGENT'] = \
            '%s MultipartDELETE' % req.environ.get('HTTP_USER_AGENT')
        get_man_resp = \
            Request.blank('', new_env).get_response(self.app)
        if get_man_resp.status_int // 100 == 2:
            manifest = json.loads(get_man_resp.body)
            delete_resp = self.bulk_deleter.handle_delete(
                req, objs_to_delete=[o['name'] for o in manifest],
                user_agent='MultipartDELETE')
            if delete_resp.status_int // 100 == 2:
                # delete the manifest file itself
                return self.app
            else:
                return delete_resp
        return get_man_resp

    def handle_multipart_get(self, req):
        """
        Will return a Response with the actual manifest itself.
        :param req: a swob.Request with query string ?multipart-manifest=get
        """
        if req.range:
            return HTTPBadRequest(
                "Range requests not allowed for retrieving manifest file")

        get_man_resp = req.get_response(self.app)
        if get_man_resp.status_int // 100 == 2:
            outgoing_format = req.params.get('format', 'json')
            raw_data = get_man_resp.body
            try:
                manifest_data = json.loads(raw_data)
            except Exception, e:
                self.logger.exception("Invalid SLO manifest file")
                raise HTTPServerError("Invalid SLO manifest file")
            try:
                get_man_resp.body = format_manifest(manifest_data,
                                                    outgoing_format)
            except (KeyError, TypeError):
                raise HTTPServerError("Invalid SLO manifest file")
        return get_man_resp

    def validate_content_type(self, req):
        """
        Because swift stores the Content-Type of each object both as metadata
        on the object and in the container listings it is a convenient place
        to store extra admin-only / user-invisible metadata.

        This metadata will take the form of an extra parameter appended to the
        end of the customer's Content Type and will identified by the format:

        swift_[key]=value

        This also means that user Content-Type parameters can not begin with
        swift_* .  This function verifies this. When more features begin to
        use this type of metadata this function should be expanded into its own
        middleware that will be towards the beginning of the proxy pipeline.
        """
        bad_req = check_metadata(req, 'object')
        if bad_req:
            raise bad_req
        content_type = req.headers.get('content-type')
        if content_type and ';' in content_type:
            for param in content_type.split(';')[1:]:
                if param.lstrip().startswith('swift_'):
                    raise HTTPBadRequest(
                        "Invalid Content-Type, "
                        "swift_* is not a valid parameter name")


    @wsgify
    def __call__(self, req):
        """
        WSGI entry point
        """
        try:
            vrs, account, container, obj = req.split_path(1, 4, True)
        except ValueError:
            return self.app
        if obj:
            if req.method == 'PUT':
                self.validate_content_type(req)
            if req.method == 'PUT' and \
                    req.params.get('multipart-manifest') == 'put':
                return self.handle_multipart_put(req)
            if req.method == 'DELETE' and \
                    req.params.get('multipart-manifest') == 'delete':
                return self.handle_multipart_delete(req)

            if req.method == 'GET' and \
                    req.params.get('multipart-manifest') == 'get':
                return self.handle_multipart_get(req)

        return self.app


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def slo_filter(app):
        return StaticLargeObject(app, conf)
    return slo_filter

    """
    Middleware that will provide Static Large Object (SLO) support.

    This feature is very similar to Dynamic Large Object (DLO) support in that
    it allows the user to upload many objects concurrently and afterwards
    download them as a single object. It is different in that is does not rely
    on eventually consistent container listings to do so. Instead, a user
    defined manifest of the object segments is used.

    After the user has uploaded the objects to be concatenated a manifest is
    uploaded. The request must be a PUT with the query parameter:

    ?multipart-manifest=put&format=(json|xml)

    The body of this request will be an ordered list of files in
    json or xml. The data to be supplied for each segment is:

    path: the path to the object (not including account) /container/object_name
    etag: the etag given back when the object segment was PUT
    size_bytes: the size of the object in bytes

    The format of the list will be:

    json:
    [{'path': '/cont/object',
      'etag': 'etagoftheobjectsegment',
      'size_bytes': 100}, ...]

    xml:
    <?xml version="1.0" encoding="UTF-8"?>
    <static_large_object>
        <object_segment>
            <path>/cont/object</path>
            <etag>etagoftheobjecitsegment</etag>
            <size_bytes>100</size_bytes>
        </object_segment>
        ...
    </static_large_object>

    The number of object segments is limited to a configurable amount, default
    1000. Each segment must be at least 1 megabyte (configurable). On upload,
    the middleware will head every object passed in and verify the size and
    etag of each object. If any of the objects do not match (not found,
    size/etag mismatch, below minimum size) then the user will receive an
    error response.

    If any of the object are below a minimum size (1 megabyte by default) If
    everything matches the manifest will be sent to object servers as is with
    an extra "X-Static-Large_object: True" header and a modified Content-Type.
    The parameter: swift_size=total_size will be appended to the Content-Type,
    where total_size is the sum of all the included object_size_bytes. This
    extra parameter will be hidden from the user.

    A GET request to the manifest object will return the concatenation of the
    objects from the manifest much like DLO except that if any of the objects
    from the manifest are not found or their Etag no longer matches the
    manifest: TODO: what happens here? I've already started to return content?

    The headers from this GET or HEAD request will return the metadata attached
    to the metadata object itself with some exceptions:

    Content-Length: the total_size from the manifest (the sum of the sizes of
                    the segments)
    Content-Type: the original Content-Type given by the user (without
                  swift_size)
    X-Static-Large-Object: True
    Etag: the etag of the manifest object (different than DLO)

    A GET request with the query parameter:

    ?multipart-manifest=get

    Will return the actual manifest file itself.

    A DELETE request will just delete the manifest file itself.

    A DELETE with a query parameter:

    ?multipart-manifest=delete

    will delete all the objects referenced in the manifest
    file. The response will be similar to the bulk delete middleware.

    PUTs / POSTs will work as expected, PUTs will overwrite the manifest object
    for example.

    When the manifest object is uploaded you are more or less guaranteed that
    every object in the manifest exists and matched the specifications.
    However, there is nothing that prevents the user from breaking the
    SLO download by deleting/replacing an object in the manifest. It is left to
    the user use caution in handling these objects.

    Manifest files can reference objects in separate containers, which
    will improve concurrent upload speed. Objects can be referenced by
    multiple manifests.

    Container Listings:

    If a GET request is made to a container that has SLO manifest files in it
    the size listed for the manifest file will be listed as the total_size
    of the concatenated objects.
    """
