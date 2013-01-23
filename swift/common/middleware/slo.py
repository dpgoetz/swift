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
from swift.common.swob import Request, HTTPBadRequest
from swift.common.wsgi import WSGIContext
from swift.common.utils import split_path


class _StaticLargeObjectContext(WSGIContent):
    """
    WSGI Context used by StaticLargeObject to wrap every GET request. If the
    object being returned is a StaticLargeObject manifest will override the
    reponse and return the concatenated segments specified in the manifest.
    """

    def __init__(self, slo):
        self.app = slo.app


class StaticLargeObject(object):
    """
    Middleware that will provide Static Large Object (SLO) support.

    This feature is very similar to Dynamic Large Object (DLO) support in that
    it allows the user to upload many objects concurrently and afterwards
    download them as a single object. It is different in that is does not rely
    on eventually consistent container listings to do so. Instead, a user
    defined manifest of the object segments is used.

    After the user has uploaded the objects to be concatenated a manifest is
    uploaded. The request must be a PUT with the query parameter:

    ?multipart-manifest=put

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
    The parameter: slo_size=total_size will be appended to the Content-Type,
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
                  slo_size)
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

    def __init__(self, app, conf):
        self.conf = conf
        self.app = app
        self.max_segments = int(self.conf.get('max_manifest_segments', 1000))
        self.max_manifest_size = int(self.conf.get('max_manifest_size',
                                     1024*1024*2))

    def parse_input(req):
        """
        Given a request will parse the body and return a list of dictionaries
        :raises: HTTPException on parse errors
        :returns: a list of dictionaries on success
        """

        if req.content_length > self.max_manifest_size:
            raise HTTPBadRequest(
                "Manifest File > %d bytes" % self.max_manifest_size)
        raw_data = req.body.read(self.max_manifest_size)
        parsed_data = []
        if req.content_type == 'application/json':
            parsed_data = json.loads(raw_data)
        elif req.content_type in ['application/xml', 'text/xml']:

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
            raise HTTPBadRequest("Invalid Content-Type, accepts json and xml")
        if len(parsed_data) > self.max_manifest_segments:
            raise HTTPBadRequest(
                'Number segments must be <= %d' % self.max_manifest_segments)

        return parsed_data


    def __call__(self, env, start_response):
        """
        WSGI entry point
        """
        req = Request(env)
        try:
            vrs, account, container, obj = split_path(req.path, 1, 4, True)
        except ValueError:
            return self.app(env, start_response)
        if obj:
            if req.method == 'PUT' and \
                    req.params.get('multipart-manifest') == 'put':
                return self.handle_multipart_put(req, vrs, account)
            if req.method == 'DELETE' and \
                    req.params.get('multipart-manifest') == 'delete':
                return self.handle_multipart_delete(req, vrs, account)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def slo_filter(app):
        return StaticLargeObject(app, conf)
    return slo_filter
