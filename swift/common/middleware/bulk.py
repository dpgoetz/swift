# Copyright (c) 2012 OpenStack, LLC.
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

import tarfile
from urllib import quote, unquote
from swift.common.swob import Request, HTTPBadGateway, HTTPCreated, \
    HTTPBadRequest, HTTPNotFound, HTTPUnauthorized, HTTPOk, \
    HTTPPreconditionFailed, HTTPRequestEntityTooLarge
from swift.common.utils import split_path, json, TRUE_VALUES
from swift.common.constraints import check_utf8
from swift.common.http import HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, \
    HTTP_NOT_FOUND
from swift.common.constraints import MAX_OBJECT_NAME_LENGTH, \
    MAX_CONTAINER_NAME_LENGTH


MAX_PATH_LENGTH = MAX_OBJECT_NAME_LENGTH + MAX_CONTAINER_NAME_LENGTH + 2


class CreateContainerError(Exception):
    def __init__(self, msg, status_int, status):
        self.status_int = status_int
        self.status = status
        Exception.__init__(self, msg)


class Bulk(object):
    """
    Middleware that will do many operations on a single request.

    Extract Archive:

    Expand tar files into a swift account. Request must be a PUT with the
    header X-Extract-Archive specifying the format of archive file. Accepted
    formats are tar, tar.gz, and tar.bz2.

    For a PUT to the following url:

    /v1/AUTH_Account/$UPLOAD_PATH

    UPLOAD_PATH is where the files will be expanded to. UPLOAD_PATH can be a
    container, a pseudo-directory within a container, or an empty string. The
    destination of a file in the archive will be built as follows:

    /v1/AUTH_Account/$UPLOAD_PATH/$FILE_PATH

    Where FILE_PATH is the file name from the listing in the tar file.

    If the UPLOAD_PATH is empty string, containers will be auto created
    accordingly and files in the tar that would not map to any container (files
    in the base directory) will be ignored.

    Only regular files will be uploaded. Empty directories, symlinks, etc will
    not be uploaded.

    If all valid files were uploaded successfully will return an HTTPCreated
    response. If any files failed to be created will return an HTTPBadGateway
    response. In both cases the response body is a json dictionary specifying
    in the number of files successfully uploaded and a list of the files that
    failed.

    Bulk Delete:

    Will delete multiple files from their account with a single request.
    Responds to DELETE requests with a header 'X-Bulk-Delete: true'.
    The body of the DELETE request will be a newline separated list of files
    to delete. The files listed must be URL encoded and in the form:

    /container_name/obj_name

    If all files were successfully deleted (or did not exist) will return an
    HTTPOk.  If any files failed to delete will return an HTTPBadGateway. In
    both cases the response body is a json dictionary specifying in the number
    of files successfully deleted, not found, and a list of the files that
    failed.
    """

    def __init__(self, app, conf):
        self.app = app
        self.max_containers = int(
            conf.get('max_containers_per_extraction', 10000))
        self.max_failed_extractions = int(
            conf.get('max_failed_extractions', 1000))
        self.max_deletes_per_request = int(
            conf.get('max_deletes_per_request', 1000))

    def create_container(self, req, container_path):
        """
        Makes a subrequest to create a new container.
        :params container_path: an unquoted path to a container to be created
        :returns: None on success
        :raises: CreateContainerError on creation error
        """
        new_env = req.environ.copy()
        new_env['PATH_INFO'] = container_path
        create_cont_req = Request.blank(container_path, environ=new_env)
        resp = create_cont_req.get_response(self.app)
        if resp.status_int // 100 != 2:
            raise CreateContainerError(
                "Create Container Failed: " + container_path,
                resp.status_int, resp.status)

    def get_objs(self, req, objs_to_delete):
        """
        Will populate objs_to_delete with data from request input.  Returns
        None on success. If an error happened a Swob response is returned.
        """
        line = ''
        data_remaining = True
        while data_remaining:
            if len(objs_to_delete) > self.max_deletes_per_request:
                return HTTPRequestEntityTooLarge(
                    'Maximum Bulk Deletes: %d per request' %
                    self.max_deletes_per_request)
            if '\n' in line:
                obj_to_delete, line = line.split('\n', 1)
                objs_to_delete.append(obj_to_delete)
            else:
                data = req.body_file.read(MAX_PATH_LENGTH)
                if data:
                    line += data
                else:
                    data_remaining = False
                    if line.strip():
                        objs_to_delete.append(line)
            if len(line) > MAX_PATH_LENGTH * 2:
                return HTTPBadRequest('Invalid File Name')
        return None

    def handle_delete(self, req):
        """
        :params req: a swob Request
        """
        try:
            vrs, account, _junk = split_path(unquote(req.path), 2, 3, True)
        except ValueError:
            return HTTPNotFound(request=req)

        objs_to_delete = []
        error_resp = self.get_objs(req, objs_to_delete)
        if error_resp:
            return error_resp

        failed_files = []
        success_count = not_found_count = 0
        failed_file_response_type = HTTPBadRequest
        for obj_to_delete in objs_to_delete:
            obj_to_delete = obj_to_delete.strip().lstrip('/')
            if not obj_to_delete:
                continue
            obj_to_delete = unquote(obj_to_delete)
            delete_path = '/'.join(['', vrs, account, obj_to_delete])
            if not check_utf8(delete_path):
                failed_files.append([quote(delete_path),
                                     HTTPPreconditionFailed().status])
                continue
            new_env = req.environ.copy()
            new_env['PATH_INFO'] = delete_path
            del(new_env['wsgi.input'])
            new_env['CONTENT_LENGTH'] = 0
            delete_obj_req = Request.blank(delete_path, new_env)
            resp = delete_obj_req.get_response(self.app)
            if resp.status_int // 100 == 2:
                success_count += 1
            elif resp.status_int == HTTP_NOT_FOUND:
                not_found_count += 1
            elif resp.status_int == HTTP_UNAUTHORIZED:
                return HTTPUnauthorized(request=req)
            else:
                if resp.status_int // 100 == 5:
                    failed_file_response_type = HTTPBadGateway
                failed_files.append([delete_path, resp.status])

        resp_body = json.dumps(
            {'Number Deleted': success_count,
             'Number Not Found': not_found_count,
             'Errors': failed_files})
        if (success_count or not_found_count) and not failed_files:
            return HTTPOk(resp_body, content_type='application/json')
        if failed_files:
            return failed_file_response_type(
                resp_body, content_type='application/json')
        return HTTPBadRequest('Invalid bulk delete.')

    def handle_extract(self, req, compress_type):
        """
        :params req: a swob Request
        :params compress_type: specifying the compression type of the tar.
                               Accepts '', 'gz, or 'bz2'
        """
        success_count = 0
        failed_files = []
        existing_containers = set()
        try:
            vrs, account, extract_base = split_path(
                unquote(req.path), 2, 3, True)
        except ValueError:
            return HTTPNotFound(request=req)
        extract_base = extract_base or ''
        extract_base = extract_base.rstrip('/')
        try:
            tar = tarfile.open(mode='r|' + compress_type,
                               fileobj=req.body_file)
            while True:
                tar_info = tar.next()
                if tar_info is None or \
                        len(failed_files) >= self.max_failed_extractions:
                    break
                if tar_info.isfile():
                    obj_path = tar_info.name
                    if obj_path.startswith('./'):
                        obj_path = obj_path[2:]
                    obj_path = obj_path.lstrip('/')
                    if extract_base:
                        obj_path = extract_base + '/' + obj_path
                    if '/' not in obj_path:
                        continue  # ignore base level file

                    destination = '/'.join(
                        ['', vrs, account, obj_path])
                    container = obj_path.split('/', 1)[0]
                    if not check_utf8(destination):
                        failed_files.append(
                            [quote(destination[:MAX_PATH_LENGTH]),
                             HTTPPreconditionFailed().status])
                        continue
                    if container not in existing_containers:
                        try:
                            self.create_container(
                                req, '/'.join(['', vrs, account, container]))
                            existing_containers.add(container)
                        except CreateContainerError, err:
                            if err.status_int == HTTP_UNAUTHORIZED:
                                return HTTPUnauthorized(request=req)
                            failed_files.append([destination[:MAX_PATH_LENGTH],
                                                 err.status])
                            continue
                        except ValueError:
                            failed_files.append([destination[:MAX_PATH_LENGTH],
                                                 HTTP_BAD_REQUEST])
                            continue
                        if len(existing_containers) > self.max_containers:
                            return HTTPBadRequest(
                                'More than %d base level containers in tar.' %
                                self.max_containers)

                    tar_file = tar.extractfile(tar_info)
                    new_env = req.environ.copy()
                    new_env['wsgi.input'] = tar_file
                    new_env['PATH_INFO'] = destination
                    new_env['CONTENT_LENGTH'] = tar_info.size
                    create_obj_req = Request.blank(destination, new_env)
                    resp = create_obj_req.get_response(self.app)
                    if resp.status_int // 100 == 2:
                        success_count += 1
                    else:
                        if resp.status_int == HTTP_UNAUTHORIZED:
                            return HTTPUnauthorized(request=req)
                        failed_files.append([destination[:MAX_PATH_LENGTH],
                                             resp.status])

            resp_body = json.dumps(
                {'Number Files Created': success_count,
                 'Errors': failed_files})
            if success_count and not failed_files:
                return HTTPCreated(resp_body, content_type='application/json')
            if failed_files:
                return HTTPBadGateway(
                    resp_body, content_type='application/json')
            return HTTPBadRequest('Invalid Tar File: No Valid Files')

        except tarfile.TarError, tar_error:
            return HTTPBadRequest('Invalid Tar File: %s' % tar_error)

    def __call__(self, env, start_response):
        req = Request(env)
        extract_type = \
            req.headers.get('X-Extract-Archive', '').lower().strip('.')
        if extract_type and req.method == 'PUT':
            archive_type = \
                {'tar': '', 'tar.gz': 'gz', 'tar.bz2': 'bz2'}.get(extract_type)
            if archive_type is not None:
                resp = self.handle_extract(req, archive_type)
            else:
                resp = HTTPBadRequest("Unsupported archive format")
            return resp(env, start_response)
        if req.headers.get('X-Bulk-Delete', '').lower() in TRUE_VALUES and \
                req.method == 'DELETE':
            return self.handle_delete(req)(env, start_response)

        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def bulk_filter(app):
        return Bulk(app, conf)
    return bulk_filter
