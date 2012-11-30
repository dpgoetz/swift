import tarfile
from urllib import quote, unquote
import simplejson
from swift.common.swob import Request, HTTPBadGateway, HTTPServerError, \
    HTTPCreated, HTTPBadRequest, HTTPNotFound, HTTPUnauthorized
from swift.common.utils import TRUE_VALUES, split_path
from swift.common.http import HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED
from swift.common.constraints import MAX_OBJECT_NAME_LENGTH, \
    MAX_CONTAINER_NAME_LENGTH


MAX_PATH_LENGTH = MAX_OBJECT_NAME_LENGTH + MAX_CONTAINER_NAME_LENGTH + 1


class CreateContainerError(Exception):
    def __init__(self, msg, status_int, status):
        self.status_int = status_int
        self.status = status
        Exception.__init__(self, msg)


class Untar(object):
    """
    Middleware that will expand tar files into a swift account.
    Request must be a PUT with the header X-Extract-Archive specifying the
    format of archive file. Accepted formats are tar, tar.gz, and tar.bz2.

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
    """

    def __init__(self, app, conf):
        self.app = app
        self.max_containers = int(
            conf.get('max_containers_per_extraction', 10000))
        self.max_failed_files = int(
            conf.get('max_failed_files', 1000))

    def create_container_for_path(self, req, file_path):
        """
        Given a path for a file will make the container for the file
        :params file_path: an unquoted path to a object to be extracted
        :returns: container_name created
        :raises: CreateContainerError on creation error
        :raises: ValueError on invalid path
        """
        vrs, account, container, obj = split_path(file_path, 3, 4, True)

        container_path = quote('/%s/%s/%s' % (vrs, account, container))
        new_env = req.environ.copy()
        new_env['PATH_INFO'] = container_path
        create_cont_req = Request.blank(container_path, environ=new_env)
        resp = create_cont_req.get_response(self.app)
        if resp.status_int // 100 != 2:
            raise CreateContainerError(
                "Create Container Failed: " + container_path,
                resp.status_int, resp.status)
        return container

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
                        len(failed_files) >= self.max_failed_files:
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
                    if container not in existing_containers:
                        try:
                            existing_containers.add(
                                self.create_container_for_path(req,
                                                               destination))
                        except CreateContainerError, err:
                            if err.status_int == HTTP_UNAUTHORIZED:
                                return HTTPUnauthorized(request=req)
                            failed_files.append(
                                (destination[:MAX_PATH_LENGTH], err.status))
                            continue
                        except ValueError:
                            failed_files.append(
                                (destination[:MAX_PATH_LENGTH],
                                 HTTP_BAD_REQUEST))
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
                        failed_files.append(
                            (destination[:MAX_PATH_LENGTH], resp.status))

            resp_body = simplejson.dumps(
                {'Number Created Files': success_count,
                 'Failures': failed_files})
            if success_count and not failed_files:
                return HTTPCreated(resp_body)
            if failed_files:
                return HTTPBadGateway(resp_body)

            return HTTPBadRequest('Invalid Tar File: No Valid Files')

        except tarfile.TarError, tar_error:
            return HTTPBadRequest('Invalid Tar File: %s' % tar_error)

    def __call__(self, env, start_response):
        req = Request(env)
        extract_type = \
            req.headers.get('X-Extract-Archive', '').lower().strip('.')
        archive_type = None
        for ext, typ in [('tar', ''), ('tar.gz', 'gz'), ('tar.bz2', 'bz2')]:
            if extract_type == ext:
                archive_type = typ
                break
        if req.method == 'PUT' and archive_type is not None:
            resp = self.handle_extract(req, archive_type)
            return resp(env, start_response)
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def bulk_filter(app):
        return Untar(app, conf)
    return bulk_filter
