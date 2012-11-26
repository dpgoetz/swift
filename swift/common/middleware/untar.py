import tarfile
from urllib import quote, unquote
import simplejson
from swift.common.swob import Request, HTTPBadGateway, HTTPServerError, \
    HTTPCreated, HTTPBadRequest, HTTPNotFound
from swift.common.utils import TRUE_VALUES, split_path, cache_from_env
from swift.common.http import HTTP_BAD_REQUEST
from swift.common.constraints import MAX_OBJECT_NAME_LENGTH, \
    MAX_CONTAINER_NAME_LENGTH
from swift.common.middleware.ratelimit import RateLimitMiddleware


MAX_PATH_LENGTH = MAX_OBJECT_NAME_LENGTH + MAX_CONTAINER_NAME_LENGTH + 1


class CreateContainerError(Exception):
    def __init__(self, msg, status):
        self.status = status
        Exception.__init__(self, msg)


class Untar(object):
    """
    Middleware that will expand tar files into a swift account.
    Request must be a PUT with the header X-Extract-Archive specifying the
    format of archive file. Accepted formats are .tar, .tar.gz, and .tar.bz2.

    For a PUT to the following url:
    /v1/AUTH_Account/$UPLOAD_PATH
    UPLOAD_PATH is where the files will be expanded to. UPLOAD_PATH can be an
    existing container, a pseudo-directory within a container, or an empty
    string. The destination of a file in the archive will be built as follows:
    /v1/AUTH_Account/$UPLOAD_PATH/$FILE_PATH
    Where FILE_PATH is the file name from the listing in the tar file.
    If the UPLOAD_PATH is empty string, containers will be auto created
    accordingly and files in the tar that would not map to any container (files
    in the base directory) will be ignored.

    Only regular files will be uploaded. Empty directories, symlinks, etc will
    not be uploaded.

    If all valid files were uploaded successfully will return an HTTPCreated
    response with the # files created in the response message.
    If any files failed to be created will return an HTTPBadGateway response
    with a list of the files (in json) that failed.
    """

    def __init__(self, app, conf):
        self.app = app
        self.ratelimit = RateLimitMiddleware(app, conf)
        self.max_containers = int(
            conf.get('max_containers_per_extraction', 100000))
        self.max_failed_files = int(
            conf.get('max_failed_files', 10000))

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
            err = CreateContainerError(
                "Create Container Failed: " + container_path, resp.status)
        return container

    def handle_extract(self, req, start_response, compress_type):
        #TODO test explode_to with unicode, spaces, etc
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
            tar_info = tar.next()
            while tar_info:
                if len(failed_files) >= self.max_failed_files:
                    break
                if tar_info.isfile():
                    obj_path = tar_info.name
                    if obj_path.startswith('./'):
                        obj_path = obj_path[2:]
                    obj_path = obj_path.lstrip('/')
                    if extract_base:
                        obj_path = extract_base + '/' + obj_path

                    destination = '/'.join(
                        ['', vrs, account, obj_path])
                    container = obj_path.split('/', 1)[0]

                    if container not in existing_containers:
                        try:
                            existing_containers.add(
                                self.create_container_for_path(req,
                                                               destination))
                        except CreateContainerError, err:
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
                    ratelimit_resp = self.ratelimit.handle_ratelimit(
                        create_obj_req, account, container, obj_path)
                    if ratelimit_resp:
                        return ratelimit_resp
                    resp = create_obj_req.get_response(self.app)
                    if resp.status_int // 100 == 2:
                        success_count += 1
                    else:
                        failed_files.append(
                            (destination[:MAX_PATH_LENGTH], resp.status))

                tar_info = tar.next()

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
        if self.ratelimit.memcache_client is None:
            self.ratelimit.memcache_client = cache_from_env(env)
        req = Request(env)
        extract_type = \
            req.headers.get('X-Extract-Archive', '').lower().strip('.')
        archive_type = None
        for ext, typ in [('tar', ''), ('tar.gz', 'gz'), ('tar.bz2', 'bz2')]:
            if extract_type == ext:
                archive_type = typ
                break
        if req.method == 'PUT' and archive_type is not None:
            resp = self.handle_extract(req, start_response, archive_type)
            return resp(env, start_response)
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def bulk_filter(app):
        return Untar(app, conf)
    return bulk_filter
