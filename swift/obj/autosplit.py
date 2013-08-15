from random import random
from time import time
from hashlib import md5

from eventlet import sleep, Timeout

from swift.common.daemon import Daemon
from swift.common.utils import get_logger, FileLikeIter
from swift.common.internal_client import InternalClient, UnexpectedResponse
from swift.common.http import HTTP_NOT_FOUND
from swift.proxy.controllers.base import get_container_info
from swift.common.exceptions import ChunkReadTimeout


class ObjectReader(object):

    def __init__(self, conf, obj_iter, obj_total_length, segment_length):
        """
        Takes an obj iterable from a resp that was made to a customer
        object to be split.  has a func that will yield up segments that it
        reads from the obj_iter.  when it hits the split_segment length, it
        will raise a StopIteration. The client's PUT request will be over,
        there will be a verify_last_etag that you'll be able to verify the etag
        that the PUT resp gave you with the last segment uploaded. At this
        point you can just create a new PUT and hand it another reference to
        this function.
        """
        # list of tuples in form
        # [{"path": cont/seg, "etag": abcd, "size_bytes": seg_len},]
        # of uploaded segments in order
        self.conf = conf
        self.segment_info = []
        self.obj_file = FileLikeIter(obj_iter)
        self.obj_total_length = obj_total_length
        self.segment_length = segment_length
        self.last_chunk = ''
        self.node_timeout = int(self.conf.get('node_timeout', 10))
        self.chunk_size = int(self.conf.get('chunk_size', 1024**1024))
        self.bytes_yielded = 0
        self.read_stopped = False

    def yielded_whole_obj(self):
        return self.bytes_yielded >= self.obj_total_length

    def segment_make_iter(self):
        """
        A generator function that will iterate over self.obj_iter to be
        used to PUT the object segments.
        """
        chunk = ''
        bytes_yielded_cur = 0
        if self.last_chunk:
            bytes_yielded_cur = len(self.last_chunk)
            yield '%x\r\n%s\r\n' % (len(self.last_chunk), self.last_chunk)
            self.last_chunk = ''
        while not self.read_stopped:
            with ChunkReadTimeout(self.node_timeout):
                try:
                    chunk = self.obj_iter.next()
                    if not chunk:
                        continue
                    if len(chunk) + bytes_yielded_cur < self.segment_length):
                        bytes_yielded_cur += len(chunk)
                        yield '%x\r\n%s\r\n' % (len(chunk), chunk)
                    else:
                        marker = self.segment_length - bytes_yielded_cur
                        self.last_chunk = chunk[marker:]
                        bytes_yielded_cur += marker
                        yield '%x\r\n%s\r\n' % (marker, chunk[:marker])
                        yield '0\r\n\r\n'
                        break
                except StopIteration:
                    self.read_stopped = True
                    print 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    break
        if self.read_stopped and self.last_chunk:
            bytes_yielded_cur += len(self.last_chunk)
            yield '%x\r\n%s\r\n' % (len(self.last_chunk), self.last_chunk)
            yield '0\r\n\r\n'
            self.last_chunk = ''
        self.bytes_yielded += bytes_yielded_cur


class ObjectAutoSplit(Daemon):
    """
    Daemon that queries the internal hidden autosplit_account to
    discover objects that need to be split and then split them.

    :param conf: The daemon configuration.
    """

    def __init__(self, conf):
        self.conf = conf
        self.logger = get_logger(conf, log_route='object-auto-split')
        self.interval = int(conf.get('interval') or 300)

        conf_path = conf.get('__file__') or '/etc/swift/object-autosplit.conf'
        request_tries = int(conf.get('request_tries') or 3)
        self.swift = InternalClient(conf_path, 'Swift Object AutoSplit',
                                    request_tries)

        self.autosplit_account = \
            (conf.get('auto_create_account_prefix') or '.') + 'autosplit'
        self.notify_autosplit_object_size = int(
            conf.get('notify_autosplit_object_size'), 0)
        self.autosplit_segment_size = int(
            conf.get('autosplit_segment_size', 100*1024*1024))
        self.number_autosplit_containers = \
            int(conf.get('number_autosplit_containers', 100000))
        self.min_age_before_split = \
            int(conf.get('min_age_before_split', 2 * 86400))

    def get_segment_info(self, obj_path, obj_last_modified):
       """
       :returns: a tuple segment_container_name, segment_base. The actual
                 segment names can be found by appending _0, _1, .. to the
                 segment_base
       """
       obj_hash = md5(obj_path).hexdigest()
       obj_segment_name = '%s/%s' % (obj_hash, obj_last_modified)
       container_id = int(obj_hash, 16) % self.number_autosplit_containers
       return '.segments_%d' % container_id, obj_segment_name

    def create_container_if_needed(self, container_name):
        if not self.swift.container_exists(self.autosplit_account,
                                           container_name):
            self.swift.create_container(self.autosplit_account, container_name)

    def split_object(self, obj_path):
        """
        1. GET the object and make sure it is still above max size
        2. figure out container- create it in needed
        3. start uploading segments
        4. do other stuff...
        :param obj_path: utf-8 encoded path to the customer object to be split
                         acc_hash/cont/obj . will be used to generate hash
                         for segment names.
        :returns: bool as whether to_be_split/obj_path can be deleted
        """
        full_obj_path = '/v1/' + obj_path
        try:
            resp = self.swift.make_request(
                'GET', full_obj_path, {}, (2,404,))
        except UnexpectedResponse, e:
            if e.resp.status_int == HTTP_NOT_FOUND:
                return True
            self.logger.error('Split %s failed on cust_obj GET: %s (%s)' % (
                full_obj_path, e.resp.status_int,
                e.resp.headers.get('X-Trans-Id')))
            return False

        obj_md5 = resp.headers['Etag']
        obj_len = int(resp.headers['Content-Length'])
        obj_last_modified = float(resp.headers['x-timestamp'])

        if obj_len < self.notify_autosplit_object_size:
            return True
        if time() - self.min_age_before_split < obj_last_modified:
            return False
        seg_container, obj_seg_name = self.get_segment_info(
            obj_path, obj_last_modified)
        self.create_container_if_needed(seg_container)

        obj_reader = ObjectReader(
            self.conf, resp.app_iter, obj_len, self.autosplit_segment_size)

        seg_info = []
        bytes_put = 0
        while not obj_reader.yielded_whole_obj():
            # make a new PUT request, give it obj_reader's iter and continue,

            seg_name = '%s_%d' % (obj_seg_name, len(seg_info))
            seg_path =  '/'.join(
                ['', 'v1', self.autosplit_account, seg_container, seg_name])
            seg_headers = {'x-object-meta-parent-object': obj_path,
                           'Transfer-Encoding': 'chunked'}
            try:
                seg_resp = self.swift.make_request(
                    'PUT', seg_path, seg_headers, (2,),
                    body_file=FileLikeIter(obj_reader.segment_make_iter()))
                
                seg_info.append(
                    {"path": seg_path, "etag": seg_resp.headers['Etag'],
                     "size_bytes": obj_reader.bytes_yielded - bytes_put})
                bytes_put = obj_reader.bytes_yielded
            except UnexpectedResponse, err:
                self.logger.error('Split %s failed on segment PUT: %s (%s)' % (
                    seg_path, err.resp.status_int,
                    err.resp.headers.get('X-Trans-Id')))
                return False

            except (Exception, Timeout), err:
                self.logger.exception(
                    'Split failed on segment PUT: %s' % seg_path)
                return False

        return True

    def run_once(self, *args, **kwargs):
        """
        Executes a single pass, looking for objects to split.

        :param args: Extra args to fulfill the Daemon interface; this daemon
                     has no additional args.
        :param kwargs: Extra keyword args to fulfill the Daemon interface; this
                       daemon has no additional keyword args.
        :raises UnexpectedResponse- remember to catch this***
        """
        self.logger.info('in run once...')
        for obj_dict in self.swift.iter_objects(self.autosplit_account,
                                                '.to_be_split'):
            obj = obj_dict['name'].encode('utf8')
            self.logger.info('found object: %s' % obj)
            if self.split_object(obj):
                self.swift.delete_object(self.autosplit_account,
                                         '.to_be_split', obj)
            else:
                pass
                # try again later


    def run_forever(self, *args, **kwargs):
        """
        Executes passes forever, looking for objects to split.

        :param args: Extra args to fulfill the Daemon interface; this daemon
                     has no additional args.
        :param kwargs: Extra keyword args to fulfill the Daemon interface; this
                       daemon has no additional keyword args.
        """
        sleep(random() * self.interval)
        while True:
            begin = time()
            try:
                self.run_once(*args, **kwargs)
            except (Exception, Timeout):
                self.logger.exception(_('Unhandled exception'))
            elapsed = time() - begin
            if elapsed < self.interval:
                sleep(random() * (self.interval - elapsed))
