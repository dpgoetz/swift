#!/usr/bin/python

import cPickle
import httplib
import time
import os
import random
import shutil
import unittest
import ConfigParser
import uuid
from hashlib import md5

from swift.common.utils import hash_path
from test.direct import OBJ_CONF_FILES


class TestReplicationSwift(unittest.TestCase):

    def setUp(self):
        config_file = OBJ_CONF_FILES[0]
        config = ConfigParser.ConfigParser()
        config.read(config_file)
        self.config = dict(config.items('DEFAULT'))

        self.drive_root = self.config.get('devices', '/srv/node')
        self.device = [
            path for path in os.listdir(self.drive_root)
            if os.path.isdir(os.path.join(self.drive_root, path))][0]
        self.part = 12345
        self.part_path = '%s/%s/objects/%s' % (
            self.drive_root, self.device, self.part)

        ip = self.config.get('bind_ip', '127.0.0.1')
        port = self.config.get('bind_port', '6010')
        self.conn = httplib.HTTPConnection('%s:%s' % (ip, port))

    def tearDown(self):
        try:
            shutil.rmtree(self.part_path)
        except OSError:
            pass

    def test_replication_single_file_and_dir_totally_clean(self):
        """
        This can be run against a go object node or a python object node
        """

        obj_hash = hash_path('a', 'c', 'o')
        obj_data = '/a/c/o'
        x_timestamp = round(time.time()-5, 2)
        ondisk_filename = '%.5f.data' % x_timestamp

        self.conn.request('PUT',
                     '/'.join(['', self.device,
                               str(self.part), 'a', 'c', 'o']),
                     body=obj_data,
                     headers={'X-Timestamp': x_timestamp,
                              'Content-Type': 'text/html'})

        resp = self.conn.getresponse()
        self.assertEqual(201, resp.status)
        resp.read()

        self.conn.request('REPLICATE',
                     '/'.join(['', self.device,
                               str(self.part), obj_hash[-3:]]),
                     body='',)

        resp = self.conn.getresponse()
        body = resp.read()
        repl_data = cPickle.loads(body)
        self.assertEqual(
            repl_data, {obj_hash[-3:]: md5(ondisk_filename).hexdigest()})

        x_timestamp += 1
        self.conn.request('DELETE',
                     '/'.join(['', self.device,
                               str(self.part), 'a', 'c', 'o']),
                     body=obj_data,
                     headers={'X-Timestamp': x_timestamp})

        resp = self.conn.getresponse()
        resp.read()
        self.conn.request('REPLICATE',
                     '/'.join(['', self.device,
                               str(self.part), obj_hash[-3:]]),
                     body='',)

        resp = self.conn.getresponse()
        body = resp.read()
        repl_data = cPickle.loads(body)
        ondisk_filename = '%.5f.ts' % x_timestamp
        self.assertEqual(
            repl_data, {obj_hash[-3:]: md5(ondisk_filename).hexdigest()})

    def test_replication_single_file_and_invalidate_hash(self):
        """
        This can be run against a go object node or a python object node
        """

        obj_hash = hash_path('a', 'c', 'o')
        obj_data = '/a/c/o'
        x_timestamp = round(time.time()-5, 2)
        ondisk_filename = '%.5f.data' % x_timestamp

        self.conn.request('PUT',
                     '/'.join(['', self.device,
                               str(self.part), 'a', 'c', 'o']),
                     body=obj_data,
                     headers={'X-Timestamp': x_timestamp,
                              'Content-Type': 'text/html'})

        resp = self.conn.getresponse()
        self.assertEqual(201, resp.status)
        resp.read()

        self.conn.request('REPLICATE',
                     '/'.join(['', self.device,
                               str(self.part), obj_hash[-3:]]),
                     body='',)

        resp = self.conn.getresponse()
        body = resp.read()
        repl_data = cPickle.loads(body)
        self.assertEqual(
            repl_data, {obj_hash[-3:]: md5(ondisk_filename).hexdigest()})

        self.conn.request('PUT',
                     '/'.join(['', self.device,
                               str(self.part), 'a', 'c', 'o']),
                     body=obj_data,
                     headers={'X-Timestamp': x_timestamp + 1,
                              'Content-Type': 'text/html'})

        resp = self.conn.getresponse()
        self.assertEqual(201, resp.status)
        resp.read()

        print 'part_path listdir: %s' % os.listdir(self.part_path)
        hashes_pkl = cPickle.load(open(os.path.join(self.part_path, 'hashes.pkl')))
        print "hashespkl: %s" % hashes_pkl

if __name__ == '__main__':
        unittest.main()
