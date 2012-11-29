# Copyright (c) 2010-2012 OpenStack, LLC.
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

import unittest
import os
import tarfile
import simplejson
from mock import patch
from shutil import rmtree
from tempfile import mkdtemp
from swift.common.middleware import untar
from swift.common.swob import Request, Response


class FakeApp(object):
#    def __init__(self):
    calls = 0
    def __call__(self, env, start_response):
        self.calls += 1
        print 'xxx: %s' % env['PATH_INFO']
        if env['PATH_INFO'].startswith('/create_cont/'):
            return Response(status='201 Created')(env, start_response)
        if env['PATH_INFO'].startswith('/create_cont_fail/'):
            return Response(status='404 Not Found')(env, start_response)
        if env['PATH_INFO'].startswith('/tar_works/'):
            if len(env['PATH_INFO']) > 100:
                return Response(status='400 Bad Request')(env, start_response)
            return Response(status='201 Created')(env, start_response)


class FakeTar(object):

    @classmethod
    def open(cls, mode, fileobj):
        return cls(mode, fileobj)

    def __init__(self, mode, fileobj):
        self.mode = mode
        self.fileobj = fileobj

    def next(self):
        return StringIO('lalala')


def build_dir_tree(start_path, tree_obj):
    if isinstance(tree_obj, list):
        for obj in tree_obj:
            build_dir_tree(start_path, obj)
    if isinstance(tree_obj, dict):
        for dir_name, obj in tree_obj.iteritems():
            dir_path = os.path.join(start_path, dir_name)
            os.mkdir(dir_path)
            build_dir_tree(dir_path, obj)
    if isinstance(tree_obj, str):
        obj_path = os.path.join(start_path, tree_obj)
        with open(obj_path, 'w+') as tree_file:
            tree_file.write('testing')

def build_tar_tree(tar, start_path, tree_obj, base_path=''):
    if isinstance(tree_obj, list):
        for obj in tree_obj:
            build_tar_tree(tar, start_path, obj, base_path=base_path)
    if isinstance(tree_obj, dict):
        for dir_name, obj in tree_obj.iteritems():
            dir_path = os.path.join(start_path, dir_name)
            tar_info = tarfile.TarInfo(dir_path[len(base_path):])
            tar_info.type = tarfile.DIRTYPE
            tar.addfile(tar_info)
            build_tar_tree(tar, dir_path, obj, base_path=base_path)
    if isinstance(tree_obj, str):
        obj_path = os.path.join(start_path, tree_obj)
        tar_info = tarfile.TarInfo('./' + obj_path[len(base_path):])
        tar.addfile(tar_info)


class TestUntar(unittest.TestCase):

    def setUp(self):
        self.app = FakeApp()
        self.untar = untar.filter_factory({})(self.app)
        self.testdir = os.path.join(mkdtemp(), 'tmp_test_untar')
        os.mkdir(self.testdir)

    def tearDown(self):
        self.app.calls = 0
        rmtree(self.testdir)

    def test_create_container_for_path(self):
        req = Request.blank('/')
        self.assertEquals(
            self.untar.create_container_for_path(req, '/create_cont/acc/cont'),
            'cont')
        self.assertRaises(ValueError,
            self.untar.create_container_for_path, req, '/create_cont/acc/')
        self.assertRaises(untar.CreateContainerError,
            self.untar.create_container_for_path,
            req, '/create_cont_fail/acc/cont')

    def test_extract_tar_works(self):
        for compress_format in ['', 'gz', 'bz2']:
            base_name = 'base_works_%s' % compress_format
            dir_tree = [
                {base_name: [{'sub_dir1': ['sub1_file1', 'sub1_file2']},
                             {'sub_dir2': ['sub2_file1', 'sub2_file2']},
                             'sub_file1',
                             {'sub_dir3': [{'sub4_dir1': 'sub4_file1'}]}]}]
            build_dir_tree(self.testdir, dir_tree)
            mode = 'w'
            extension = ''
            if compress_format:
                mode += ':' + compress_format
                extension += '.' + compress_format
#            print "aaa: %s" % os.path.join(self.testdir,
#                                           'tar_works.tar' + extension)
            tar = tarfile.open(name=os.path.join(self.testdir,
                                                 'tar_works.tar' + extension),
                               mode=mode)
            tar.add(os.path.join(self.testdir, base_name))
            tar.close()
            req = Request.blank('/tar_works/acc/cont/')
            req.environ['wsgi.input'] = open(
                os.path.join(self.testdir, 'tar_works.tar' + extension))
            resp = self.untar.handle_extract(req, compress_format)
            resp_data = simplejson.loads(resp.body)
            self.assertEquals(resp_data['Number Created Files'], 6)

    def test_bad_container(self):
        req = Request.blank('/invalid/')
        resp = self.untar.handle_extract(req, '')
        self.assertEquals(resp.status_int, 404)

        req = Request.blank('/create_cont_fail/acc/cont')
        resp = self.untar.handle_extract(req, '')
        self.assertEquals(resp.status_int, 400)

    def build_bad_tar(self, dir_tree=None):
        if not dir_tree:
            dir_tree = [
                {'base_fails1': [{'sub_dir1': ['sub1_file1']},
                                 {'sub_dir2': ['sub2_file1', 'sub2_file2']},
                                 'f' * 101,
                                 {'sub_dir3': [{'sub4_dir1': 'sub4_file1'}]}]}]
        tar = tarfile.open(name=os.path.join(self.testdir, 'tar_fails.tar'),
                           mode='w')
        build_tar_tree(tar, self.testdir, dir_tree,
                       base_path=self.testdir + '/')
        tar.close()
        return tar

    def test_extract_tar_fail_obj_name_len(self):
        tar = self.build_bad_tar()
        req = Request.blank('/tar_works/acc/cont/')
        req.environ['wsgi.input'] = open(os.path.join(self.testdir,
                                                      'tar_fails.tar'))
        resp = self.untar.handle_extract(req, '')
        resp_data = simplejson.loads(resp.body)
        self.assertEquals(resp_data['Number Created Files'], 4)
        self.assertEquals(resp_data['Failures'][0][0],
                          '/tar_works/acc/cont/base_fails1/' + ('f' * 101))

    def test_extract_tar_fail_max_file(self):
        tar = self.build_bad_tar()
        was_failed = self.untar.max_failed_files
        try:
            self.app.calls = 0
            self.untar.max_failed_files = 1
            req = Request.blank('/tar_works/acc/cont/')
            req.environ['wsgi.input'] = open(os.path.join(self.testdir,
                                                          'tar_fails.tar'))
            resp = self.untar.handle_extract(req, '')
            resp_data = simplejson.loads(resp.body)
            self.assertEquals(self.app.calls, 5)
            self.assertEquals(resp_data['Failures'][0][0],
                              '/tar_works/acc/cont/base_fails1/' + ('f' * 101))
        finally:
            self.untar.max_failed_files = was_failed

    def test_extract_tar_fail_max_cont(self):
        dir_tree = [{'sub_dir1': ['sub1_file1']},
                    {'sub_dir2': ['sub2_file1', 'sub2_file2']},
                    'f' * 101,
                    {'sub_dir3': [{'sub4_dir1': 'sub4_file1'}]}]
        tar = self.build_bad_tar(dir_tree)
        was_max_containers = self.untar.max_containers
        try:
            self.app.calls = 0
            self.untar.max_containers = 1
            req = Request.blank('/tar_works/acc/')
            req.environ['wsgi.input'] = open(os.path.join(self.testdir,
                                                          'tar_fails.tar'))
            resp = self.untar.handle_extract(req, '')
            self.assertEquals(self.app.calls, 3)
            self.assertEquals(resp.status_int, 400)
        finally:
            self.untar.max_containers = was_max_containers

    def test_extract_tar_fail_create_cont(self):
        tar = self.build_bad_tar()
        req = Request.blank('/create_cont_fail/acc/cont/')
        req.environ['wsgi.input'] = open(os.path.join(self.testdir,
                                                      'tar_fails.tar'))
        resp = self.untar.handle_extract(req, '')
        resp_data = simplejson.loads(resp.body)
        self.assertEquals(self.app.calls, 5)
        self.assertEquals(len(resp_data['Failures']), 5)

    def test_extract_tar_fail_create_cont_value_err(self):
        tar = self.build_bad_tar()
        req = Request.blank('/create_cont_fail/acc/cont/')
        req.environ['wsgi.input'] = open(os.path.join(self.testdir,
                                                      'tar_fails.tar'))
        def bad_create(req, path):
            raise ValueError('Test')

        was_func = self.untar.create_container_for_path
        try:
            self.untar.create_container_for_path = bad_create
            resp = self.untar.handle_extract(req, '')
            resp_data = simplejson.loads(resp.body)
            self.assertEquals(self.app.calls, 0)
            self.assertEquals(len(resp_data['Failures']), 5)
        finally:
            self.untar.create_container_for_path = was_func

if __name__ == '__main__':
    unittest.main()
