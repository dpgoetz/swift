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

import unittest
from mock import patch
from swift.common.middleware import slo
from swift.common.utils import json
from swift.common.swob import Request, Response, HTTPException, \
    HTTPRequestEntityTooLarge


class FakeApp(object):
    def __init__(self):
        self.calls = 0
        self.req_method_paths = []

    def __call__(self, env, start_response):
        self.calls += 1
        if env['PATH_INFO'] == '/':
            return Response(status=200, body='passed')(env, start_response)
        if env['PATH_INFO'].startswith('/test_good/'):
            return Response(
                status=200,
                headers={'etag': 'etagoftheobjectsegment',
                         'Content-Length': 100})(env, start_response)
        if env['PATH_INFO'].startswith('/test_good_check/'):
            j, v, a, cont, obj = env['PATH_INFO'].split('/')
            etag, size = obj.split('_')
            last_mod = 'Fri, 01 Feb 2012 20:38:36 GMT'
            if obj == 'a_1':
                last_mod = ''
            return Response(
                status=200,
                headers={'etag': etag, 'Last-Modified': last_mod,
                         'Content-Length': size})(env, start_response)
        if env['PATH_INFO'].startswith('/test_get/'):
            good_data = json.dumps(
                [{'name': '/c/a_1', 'hash': 'a', 'bytes': '1'},
                 {'name': '/d/b_2', 'hash': 'b', 'bytes': '2'},])
            return Response(status=200, body=good_data)(env, start_response)

        if env['PATH_INFO'].startswith('/test_delete_404/'):
            self.req_method_paths.append((env['REQUEST_METHOD'], env['PATH_INFO']))
            return Response(status=404)(env, start_response)

        if env['PATH_INFO'].startswith('/test_delete/'):
            good_data = json.dumps(
                [{'name': '/c/a_1', 'hash': 'a', 'bytes': '1'},
                 {'name': '/d/b_2', 'hash': 'b', 'bytes': '2'},])
            self.req_method_paths.append((env['REQUEST_METHOD'], env['PATH_INFO']))
            return Response(status=200, body=good_data)(env, start_response)

        if env['PATH_INFO'].startswith('/test_delete_bad/'):
            good_data = json.dumps(
                [{'name': '/c/a_1', 'hash': 'a', 'bytes': '1'},
                 {'name': '/d/b_2', 'hash': 'b', 'bytes': '2'},])
            self.req_method_paths.append((env['REQUEST_METHOD'], env['PATH_INFO']))
            if env['PATH_INFO'].endswith('/c/a_1'):
                return Response(status=401)(env, start_response)
            return Response(status=200, body=good_data)(env, start_response)

test_xml_data = '''<?xml version="1.0" encoding="UTF-8"?>
<static_large_object>
<object_segment>
<path>/cont/object</path>
<etag>etagoftheobjectsegment</etag>
<size_bytes>100</size_bytes>
</object_segment>
</static_large_object>
'''


def fake_start_response(*args, **kwargs):
    pass


class TestStaticLargeObject(unittest.TestCase):

    def setUp(self):
        self.app = FakeApp()
        self.slo = slo.filter_factory({})(self.app)

    def tearDown(self):
        pass

    def test_handle_multipart_no_obj(self):
        req = Request.blank('/')
        resp_iter = self.slo(req.environ, fake_start_response)
        self.assertEquals(self.app.calls, 1)
        self.assertEquals(''.join(resp_iter), 'passed')

    def test_format_manifest_xml(self):
        data_dict = [{'name': '/cont/object',
                      'hash': 'etagoftheobjectsegment',
                      'content_type': 'testtype',
                      'bytes': 100}]
        self.assertEquals(test_xml_data, slo.format_manifest(data_dict, 'xml'))
        self.assert_('content_type' not in
                     json.loads(slo.format_manifest(data_dict, 'json'))[0])
        self.assertEquals(
            '/cont/object',
            json.loads(slo.format_manifest(data_dict, 'json'))[0]['path'])
        self.assertRaises(
            HTTPException, slo.format_manifest, data_dict, 'hello')

    def test_parse_input(self):
        self.assertRaises(HTTPException,
                          slo.parse_input, test_xml_data, 'hello')
        self.assertEquals('/cont/object',
                          slo.parse_input(test_xml_data, 'xml')[0]['path'])
        self.assertRaises(HTTPException,
                          slo.parse_input, test_xml_data[:-8], 'xml')
        self.assertRaises(
            HTTPException, slo.parse_input,
            test_xml_data.replace('static_large_object', 'static_large_o'),
            'xml')
        self.assertRaises(
            HTTPException, slo.parse_input,
            test_xml_data.replace('object_segment', 'object_'),
            'xml')
        data = json.dumps(
            [{'path': '/cont/object', 'etag': 'etagoftheobjecitsegment',
              'size_bytes': 100}])
        self.assertEquals('/cont/object',
                          slo.parse_input(data, 'json')[0]['path'])

        bad_data = json.dumps([{'path': '/cont/object', 'size_bytes': 100}])
        self.assertRaises(HTTPException, slo.parse_input, bad_data, 'json')

    def test_validate_content_type(self):
        req = Request.blank(
            '/v/a/c/o', headers={'Content-Type': 'text/html; swift_hey=there'})
        self.assertRaises(HTTPException, self.slo.validate_content_type, req)

    def test_put_manifest_too_quick_fail(self):
        req = Request.blank('/')
        req.content_length = self.slo.max_manifest_size + 1
        try:
            self.slo.handle_multipart_put(req)
        except HTTPException, e:
            self.assertEquals(e.status_int, 413)

        with patch.object(self.slo, 'max_manifest_segments', 0):
            req = Request.blank('/?format=xml', body=test_xml_data)
            try:
                self.slo.handle_multipart_put(req)
            except HTTPException, e:
                self.assertEquals(e.status_int, 413)

        req = Request.blank('/', headers={'X-Copy-From': 'lala'})
        try:
            self.slo.handle_multipart_put(req)
        except HTTPException, e:
            self.assertEquals(e.status_int, 405)

        # ignores requests to /
        req = Request.blank(
            '/?multipart-manifest=put&format=xml',
            environ={'REQUEST_METHOD': 'PUT'}, body=test_xml_data)
        self.assertEquals(self.slo.handle_multipart_put(req), self.app)

    def test_handle_multipart_put_success(self):
        req = Request.blank(
            '/test_good/AUTH_test/c/man?multipart-manifest=put&format=xml',
            environ={'REQUEST_METHOD': 'PUT'}, headers={'Accept': 'test'},
            body=test_xml_data)
        self.assertTrue('X-Static-Large-Object' not in req.headers)
        # and just to be sure
        self.assertTrue(not 'X-Static-Large-Object' in req.headers)
        self.slo(req.environ, fake_start_response)
        self.assertEquals(req.headers['X-Static-Large-Object'], 'True')

    def test_handle_multipart_put_bad_data(self):
        bad_data = json.dumps([{'path': '/cont/object',
                                'etag': 'etagoftheobj',
                                'size_bytes': 'lala'},])
        req = Request.blank(
            '/test_good/AUTH_test/c/man?multipart-manifest=put&format=json',
            environ={'REQUEST_METHOD': 'PUT'}, body=bad_data)
        self.assertRaises(HTTPException, self.slo.handle_multipart_put, req)

    def test_handle_multipart_put_check_data(self):
        good_data = json.dumps(
            [{'path': '/c/a_1', 'etag': 'a', 'size_bytes': '1'},
             {'path': '/d/b_2', 'etag': 'b', 'size_bytes': '2'},])
        req = Request.blank(
            '/test_good_check/A/c/man?multipart-manifest=put&format=json',
            environ={'REQUEST_METHOD': 'PUT'}, body=good_data)
        self.slo.handle_multipart_put(req)
        self.assertEquals(self.app.calls, 2)
        self.assert_(req.environ['CONTENT_TYPE'].endswith(';swift_bytes=3'))
        manifest_data = json.loads(req.environ['wsgi.input'].read())
        self.assertEquals(len(manifest_data), 2)
        self.assertEquals(manifest_data[0]['hash'], 'a')
        self.assertEquals(manifest_data[0]['bytes'], 1)
        self.assert_(not manifest_data[0]['last_modified'].startswith('2012'))
        self.assert_(manifest_data[1]['last_modified'].startswith('2012'))

    def test_handle_multipart_put_check_data_bad(self):
        bad_data = json.dumps(
            [{'path': '/c/a_1', 'etag': 'a', 'size_bytes': '1'},
             {'path': '/d/b_2', 'etag': 'b', 'size_bytes': '2'},])
        req = Request.blank(
            '/test_good/A/c/man?multipart-manifest=put&format=json',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Accept': 'application/json'},
            body=bad_data)
        try:
            self.slo.handle_multipart_put(req)
        except HTTPException, e:
            self.assertEquals(self.app.calls, 2)
            data = json.loads(e.body)
            errors = data['Errors']
            self.assertEquals(errors[0][0], '/test_good/A/c/a_1')
            self.assertEquals(errors[0][1], 'Size Mismatch')
            self.assertEquals(errors[-1][0], '/test_good/A/d/b_2')
            self.assertEquals(errors[-1][1], 'Etag Mismatch')
        else:
            self.assert_(False)

    def test_handle_multipart_get_json(self):
        good_data = json.dumps(
            [{'path': '/c/a_1', 'etag': 'a', 'size_bytes': '1'},
             {'path': '/d/b_2', 'etag': 'b', 'size_bytes': '2'},])
        req = Request.blank(
            '/test_get/A/c/man?multipart-manifest=get',
            environ={'REQUEST_METHOD': 'GET'})
        resp = self.slo.handle_multipart_get(req)
        self.assertEquals(self.app.calls, 1)
        self.assertEquals(resp.body, good_data)

    def test_handle_multipart_get_xml(self):
        good_data = json.dumps(
            [{'path': '/c/a_1', 'etag': 'a', 'size_bytes': '1'},
             {'path': '/d/b_2', 'etag': 'b', 'size_bytes': '2'},])
        req = Request.blank(
            '/test_get/A/c/man?multipart-manifest=get&format=xml',
            environ={'REQUEST_METHOD': 'GET'})
        p = self.slo(req.environ, fake_start_response)
        self.assertEquals(self.app.calls, 1)
        resp_body = ''.join(p)
        self.assert_('<path>/c/a_1</path>' in resp_body)
        self.assert_('<path>/d/b_2</path>' in resp_body)

    def test_handle_multipart_delete_man(self):
        req = Request.blank(
            '/test_good/A/c/man', environ={'REQUEST_METHOD': 'DELETE'})
        self.slo(req.environ, fake_start_response)
        self.assertEquals(self.app.calls, 1)

    def test_handle_multipart_delete_whole_404(self):
        req = Request.blank(
            '/test_delete_404/A/c/man?multipart-manifest=delete',
            environ={'REQUEST_METHOD': 'DELETE'})
        self.slo(req.environ, fake_start_response)
        self.assertEquals(self.app.calls, 1)
        self.assertEquals(self.app.req_method_paths,
                          [('GET', '/test_delete_404/A/c/man'),])

    def test_handle_multipart_delete_whole(self):
        req = Request.blank(
            '/test_delete/A/c/man?multipart-manifest=delete',
            environ={'REQUEST_METHOD': 'DELETE'})
        self.slo(req.environ, fake_start_response)
        self.assertEquals(self.app.calls, 4)
        self.assertEquals(self.app.req_method_paths,
                          [('GET', '/test_delete/A/c/man'),
                           ('DELETE', '/test_delete/A/c/a_1'),
                           ('DELETE', '/test_delete/A/d/b_2'),
                           ('DELETE', '/test_delete/A/c/man')])

    def test_handle_multipart_delete_whole_bad(self):
        req = Request.blank(
            '/test_delete_bad/A/c/man?multipart-manifest=delete',
            environ={'REQUEST_METHOD': 'DELETE'})
        self.slo(req.environ, fake_start_response)
        self.assertEquals(self.app.calls, 2)
        self.assertEquals(self.app.req_method_paths,
                          [('GET', '/test_delete_bad/A/c/man'),
                           ('DELETE', '/test_delete_bad/A/c/a_1')])

if __name__ == '__main__':
    unittest.main()
