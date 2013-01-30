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

    def __call__(self, env, start_response):
        self.calls += 1
        if env['PATH_INFO'].startswith('/test_good/'):
            return Response(
                status=200,
                headers={'etag': 'etagoftheobjectsegment',
                         'Content-Length': 100})(env, start_response)


test_xml_data = '''<?xml version="1.0" encoding="UTF-8"?>
<static_large_object>
<object_segment>
<path>/cont/object</path>
<etag>etagoftheobjectsegment</etag>
<size_bytes>100</size_bytes>
</object_segment>
</static_large_object>
'''


class TestStaticLargeObject(unittest.TestCase):

    def setUp(self):
        self.app = FakeApp()
        self.slo = slo.filter_factory({})(self.app)

    def tearDown(self):
        pass

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
        self.assertEquals(self.slo.validate_content_type(req).status_int, 400)

    def test_put_manifest_too_big(self):
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

    def test_handle_multipart_put_success(self):
        req = Request.blank(
            '/test_good/AUTH_test/c/man?multipart-manifest=put&format=xml',
            environ={'REQUEST_METHOD': 'PUT'}, body=test_xml_data)
        self.slo.handle_multipart_put(req)
        self.assertEquals(req.headers['X-Static-Large-Object'], 'True')

if __name__ == '__main__':
    unittest.main()
