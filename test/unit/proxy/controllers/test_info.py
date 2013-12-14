# Copyright (c) 2010-2012 OpenStack Foundation
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
import time
from mock import Mock, patch

from swift import __canonical_version__ as swift_version
from swift.common import utils
from swift.common.constraints import MAX_EXTENDED_SWIFT_INFO_ATTEMPTS
from swift.common.exceptions import ExtraSwiftInfoError
from swift.common.utils import json
from swift.common.swob import Request, HTTPException
from swift.proxy.controllers import info, InfoController
from swift.proxy.server import Application as ProxyApp
from test.unit import FakeRing, fake_http_connect


class TestInfoController(unittest.TestCase):
    def setUp(self):
        info._extended_info = False
        utils._swift_info = {}
        utils._swift_admin_info = {}

    def get_controller(self, expose_info=None, disallowed_sections=None,
                       admin_key=None):
        disallowed_sections = disallowed_sections or []

        app = Mock(spec=ProxyApp)
        app.account_ring = FakeRing()
        app.container_ring = FakeRing()
        app.object_ring = FakeRing()
        return InfoController(app, None, expose_info,
                              disallowed_sections, admin_key)

    def start_response(self, status, headers):
        self.got_statuses.append(status)
        for h in headers:
            self.got_headers.append({h[0]: h[1]})

    def get_fake_bodies(self, **kwargs):
        """
        Create fake resoponses for http_connect when askign the
        account/container/object nodes for swift info.

        :returns: list of strings representing the body of the response.
        """
        bodies = []

        body = {'swift': {'version': swift_version},
                'section-a': {'foo-a': 'bar-a'},
                'admin': {'quux-a': 'corge-a'}}
        for key in kwargs.iterkeys():
            body['{0}-a'.format(key)] = kwargs[key]
        bodies.append(json.dumps(body))

        body = {'swift': {'version': swift_version},
                'section-c': {'foo-c': 'bar-c'},
                'admin': {'quux-c': 'corge-c'}}
        for key in kwargs.iterkeys():
            body['{0}-c'.format(key)] = kwargs[key]
        bodies.append(json.dumps(body))

        body = {'swift': {'version': swift_version},
                'section-o': {'foo-o': 'bar-o'},
                'admin': {'quux-o': 'corge-o'}}
        for key in kwargs:
            body['{0}-o'.format(key)] = kwargs[key]
        bodies.append(json.dumps(body))

        return bodies

    def test_disabled_info(self):
        controller = self.get_controller(expose_info=False)

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies())):
            req = Request.blank('/info', environ={'REQUEST_METHOD': 'GET'})
            resp = controller.GET(req)

        req = Request.blank(
            '/info', environ={'REQUEST_METHOD': 'GET'})
        resp = controller.GET(req)
        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('403 Forbidden', str(resp))

    def test_get_info(self):
        info._extended_info = False
        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        controller = self.get_controller(expose_info=True)

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies())):
            req = Request.blank('/info', environ={'REQUEST_METHOD': 'GET'})
            resp = controller.GET(req)

        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('200 OK', str(resp))
        data = json.loads(resp.body)

        self.assertTrue('admin' not in data)
        self.assertTrue('quux-a' not in data)
        self.assertTrue('quux-c' not in data)
        self.assertTrue('quux-o' not in data)
        self.assertTrue('foo' in data)
        self.assertTrue('bar' in data['foo'])
        self.assertTrue('section-a' in data)
        self.assertTrue('foo-a' in data['section-a'])
        self.assertEqual(data['section-a']['foo-a'], 'bar-a')
        self.assertTrue('section-c' in data)
        self.assertTrue('foo-c' in data['section-c'])
        self.assertEqual(data['section-c']['foo-c'], 'bar-c')
        self.assertTrue('section-o' in data)
        self.assertTrue('foo-o' in data['section-o'])
        self.assertEqual(data['section-o']['foo-o'], 'bar-o')
        self.assertEqual(data['foo']['bar'], 'baz')

    def test_options_info(self):
        controller = self.get_controller(expose_info=True)

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies())):
            req = Request.blank('/info', environ={'REQUEST_METHOD': 'GET'})
            resp = controller.OPTIONS(req)

        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('200 OK', str(resp))
        self.assertTrue('Allow' in resp.headers)

    def test_get_info_cors(self):
        controller = self.get_controller(expose_info=True)
        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies())):
            req = Request.blank(
                '/info', environ={'REQUEST_METHOD': 'GET'},
                headers={'Origin': 'http://example.com'})
            resp = controller.GET(req)

        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('200 OK', str(resp))
        data = json.loads(resp.body)
        self.assertTrue('admin' not in data)
        self.assertTrue('foo' in data)
        self.assertTrue('bar' in data['foo'])
        self.assertEqual(data['foo']['bar'], 'baz')
        self.assertTrue('Access-Control-Allow-Origin' in resp.headers)
        self.assertTrue('Access-Control-Expose-Headers' in resp.headers)

    def test_head_info(self):
        controller = self.get_controller(expose_info=True)
        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies())):
            req = Request.blank('/info', environ={'REQUEST_METHOD': 'HEAD'})
            resp = controller.HEAD(req)

        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('200 OK', str(resp))

    def test_disallow_info(self):
        controller = self.get_controller(
            expose_info=True,
            disallowed_sections=['foo2', 'bar2-a', 'bar2-c', 'bar2-o'])

        utils._swift_info = {'foo': {'bar': 'baz'},
                             'foo2': {'bar2': 'baz2'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies(bar2={}))):
            req = Request.blank('/info', environ={'REQUEST_METHOD': 'GET'})
            resp = controller.GET(req)

        self.assertTrue('bar2-a' in utils._swift_info)
        self.assertTrue('bar2-c' in utils._swift_info)
        self.assertTrue('bar2-o' in utils._swift_info)
        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('200 OK', str(resp))
        data = json.loads(resp.body)
        self.assertTrue('foo' in data)
        self.assertTrue('bar' in data['foo'])
        self.assertEqual(data['foo']['bar'], 'baz')
        self.assertTrue('foo2' not in data)
        self.assertTrue('foo2-a' not in data)
        self.assertTrue('foo2-c' not in data)
        self.assertTrue('foo2-o' not in data)

    def test_disabled_admin_info(self):
        controller = self.get_controller(expose_info=True, admin_key='')
        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        expires = int(time.time() + 86400)
        sig = utils.get_hmac('GET', '/info', expires, '')
        path = '/info?swiftinfo_sig={sig}&swiftinfo_expires={expires}'.format(
            sig=sig, expires=expires)

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies())):
            req = Request.blank(path, environ={'REQUEST_METHOD': 'GET'})
            resp = controller.GET(req)

        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('403 Forbidden', str(resp))

    def test_get_admin_info(self):
        controller = self.get_controller(expose_info=True,
                                         admin_key='secret-admin-key')
        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        expires = int(time.time() + 86400)
        sig = utils.get_hmac('GET', '/info', expires, 'secret-admin-key')
        path = '/info?swiftinfo_sig={sig}&swiftinfo_expires={expires}'.format(
            sig=sig, expires=expires)

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies())):
            req = Request.blank(path, environ={'REQUEST_METHOD': 'GET'})
            resp = controller.GET(req)

        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('200 OK', str(resp))
        data = json.loads(resp.body)
        self.assertTrue('admin' in data)
        self.assertTrue('qux' in data['admin'])
        self.assertTrue('quux' in data['admin']['qux'])
        self.assertEqual(data['admin']['qux']['quux'], 'corge')

    def test_head_admin_info(self):
        controller = self.get_controller(expose_info=True,
                                         admin_key='secret-admin-key')
        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        expires = int(time.time() + 86400)
        sig = utils.get_hmac('GET', '/info', expires, 'secret-admin-key')
        path = '/info?swiftinfo_sig={sig}&swiftinfo_expires={expires}'.format(
            sig=sig, expires=expires)

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies())):
            req = Request.blank(path, environ={'REQUEST_METHOD': 'HEAD'})
            resp = controller.GET(req)

        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('200 OK', str(resp))

        expires = int(time.time() + 86400)
        sig = utils.get_hmac('HEAD', '/info', expires, 'secret-admin-key')
        path = '/info?swiftinfo_sig={sig}&swiftinfo_expires={expires}'.format(
            sig=sig, expires=expires)
        req = Request.blank(
            path, environ={'REQUEST_METHOD': 'HEAD'})
        resp = controller.GET(req)
        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('200 OK', str(resp))

    def test_get_admin_info_invalid_method(self):
        controller = self.get_controller(expose_info=True,
                                         admin_key='secret-admin-key')
        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        expires = int(time.time() + 86400)
        sig = utils.get_hmac('HEAD', '/info', expires, 'secret-admin-key')
        path = '/info?swiftinfo_sig={sig}&swiftinfo_expires={expires}'.format(
            sig=sig, expires=expires)

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies())):
            req = Request.blank(path, environ={'REQUEST_METHOD': 'GET'})
            resp = controller.GET(req)

        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('401 Unauthorized', str(resp))

    def test_get_admin_info_invalid_expires(self):
        controller = self.get_controller(expose_info=True,
                                         admin_key='secret-admin-key')
        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        expires = 1
        sig = utils.get_hmac('GET', '/info', expires, 'secret-admin-key')
        path = '/info?swiftinfo_sig={sig}&swiftinfo_expires={expires}'.format(
            sig=sig, expires=expires)

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies())):
            req = Request.blank(path, environ={'REQUEST_METHOD': 'GET'})
            resp = controller.GET(req)

        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('401 Unauthorized', str(resp))

        expires = 'abc'
        sig = utils.get_hmac('GET', '/info', expires, 'secret-admin-key')
        path = '/info?swiftinfo_sig={sig}&swiftinfo_expires={expires}'.format(
            sig=sig, expires=expires)
        req = Request.blank(
            path, environ={'REQUEST_METHOD': 'GET'})
        resp = controller.GET(req)
        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('401 Unauthorized', str(resp))

    def test_get_admin_info_invalid_path(self):
        controller = self.get_controller(expose_info=True,
                                         admin_key='secret-admin-key')
        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        expires = int(time.time() + 86400)
        sig = utils.get_hmac('GET', '/foo', expires, 'secret-admin-key')
        path = '/info?swiftinfo_sig={sig}&swiftinfo_expires={expires}'.format(
            sig=sig, expires=expires)

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies())):
            req = Request.blank(path, environ={'REQUEST_METHOD': 'GET'})
            resp = controller.GET(req)

        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('401 Unauthorized', str(resp))

    def test_get_admin_info_invalid_key(self):
        controller = self.get_controller(expose_info=True,
                                         admin_key='secret-admin-key')
        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        expires = int(time.time() + 86400)
        sig = utils.get_hmac('GET', '/foo', expires, 'invalid-admin-key')
        path = '/info?swiftinfo_sig={sig}&swiftinfo_expires={expires}'.format(
            sig=sig, expires=expires)

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies())):
            req = Request.blank(path, environ={'REQUEST_METHOD': 'GET'})
            resp = controller.GET(req)

        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('401 Unauthorized', str(resp))

    def test_admin_disallow_info(self):
        controller = self.get_controller(
            expose_info=True,
            disallowed_sections=['foo2', 'bar2-a', 'bar2-c', 'bar2-o'],
            admin_key='secret-admin-key')

        utils._swift_info = {'foo': {'bar': 'baz'},
                             'foo2': {'bar2': 'baz2'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        expires = int(time.time() + 86400)
        sig = utils.get_hmac('GET', '/info', expires, 'secret-admin-key')
        path = '/info?swiftinfo_sig={sig}&swiftinfo_expires={expires}'.format(
            sig=sig, expires=expires)

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(200, 200, 200,
                                     body_iter=self.get_fake_bodies(bar2={}))):
            req = Request.blank(path, environ={'REQUEST_METHOD': 'GET'})
            resp = controller.GET(req)

        self.assertTrue('bar2-a' in utils._swift_info)
        self.assertTrue('bar2-c' in utils._swift_info)
        self.assertTrue('bar2-o' in utils._swift_info)
        self.assertTrue(isinstance(resp, HTTPException))
        self.assertEqual('200 OK', str(resp))
        data = json.loads(resp.body)
        self.assertTrue('foo2' not in data)
        self.assertTrue('admin' in data)
        self.assertTrue('disallowed_sections' in data['admin'])
        self.assertTrue('foo2' in data['admin']['disallowed_sections'])
        self.assertTrue('bar2-a' in data['admin']['disallowed_sections'])
        self.assertTrue('bar2-c' in data['admin']['disallowed_sections'])
        self.assertTrue('bar2-o' in data['admin']['disallowed_sections'])
        self.assertTrue('qux' in data['admin'])
        self.assertTrue('quux' in data['admin']['qux'])
        self.assertEqual(data['admin']['qux']['quux'], 'corge')

    def test_extended_info_fails_with_invalid_json(self):
        controller = self.get_controller(expose_info=True)

        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        status = []
        bodies = []
        for x in xrange(MAX_EXTENDED_SWIFT_INFO_ATTEMPTS):
            status.append(200)
            bodies.append('')

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(*status, body_iter=bodies)):
            req = Request.blank('/info', environ={'REQUEST_METHOD': 'GET'})
            self.assertRaises(ExtraSwiftInfoError, controller.GET, req)

    def test_extended_info_fails_with_bad_response_status(self):
        controller = self.get_controller(expose_info=True)

        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        status = []
        bodies = []
        for x in xrange(MAX_EXTENDED_SWIFT_INFO_ATTEMPTS):
            status.append(500)
            bodies.append('')

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(*status, body_iter=bodies)):
            req = Request.blank('/info', environ={'REQUEST_METHOD': 'GET'})
            self.assertRaises(ExtraSwiftInfoError, controller.GET, req)

    def test_extended_info_fails_with_mismatched_versions(self):
        controller = self.get_controller(expose_info=True)

        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        status = []
        bodies = []
        for x in xrange(MAX_EXTENDED_SWIFT_INFO_ATTEMPTS):
            status.append(200)
            bodies.append(json.dumps(
                {'swift': {
                 'version': '{0}.1'.format(swift_version)}}))

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(*status, body_iter=bodies)):
            req = Request.blank('/info', environ={'REQUEST_METHOD': 'GET'})
            self.assertRaises(ExtraSwiftInfoError, controller.GET, req)

    def test_extended_info_retries_on_failure(self):
        controller = self.get_controller(expose_info=True)

        utils._swift_info = {'foo': {'bar': 'baz'}}
        utils._swift_admin_info = {'qux': {'quux': 'corge'}}

        status = []
        bodies = []
        for x in xrange(MAX_EXTENDED_SWIFT_INFO_ATTEMPTS - 1):
            status.append(200)
            bodies.append(json.dumps(
                {'swift': {'version': '{0}.1'.format(swift_version)}}))
        status = status + [200, 200, 200]
        bodies = bodies + self.get_fake_bodies()

        with patch('swift.proxy.controllers.info.http_connect_raw',
                   fake_http_connect(*status, body_iter=bodies)):
            req = Request.blank('/info', environ={'REQUEST_METHOD': 'GET'})
            resp = controller.GET(req)

        data = json.loads(resp.body)

        self.assertTrue('section-a' in data)
        self.assertTrue('foo-a' in data['section-a'])
        self.assertEqual(data['section-a']['foo-a'], 'bar-a')


if __name__ == '__main__':
    unittest.main()
