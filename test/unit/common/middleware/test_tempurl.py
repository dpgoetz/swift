# Copyright (c) 2011 OpenStack, LLC.
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

import hmac
import unittest
from hashlib import sha1
from contextlib import contextmanager
from time import time

from swift.common.swob import Request, Response, HeaderKeyDict
from swift.common.middleware import tempauth, tempurl


class FakeMemcache(object):

    def __init__(self):
        self.store = {}
        self.times = {}

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value, time=0):
        self.store[key] = value
        self.times[key] = time
        return True

    def incr(self, key, time=0):
        self.store[key] = self.store.setdefault(key, 0) + 1
        if time:
            self.times[key] = time
        return self.store[key]

    def time_for_key(self, key):
        return self.times.get(key)

    @contextmanager
    def soft_lock(self, key, timeout=0, retries=5):
        yield True

    def delete(self, key):
        try:
            del self.store[key]
        except Exception:
            pass
        return True


class FakeApp(object):

    def __init__(self, status_headers_body_iter=None):
        self.calls = 0
        self.status_headers_body_iter = status_headers_body_iter
        if not self.status_headers_body_iter:
            self.status_headers_body_iter = iter([('404 Not Found', {
                'x-test-header-one-a': 'value1',
                'x-test-header-two-a': 'value2',
                'x-test-header-two-b': 'value3'}, '')])
        self.request = None

    def __call__(self, env, start_response):
        self.calls += 1
        self.request = Request.blank('', environ=env)
        if 'swift.authorize' in env:
            resp = env['swift.authorize'](self.request)
            if resp:
                return resp(env, start_response)
        status, headers, body = self.status_headers_body_iter.next()
        return Response(status=status, headers=headers,
                        body=body)(env, start_response)


class TestTempURL(unittest.TestCase):

    def setUp(self):
        self.app = FakeApp()
        self.auth = tempauth.filter_factory({})(self.app)
        self.auth.reseller_prefix = 'a'
        self.tempurl = tempurl.filter_factory({})(self.auth)

    def _make_request(self, path, **kwargs):
        req = Request.blank(path, **kwargs)
        req.environ['swift.cache'] = FakeMemcache()
        return req

    def test_passthrough(self):
        resp = self._make_request('/v1/a/c/o').get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' not in resp.body)

    def test_allow_options(self):
        self.app.status_headers_body_iter = iter([('200 Ok', {}, '')])
        resp = self._make_request(
            '/v1/a/c/o?temp_url_sig=abcde&temp_url_expires=12345',
            environ={'REQUEST_METHOD': 'OPTIONS'}).get_response(self.tempurl)
        self.assertEquals(resp.status_int, 200)

    def test_get_valid(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()

    def assert_valid_sig(self, expires, path, keys, sig):
        req = self._make_request(path,
            environ={'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', keys)
        self.tempurl.app = FakeApp(iter([('200 Ok', (), '123')]))
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.headers['content-disposition'],
                          'attachment; filename="o"')
        self.assertEquals(req.environ['swift.authorize_override'], True)
        self.assertEquals(req.environ['REMOTE_USER'], '.wsgi.tempurl')

    def test_get_valid(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        self.assert_valid_sig(expires, path, [key], sig)

    def test_get_valid_key2(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key1 = 'abc123'
        key2 = 'def456'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig1 = hmac.new(key1, hmac_body, sha1).hexdigest()
        sig2 = hmac.new(key2, hmac_body, sha1).hexdigest()
        for sig in (sig1, sig2):
            self.assert_valid_sig(expires, path, [key1, key2], sig)

    def test_get_valid_with_filename(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path, environ={
            'QUERY_STRING': 'temp_url_sig=%s&temp_url_expires=%s&'
            'filename=bob%%20%%22killer%%22.txt' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        self.tempurl.app = FakeApp(iter([('200 Ok', (), '123')]))
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.headers['content-disposition'],
                          'attachment; filename="bob \\\"killer\\\".txt"')
        self.assertEquals(req.environ['swift.authorize_override'], True)
        self.assertEquals(req.environ['REMOTE_USER'], '.wsgi.tempurl')

    def test_obj_trailing_slash(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o/'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path, environ={
            'QUERY_STRING': 'temp_url_sig=%s&temp_url_expires=%s' % (
                sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        self.tempurl.app = FakeApp(iter([('200 Ok', (), '123')]))
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.headers['content-disposition'],
                          'attachment; filename="o"')
        self.assertEquals(req.environ['swift.authorize_override'], True)
        self.assertEquals(req.environ['REMOTE_USER'], '.wsgi.tempurl')

    def test_filename_trailing_slash(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path, environ={
            'QUERY_STRING': 'temp_url_sig=%s&temp_url_expires=%s&'
            'filename=/i/want/this/just/as/it/is/' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        self.tempurl.app = FakeApp(iter([('200 Ok', (), '123')]))
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.headers['content-disposition'],
                          'attachment; filename="/i/want/this/just/as/it/is/"')
        self.assertEquals(req.environ['swift.authorize_override'], True)
        self.assertEquals(req.environ['REMOTE_USER'], '.wsgi.tempurl')

    def test_get_valid_but_404(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 404)
        self.assertFalse('content-disposition' in resp.headers)
        self.assertEquals(req.environ['swift.authorize_override'], True)
        self.assertEquals(req.environ['REMOTE_USER'], '.wsgi.tempurl')

    def test_put_not_allowed_by_get(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'REQUEST_METHOD': 'PUT',
                     'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' in resp.body)

    def test_put_valid(self):
        method = 'PUT'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'REQUEST_METHOD': 'PUT',
                     'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 404)
        self.assertEquals(req.environ['swift.authorize_override'], True)
        self.assertEquals(req.environ['REMOTE_USER'], '.wsgi.tempurl')

    def test_get_not_allowed_by_put(self):
        method = 'PUT'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' in resp.body)

    def test_cache_miss_with_keys(self):
        self.app.status_headers_body_iter = iter(
            [('200 OK', {'X-Account-Meta-Temp-Url-Key': 'some-key'}, '')])
        # doesn't have to be valid, just has to trigger a check
        req = self._make_request('/v1/a/c/o',
            environ={'QUERY_STRING':
                     'temp_url_sig=abcd&temp_url_expires=%d' %
                     int(time() + 1000)})
        resp = req.get_response(self.tempurl)

        self.assertEquals(resp.status_int, 401)
        self.assertEquals(
            ['some-key'],
            req.environ['swift.cache'].get('temp-url-keys/a'))
        self.assertEquals(
            60,
            req.environ['swift.cache'].time_for_key('temp-url-keys/a'))

    def test_cache_miss_without_keys(self):
        self.app.status_headers_body_iter = iter([('200 OK', {}, '')])
        req = self._make_request('/v1/a/c/o',
            environ={'QUERY_STRING':
                     'temp_url_sig=abcd&temp_url_expires=%d' %
                     int(time() + 1000)})
        resp = req.get_response(self.tempurl)

        self.assertEquals(resp.status_int, 401)
        self.assertEquals(
            [],
            req.environ['swift.cache'].get('temp-url-keys/a'))
        self.assertEquals(
            6,
            req.environ['swift.cache'].time_for_key('temp-url-keys/a'))

    def test_missing_sig(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'QUERY_STRING': 'temp_url_expires=%s' % expires})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' in resp.body)

    def test_missing_expires(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'QUERY_STRING': 'temp_url_sig=%s' % sig})
        req.environ['swift.cache'].set('temp-url-key/a', key)
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' in resp.body)

    def test_bad_path(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-key/a', key)
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' in resp.body)

    def test_no_key(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' in resp.body)

    def test_head_allowed_by_get(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'REQUEST_METHOD': 'HEAD',
                     'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 404)
        self.assertEquals(req.environ['swift.authorize_override'], True)
        self.assertEquals(req.environ['REMOTE_USER'], '.wsgi.tempurl')

    def test_head_allowed_by_put(self):
        method = 'PUT'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'REQUEST_METHOD': 'HEAD',
                     'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 404)
        self.assertEquals(req.environ['swift.authorize_override'], True)
        self.assertEquals(req.environ['REMOTE_USER'], '.wsgi.tempurl')

    def test_head_otherwise_not_allowed(self):
        method = 'PUT'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        # Deliberately fudge expires to show HEADs aren't just automatically
        # allowed.
        expires += 1
        req = self._make_request(path,
            environ={'REQUEST_METHOD': 'HEAD',
                     'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-key/a', key)
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)

    def test_post_not_allowed(self):
        method = 'POST'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'REQUEST_METHOD': 'POST',
                     'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-key/a', key)
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' in resp.body)

    def test_delete_not_allowed(self):
        method = 'DELETE'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'REQUEST_METHOD': 'DELETE',
                     'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-key/a', key)
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' in resp.body)

    def test_delete_allowed_with_conf(self):
        self.tempurl.methods.append('DELETE')
        method = 'DELETE'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'REQUEST_METHOD': 'DELETE',
                     'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 404)

    def test_unknown_not_allowed(self):
        method = 'UNKNOWN'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'REQUEST_METHOD': 'UNKNOWN',
                     'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' in resp.body)

    def test_changed_path_invalid(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path + '2',
            environ={'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' in resp.body)

    def test_changed_sig_invalid(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        if sig[-1] != '0':
            sig = sig[:-1] + '0'
        else:
            sig = sig[:-1] + '1'
        req = self._make_request(path,
            environ={'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' in resp.body)

    def test_changed_expires_invalid(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' %
                       (sig, expires + 1)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' in resp.body)

    def test_different_key_invalid(self):
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key + '2'])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 401)
        self.assertTrue('Temp URL invalid' in resp.body)

    def test_removed_incoming_header(self):
        self.tempurl = tempurl.filter_factory({
            'incoming_remove_headers': 'x-remove-this'})(self.auth)
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path, headers={'x-remove-this': 'value'},
            environ={'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 404)
        self.assertTrue('x-remove-this' not in self.app.request.headers)

    def test_removed_incoming_headers_match(self):
        self.tempurl = tempurl.filter_factory({
            'incoming_remove_headers': 'x-remove-this-*',
            'incoming_allow_headers': 'x-remove-this-except-this'})(self.auth)
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            headers={'x-remove-this-one': 'value1',
                     'x-remove-this-except-this': 'value2'},
            environ={'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 404)
        self.assertTrue('x-remove-this-one' not in self.app.request.headers)
        self.assertEquals(
            self.app.request.headers['x-remove-this-except-this'], 'value2')

    def test_removed_outgoing_header(self):
        self.tempurl = tempurl.filter_factory({
            'outgoing_remove_headers': 'x-test-header-one-a'})(self.auth)
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 404)
        self.assertTrue('x-test-header-one-a' not in resp.headers)
        self.assertEquals(resp.headers['x-test-header-two-a'], 'value2')

    def test_removed_outgoing_headers_match(self):
        self.tempurl = tempurl.filter_factory({
            'outgoing_remove_headers': 'x-test-header-two-*',
            'outgoing_allow_headers': 'x-test-header-two-b'})(self.auth)
        method = 'GET'
        expires = int(time() + 86400)
        path = '/v1/a/c/o'
        key = 'abc'
        hmac_body = '%s\n%s\n%s' % (method, expires, path)
        sig = hmac.new(key, hmac_body, sha1).hexdigest()
        req = self._make_request(path,
            environ={'QUERY_STRING':
                       'temp_url_sig=%s&temp_url_expires=%s' % (sig, expires)})
        req.environ['swift.cache'].set('temp-url-keys/a', [key])
        resp = req.get_response(self.tempurl)
        self.assertEquals(resp.status_int, 404)
        self.assertEquals(resp.headers['x-test-header-one-a'], 'value1')
        self.assertTrue('x-test-header-two-a' not in resp.headers)
        self.assertEquals(resp.headers['x-test-header-two-b'], 'value3')

    def test_get_account(self):
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'HEAD', 'PATH_INFO': '/v1/a/c/o'}), 'a')
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'GET', 'PATH_INFO': '/v1/a/c/o'}), 'a')
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'PUT', 'PATH_INFO': '/v1/a/c/o'}), 'a')
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'POST', 'PATH_INFO': '/v1/a/c/o'}), None)
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'DELETE', 'PATH_INFO': '/v1/a/c/o'}), None)
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'UNKNOWN', 'PATH_INFO': '/v1/a/c/o'}), None)
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'GET', 'PATH_INFO': '/v1/a/c/'}), None)
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'GET', 'PATH_INFO': '/v1/a/c//////'}), None)
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'GET', 'PATH_INFO': '/v1/a/c///o///'}), 'a')
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'GET', 'PATH_INFO': '/v1/a/c'}), None)
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'GET', 'PATH_INFO': '/v1/a//o'}), None)
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'GET', 'PATH_INFO': '/v1//c/o'}), None)
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'GET', 'PATH_INFO': '//a/c/o'}), None)
        self.assertEquals(self.tempurl._get_account({
            'REQUEST_METHOD': 'GET', 'PATH_INFO': '/v2/a/c/o'}), None)

    def test_get_temp_url_info(self):
        s = 'f5d5051bddf5df7e27c628818738334f'
        e = int(time() + 86400)
        self.assertEquals(self.tempurl._get_temp_url_info({'QUERY_STRING':
            'temp_url_sig=%s&temp_url_expires=%s' % (s, e)}), (s, e, None))
        self.assertEquals(self.tempurl._get_temp_url_info({
            'QUERY_STRING': 'temp_url_sig=%s&temp_url_expires=%s&'
            'filename=bobisyouruncle' % (s, e)}), (s, e, 'bobisyouruncle'))
        self.assertEquals(self.tempurl._get_temp_url_info({}),
                          (None, None, None))
        self.assertEquals(self.tempurl._get_temp_url_info({'QUERY_STRING':
            'temp_url_expires=%s' % e}), (None, e, None))
        self.assertEquals(self.tempurl._get_temp_url_info({'QUERY_STRING':
            'temp_url_sig=%s' % s}), (s, None, None))
        self.assertEquals(self.tempurl._get_temp_url_info({'QUERY_STRING':
            'temp_url_sig=%s&temp_url_expires=bad' % s}), (s, 0, None))
        e = int(time() - 1)
        self.assertEquals(self.tempurl._get_temp_url_info({'QUERY_STRING':
            'temp_url_sig=%s&temp_url_expires=%s' % (s, e)}), (s, 0, None))

    def test_get_key_memcache(self):
        self.app.status_headers_body_iter = iter([('404 Not Found', {}, '')])
        self.assertEquals(
            self.tempurl._get_keys({}, 'a'), [])
        self.app.status_headers_body_iter = iter([('404 Not Found', {}, '')])
        self.assertEquals(
            self.tempurl._get_keys({'swift.cache': None}, 'a'), [])
        mc = FakeMemcache()
        self.app.status_headers_body_iter = iter([('404 Not Found', {}, '')])
        self.assertEquals(
            self.tempurl._get_keys({'swift.cache': mc}, 'a'), [])
        mc.set('temp-url-keys/a', ['abc', 'def'])
        self.assertEquals(
            self.tempurl._get_keys({'swift.cache': mc}, 'a'), ['abc', 'def'])

    def test_get_keys_from_source(self):
        self.app.status_headers_body_iter = \
            iter([('200 Ok', {'x-account-meta-temp-url-key': 'abc'}, '')])
        mc = FakeMemcache()
        self.assertEquals(
            self.tempurl._get_keys({'swift.cache': mc}, 'a'), ['abc'])
        self.assertEquals(mc.get('temp-url-keys/a'), ['abc'])

        self.app.status_headers_body_iter = \
            iter([('200 Ok',
                   {'x-account-meta-temp-url-key': 'abc',
                    'x-account-meta-temp-url-key-2': 'def'},
                   '')])
        mc = FakeMemcache()
        self.assertEquals(
            sorted(self.tempurl._get_keys({'swift.cache': mc}, 'a')),
            ['abc', 'def'])
        self.assertEquals(sorted(mc.get('temp-url-keys/a')), ['abc', 'def'])

        # no keys at all: still gets cached
        self.app.status_headers_body_iter = iter([('200 Ok', {}, '')])
        mc = FakeMemcache()
        self.assertEquals(
            sorted(self.tempurl._get_keys({'swift.cache': mc}, 'a')),
            [])
        self.assertEquals(sorted(mc.get('temp-url-keys/a')), [])

    def test_get_hmac(self):
        self.assertEquals(self.tempurl._get_hmac(
                {'REQUEST_METHOD': 'GET', 'PATH_INFO': '/v1/a/c/o'},
                1, 'abc'),
            '026d7f7cc25256450423c7ad03fc9f5ffc1dab6d')
        self.assertEquals(self.tempurl._get_hmac(
                {'REQUEST_METHOD': 'HEAD', 'PATH_INFO': '/v1/a/c/o'},
                1, 'abc', request_method='GET'),
            '026d7f7cc25256450423c7ad03fc9f5ffc1dab6d')

    def test_invalid(self):

        def _start_response(status, headers, exc_info=None):
            self.assertTrue(status, '401 Unauthorized')

        self.assertTrue('Temp URL invalid' in
            ''.join(self.tempurl._invalid({'REQUEST_METHOD': 'GET'},
                                          _start_response)))
        self.assertEquals('',
            ''.join(self.tempurl._invalid({'REQUEST_METHOD': 'HEAD'},
                                          _start_response)))

    def test_clean_incoming_headers(self):
        irh = ''
        iah = ''
        env = {'HTTP_TEST_HEADER': 'value'}
        tempurl.TempURL(None, {'incoming_remove_headers': irh,
            'incoming_allow_headers': iah})._clean_incoming_headers(env)
        self.assertTrue('HTTP_TEST_HEADER' in env)

        irh = 'test-header'
        iah = ''
        env = {'HTTP_TEST_HEADER': 'value'}
        tempurl.TempURL(None, {'incoming_remove_headers': irh,
            'incoming_allow_headers': iah})._clean_incoming_headers(env)
        self.assertTrue('HTTP_TEST_HEADER' not in env)

        irh = 'test-header-*'
        iah = ''
        env = {'HTTP_TEST_HEADER_ONE': 'value',
               'HTTP_TEST_HEADER_TWO': 'value'}
        tempurl.TempURL(None, {'incoming_remove_headers': irh,
            'incoming_allow_headers': iah})._clean_incoming_headers(env)
        self.assertTrue('HTTP_TEST_HEADER_ONE' not in env)
        self.assertTrue('HTTP_TEST_HEADER_TWO' not in env)

        irh = 'test-header-*'
        iah = 'test-header-two'
        env = {'HTTP_TEST_HEADER_ONE': 'value',
               'HTTP_TEST_HEADER_TWO': 'value'}
        tempurl.TempURL(None, {'incoming_remove_headers': irh,
            'incoming_allow_headers': iah})._clean_incoming_headers(env)
        self.assertTrue('HTTP_TEST_HEADER_ONE' not in env)
        self.assertTrue('HTTP_TEST_HEADER_TWO' in env)

        irh = 'test-header-* test-other-header'
        iah = 'test-header-two test-header-yes-*'
        env = {'HTTP_TEST_HEADER_ONE': 'value',
               'HTTP_TEST_HEADER_TWO': 'value',
               'HTTP_TEST_OTHER_HEADER': 'value',
               'HTTP_TEST_HEADER_YES': 'value',
               'HTTP_TEST_HEADER_YES_THIS': 'value'}
        tempurl.TempURL(None, {'incoming_remove_headers': irh,
            'incoming_allow_headers': iah})._clean_incoming_headers(env)
        self.assertTrue('HTTP_TEST_HEADER_ONE' not in env)
        self.assertTrue('HTTP_TEST_HEADER_TWO' in env)
        self.assertTrue('HTTP_TEST_OTHER_HEADER' not in env)
        self.assertTrue('HTTP_TEST_HEADER_YES' not in env)
        self.assertTrue('HTTP_TEST_HEADER_YES_THIS' in env)

    def test_clean_outgoing_headers(self):
        orh = ''
        oah = ''
        hdrs = {'test-header': 'value'}
        hdrs = HeaderKeyDict(tempurl.TempURL(None,
            {'outgoing_remove_headers': orh, 'outgoing_allow_headers': oah}
            )._clean_outgoing_headers(hdrs.iteritems()))
        self.assertTrue('test-header' in hdrs)

        orh = 'test-header'
        oah = ''
        hdrs = {'test-header': 'value'}
        hdrs = HeaderKeyDict(tempurl.TempURL(None,
            {'outgoing_remove_headers': orh, 'outgoing_allow_headers': oah}
            )._clean_outgoing_headers(hdrs.iteritems()))
        self.assertTrue('test-header' not in hdrs)

        orh = 'test-header-*'
        oah = ''
        hdrs = {'test-header-one': 'value',
                'test-header-two': 'value'}
        hdrs = HeaderKeyDict(tempurl.TempURL(None,
            {'outgoing_remove_headers': orh, 'outgoing_allow_headers': oah}
            )._clean_outgoing_headers(hdrs.iteritems()))
        self.assertTrue('test-header-one' not in hdrs)
        self.assertTrue('test-header-two' not in hdrs)

        orh = 'test-header-*'
        oah = 'test-header-two'
        hdrs = {'test-header-one': 'value',
                'test-header-two': 'value'}
        hdrs = HeaderKeyDict(tempurl.TempURL(None,
            {'outgoing_remove_headers': orh, 'outgoing_allow_headers': oah}
            )._clean_outgoing_headers(hdrs.iteritems()))
        self.assertTrue('test-header-one' not in hdrs)
        self.assertTrue('test-header-two' in hdrs)

        orh = 'test-header-* test-other-header'
        oah = 'test-header-two test-header-yes-*'
        hdrs = {'test-header-one': 'value',
                'test-header-two': 'value',
                'test-other-header': 'value',
                'test-header-yes': 'value',
                'test-header-yes-this': 'value'}
        hdrs = HeaderKeyDict(tempurl.TempURL(None,
            {'outgoing_remove_headers': orh, 'outgoing_allow_headers': oah}
            )._clean_outgoing_headers(hdrs.iteritems()))
        self.assertTrue('test-header-one' not in hdrs)
        self.assertTrue('test-header-two' in hdrs)
        self.assertTrue('test-other-header' not in hdrs)
        self.assertTrue('test-header-yes' not in hdrs)
        self.assertTrue('test-header-yes-this' in hdrs)


if __name__ == '__main__':
    unittest.main()
