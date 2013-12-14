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

from hashlib import md5
from time import time

from swift import __canonical_version__ as swift_version
from swift.common.bufferedhttp import http_connect_raw
from swift.common.constraints import MAX_EXTENDED_SWIFT_INFO_ATTEMPTS
from swift.common.exceptions import ExtraSwiftInfoError
from swift.common.utils import public, get_hmac, get_swift_info, json, \
    streq_const_time, update_swift_info
from swift.proxy.controllers.base import Controller, delay_denial
from swift.common.swob import HTTPOk, HTTPForbidden, HTTPUnauthorized

_extended_info = False


class InfoController(Controller):
    """WSGI controller for info requests"""
    server_type = 'Info'

    def __init__(self, app, version, expose_info, disallowed_sections,
                 admin_key):
        Controller.__init__(self, app)
        self.expose_info = expose_info
        self.disallowed_sections = disallowed_sections
        self.admin_key = admin_key
        self.allowed_hmac_methods = {
            'HEAD': ['HEAD', 'GET'],
            'GET': ['GET']}

    @public
    @delay_denial
    def GET(self, req):
        return self.GETorHEAD(req)

    @public
    @delay_denial
    def HEAD(self, req):
        return self.GETorHEAD(req)

    @public
    @delay_denial
    def OPTIONS(self, req):
        return HTTPOk(request=req, headers={'Allow': 'HEAD, GET, OPTIONS'})

    def get_node_info(self, ring):
        """
        Retrieves swift info from a random node in the ring provided.

        If errors occur attempting to retrieve info from a node, a new
        node will be selected.  It will continue like this until either it
        finds a node which has a matching swift version, or until it has
        tried MAX_EXTENDED_SWIFT_INFO_ATTEMPTS times.

        :param ring: Ring to be used for the random selection of nodes.
        :returns: tuple of (ip, port, resp, info)

        :raises: ExtraSwiftInfoError if MAX_EXTENDED_SWIFT_INFO_ATTEMPTS is
                 exceeded without getting valid info back.
        """
        errors = []
        for x in xrange(MAX_EXTENDED_SWIFT_INFO_ATTEMPTS):
            seed = md5(str(time())).hexdigest()
            (partition, nodes) = ring.get_nodes(seed)
            ip = nodes[0]['ip']
            port = nodes[0]['port']

            conn = http_connect_raw(ip, port, 'GET', '/info')
            resp = conn.getresponse()

            data = resp.read()
            try:
                info = json.loads(data)
            except (TypeError, ValueError):
                errors.append({'ip': ip, 'port': port, 'msg': 'invalid json'})
                continue

            if resp.status != 200:
                errors.append({'ip': ip, 'port': port,
                               'msg': 'status: {0}'.format(resp.status)})
                continue

            node_version = None
            try:
                node_version = info['swift'].pop('version')
            except KeyError:
                pass

            if swift_version != node_version:
                errors.append({
                    'ip': ip, 'port': port,
                    'msg': ('proxy version ({0}) does not match '
                            'node version ({1})').format(
                    swift_version, node_version)})
                continue

            return (ip, port, resp, info)

        raise ExtraSwiftInfoError('/n'.join(
            ['ip: {0} | port: {1} | msg: {2}'.format(
                x['ip'], x['port'], x['msg']) for x in errors]))

    def load_extended_swift_info(self):
        """
        Retrieves swift info from a account, container and object server, then
        adds it to the proxy's swift info.

        Subsequent calls will return as, the extended info has already been
        merged in with the proxies swift info.

        :raises: ExtraSwiftInfoError (thrown by get_node_info) if valid
                 swift info can not be found in the ring provided.
        """
        global _extended_info
        if _extended_info:
            return

        data = []
        for ring in [self.app.account_ring,
                     self.app.container_ring,
                     self.app.object_ring]:
            (ip, port, resp, info) = self.get_node_info(ring)

            data.append({'ip': ip, 'port': port, 'resp': resp, 'info': info})

        for d in data:
            update_swift_info(d['info'])

        _extended_info = True

    def GETorHEAD(self, req):
        """
        Handles requests to /info
        Should return a WSGI-style callable (such as swob.Response).

        :param req: swob.Request object
        """
        if not self.expose_info:
            return HTTPForbidden(request=req)

        self.load_extended_swift_info()

        admin_request = False
        sig = req.params.get('swiftinfo_sig', '')
        expires = req.params.get('swiftinfo_expires', '')

        if sig != '' or expires != '':
            admin_request = True
            if not self.admin_key:
                return HTTPForbidden(request=req)
            try:
                expires = int(expires)
            except ValueError:
                return HTTPUnauthorized(request=req)
            if expires < time():
                return HTTPUnauthorized(request=req)

            valid_sigs = []
            for method in self.allowed_hmac_methods[req.method]:
                valid_sigs.append(get_hmac(method,
                                           '/info',
                                           expires,
                                           self.admin_key))

            # While it's true that any() will short-circuit, this doesn't
            # affect the timing-attack resistance since the only way this will
            # short-circuit is when a valid signature is passed in.
            is_valid_hmac = any(streq_const_time(valid_sig, sig)
                                for valid_sig in valid_sigs)
            if not is_valid_hmac:
                return HTTPUnauthorized(request=req)

        headers = {}
        if 'Origin' in req.headers:
            headers['Access-Control-Allow-Origin'] = req.headers['Origin']
            headers['Access-Control-Expose-Headers'] = ', '.join(
                ['x-trans-id'])

        info = json.dumps(get_swift_info(
            admin=admin_request, disallowed_sections=self.disallowed_sections))

        return HTTPOk(request=req,
                      headers=headers,
                      body=info,
                      content_type='application/json; charset=UTF-8')
