#   Copyright 2016 Red Hat, Inc.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

try:
    import http.server as BaseHTTPServer  # Python3
except ImportError:
    import BaseHTTPServer  # Python2
import datetime
import json
import logging
import os

from oslo_utils import timeutils

TOMORROW = timeutils.isotime(at=(timeutils.utcnow()
                                 + datetime.timedelta(days=1)))

VERSION_RESPONSE_GET = {
    "version": {
        "status": "stable",
        "updated": timeutils.isotime(),
        "media-types": [{
            "base": "application/json",
            "type": "application/vnd.openstack.identity-v3+json"
        }],
        "id": "v3.6",
        "links": [{
            "href": "http://127.0.0.1:%(api_port)s/v3/",
            "rel": "self"
        }]
    }
}

TOKEN_RESPONSE_POST = {
    "token": {
        "is_domain": False,
        "methods": ["password"],
        "roles": [{
            "id": "4c8de39b96794ab28bf37a0b842b8bc8",
            "name": "admin"
        }],
        "expires_at": TOMORROW,
        "project": {
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "admin",
            "name": "admin"
        },
        "catalog": [{
            "endpoints": [{
                "url": "http://127.0.0.1:%(heat_port)s/v1/admin",
                "interface": "public",
                "region": "regionOne",
                "region_id": "regionOne",
                "id": "2809305628004fb391b3d0254fb5b4f7"
            }, {
                "url": "http://127.0.0.1:%(heat_port)s/v1/admin",
                "interface": "internal",
                "region": "regionOne",
                "region_id": "regionOne",
                "id": "2809305628004fb391b3d0254fb5b4f7"
            }, {
                "url": "http://127.0.0.1:%(heat_port)s/v1/admin",
                "interface": "admin",
                "region": "regionOne",
                "region_id": "regionOne",
                "id": "2809305628004fb391b3d0254fb5b4f7"
            }],
            "type": "orchestration",
            "id": "96a549e3961d45cabe883dd17c5835be",
            "name": "heat"
        }, {
            "endpoints": [{
                "url": "http://127.0.0.1:%(api_port)s/v3",
                "interface": "public",
                "region": "regionOne",
                "region_id": "regionOne",
                "id": "eca215878e404a2d9dcbcc7f6a027165"
            }, {
                "url": "http://127.0.0.1:%(api_port)s/v3",
                "interface": "internal",
                "region": "regionOne",
                "region_id": "regionOne",
                "id": "eca215878e404a2d9dcbcc7f6a027165"
            }, {
                "url": "http://127.0.0.1:%(api_port)s/v3",
                "interface": "admin",
                "region": "regionOne",
                "region_id": "regionOne",
                "id": "eca215878e404a2d9dcbcc7f6a027165"
            }],
            "type": "identity",
            "id": "a785f0b7603042d1bf59237c71af2f15",
            "name": "keystone"
        }],
        "user": {
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "8b7b4c094f934e8c83aa7fe12591dc6c",
            "name": "admin"
        },
        "audit_ids": ["F6ONJ8fCT6i_CFTbmC0vBA"],
        "issued_at": timeutils.isotime()
    }
}

STACK_USER_ROLE_GET = {
    "links": {
        "self": "http://127.0.0.1:%(api_port)s/v3/roles",
        "previous": None,
        "next": None
    },
    "roles": [{
        "domain_id": None,
        "id": "b123456",
        "links": {
            "self": "http://127.0.0.1:%(api_port)s/v3/roles/b123456"
        },
        "name": "heat_stack_user"
    }]
}

STACK_USER_POST = {
    "user": {
        "name": "heat_stack_user",
        "links": {
            "self": "http://127.0.0.1:%(api_port)s/v3/users/c123456"
        },
        "domain_id": "default",
        "enabled": True,
        "email": "heat@localhost",
        "id": "c123456"
    }
}

AUTH_TOKEN_GET = {
    "token": {
        "issued_at": timeutils.isotime(),
        "audit_ids": ["PUrztDYYRBeq-C8CKr-kEw"],
        "methods": ["password"],
        "expires_at": TOMORROW,
        "user": {
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "8b7b4c094f934e8c83aa7fe12591dc6c",
            "name": "admin"
        }
    }
}


class FakeKeystone(BaseHTTPServer.BaseHTTPRequestHandler):

    log = logging.getLogger(__name__ + ".FakeKeystone")

    def _get_port_from_env(self):
        return os.environ.get('FAKE_KEYSTONE_PORT', '35358')

    def _get_heat_port_from_env(self):
        return os.environ.get('HEAT_API_PORT', '8006')

    def _format(self, my_json):
        return (json.dumps(my_json) % {'api_port': self._get_port_from_env(),
                'heat_port': self._get_heat_port_from_env()})

    def _send_headers(self, code=200):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.send_header('X-Auth-User', 'admin')
        self.send_header('X-Subject-Token', '123456789')
        self.end_headers()

    def do_GET(self):
        if self.path in ['/', '/v3', '/v3/']:
            self._send_headers(300)
            self.wfile.write(self._format(VERSION_RESPONSE_GET))
        elif self.path == '/v3/auth/tokens':
            self._send_headers(200)
            self.wfile.write(self._format(AUTH_TOKEN_GET))
        elif self.path.startswith('/v3/roles?name=heat_stack_user'):
            self._send_headers()
            self.wfile.write(self._format(STACK_USER_ROLE_GET))
        else:
            raise Exception('Not Implemented: %s' % self.path)

    def do_POST(self):
        if self.path == '/v3/auth/tokens':
            self._send_headers(201)
            self.wfile.write(self._format(TOKEN_RESPONSE_POST))
        elif self.path == '/v3/users':
            self._send_headers()
            self.wfile.write(self._format(STACK_USER_POST))
        else:
            raise Exception('Not Implemented: %s' % self.path)

    def do_PUT(self):
        if self.path.startswith('/v3/projects/admin/users/'):
            self._send_headers()
            pass  # NOTE: 200 response is good enough here
        else:
            raise Exception('Not Implemented: %s' % self.path)

    def log_message(self, format, *args):
        return


def launch():
    port = os.environ.get('FAKE_KEYSTONE_PORT', '35358')
    httpd = BaseHTTPServer.HTTPServer(('127.0.0.1', int(port)), FakeKeystone)
    httpd.serve_forever()
