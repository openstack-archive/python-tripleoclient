#   Copyright 2013 Nebula Inc.
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

import mock
import sys


AUTH_TOKEN = "foobar"
AUTH_URL = "http://0.0.0.0"
WS_URL = "ws://0.0.0.0"


class FakeApp(object):
    def __init__(self):
        _stdout = None
        self.client_manager = None
        self.stdin = sys.stdin
        self.stdout = _stdout or sys.stdout
        self.stderr = sys.stderr
        self.restapi = None


class FakeClientManager(object):
    def __init__(self):
        self.identity = None
        self.workflow_engine = None
        self.tripleoclient = None
        self.auth_ref = None
        self.tripleoclient = FakeClientWrapper()
        self.workflow_engine = mock.Mock()


class FakeWebSocket(object):

    def wait_for_message(self, execution_id):
        return {
            'status': 'SUCCESS'
        }

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return


class FakeClientWrapper(object):

    def messaging_websocket(self, queue_name):
        return FakeWebSocket()
