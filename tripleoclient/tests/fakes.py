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
WSS_URL = "wss://0.0.0.0"


class FakeApp(object):
    def __init__(self):
        _stdout = None
        self.client_manager = None
        self.stdin = sys.stdin
        self.stdout = _stdout or sys.stdout
        self.stderr = sys.stderr
        self.restapi = None
        self.command_options = None


class FakeStackObject(object):
    stack_name = 'undercloud'


class FakeClientManager(object):
    def __init__(self):
        self.identity = None
        self.workflow_engine = None
        self.auth_ref = None
        self.tripleoclient = FakeClientWrapper()
        self.workflow_engine = mock.Mock()
        self.create_mistral_context = mock.Mock()


class FakeHandle(object):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return


class FakeFile(FakeHandle):
    def __init__(self, contents):
        self.contents = contents

    def read(self):
        if not self.contents:
            raise ValueError('I/O operation on closed file')
        return self.contents

    def close(self):
        self.contents = None


class FakeWebSocket(FakeHandle):

    def wait_for_messages(self, timeout=None):
        yield {
            'execution_id': 'IDID',
            'status': 'SUCCESS',
        }


class FakeClientWrapper(object):

    def __init__(self):
        self.ws = FakeWebSocket()

    def messaging_websocket(self):
        return self.ws


class FakeRunnerConfig(object):
    env = dict()  # noqa

    def prepare(self):
        pass


class FakeInstanceData(object):
    cacert = '/file/system/path'
    _region_name = 'region1'

    @staticmethod
    def get_endpoint_for_service_type(*args, **kwargs):
        return 'http://things'

    class auth_ref(object):
        trust_id = 'yy'
        project_id = 'ww'

    class auth(object):
        auth_url = 'http://url'
        _project_name = 'projectname'
        _username = 'username'
        _user_id = 'zz'

        @staticmethod
        def get_token(*args, **kwargs):
            return '12345abcde'

        @staticmethod
        def get_project_id(*args, **kwargs):
            return 'xx'

    class session(object):
        class auth(object):
            class auth_ref(object):
                _data = {'token': {}}


def fake_ansible_runner_run_return(rc=0):

    return 'Test Status', rc
