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

from osc_lib.tests import utils

from tripleoclient import plugin

AUTH_TOKEN = "foobar"
AUTH_URL = "http://0.0.0.0"
WS_URL = "ws://0.0.0.0"
WSS_URL = "wss://0.0.0.0"

VALIDATIONS_LIST = [{
    'description': 'My Validation One Description',
    'groups': ['prep', 'pre-deployment'],
    'id': 'my_val1',
    'name': 'My Validition One Name',
    'parameters': {}
}, {
    'description': 'My Validation Two Description',
    'groups': ['prep', 'pre-introspection'],
    'id': 'my_val2',
    'name': 'My Validition Two Name',
    'parameters': {'min_value': 8}
}]

GROUPS_LIST = [
    ('group1', 'Group1 description'),
    ('group2', 'Group2 description'),
    ('group3', 'Group3 description'),
]

VALIDATIONS_LOGS_CONTENTS_LIST = [{
    'plays': [{
        'play': {
            'duration': {
                'end': '2019-11-25T13:40:17.538611Z',
                'start': '2019-11-25T13:40:14.404623Z',
                'time_elapsed': '0:00:03.753'
            },
            'host': 'undercloud',
            'id': '008886df-d297-1eaa-2a74-000000000008',
            'validation_id': '512e',
            'validation_path':
            '/usr/share/ansible/validation-playbooks'
        },
        'tasks': [
            {
                'hosts': {
                    'undercloud': {
                        '_ansible_no_log': False,
                        'action': 'command',
                        'changed': False,
                        'cmd': [u'ls', '/sys/class/block/'],
                        'delta': '0:00:00.018913',
                        'end': '2019-11-25 13:40:17.120368',
                        'invocation': {
                            'module_args': {
                                '_raw_params': 'ls /sys/class/block/',
                                '_uses_shell': False,
                                'argv': None,
                                'chdir': None,
                                'creates': None,
                                'executable': None,
                                'removes': None,
                                'stdin': None,
                                'stdin_add_newline': True,
                                'strip_empty_ends': True,
                                'warn': True
                            }
                        },
                        'rc': 0,
                        'start': '2019-11-25 13:40:17.101455',
                        'stderr': '',
                        'stderr_lines': [],
                        'stdout': 'vda',
                        'stdout_lines': [u'vda']
                    }
                },
                'task': {
                    'duration': {
                        'end': '2019-11-25T13:40:17.336687Z',
                        'start': '2019-11-25T13:40:14.529880Z'
                    },
                    'id':
                    '008886df-d297-1eaa-2a74-00000000000d',
                    'name':
                    'advanced-format-512e-support : List the available drives'
                }
            },
            {
                'hosts': {
                    'undercloud': {
                        'action':
                        'advanced_format',
                        'changed': False,
                        'msg':
                        'All items completed',
                        'results': [{
                            '_ansible_item_label': 'vda',
                            '_ansible_no_log': False,
                            'ansible_loop_var': 'item',
                            'changed': False,
                            'item': 'vda',
                            'skip_reason': 'Conditional result was False',
                            'skipped': True
                        }],
                        'skipped': True
                    }
                },
                'task': {
                    'duration': {
                        'end': '2019-11-25T13:40:17.538611Z',
                        'start': '2019-11-25T13:40:17.341704Z'
                    },
                    'id': '008886df-d297-1eaa-2a74-00000000000e',
                    'name':
                    'advanced-format-512e-support: Detect the drive'
                }
            }
        ]
    }],
    'stats': {
        'undercloud': {
            'changed': 0,
            'failures': 0,
            'ignored': 0,
            'ok': 1,
            'rescued': 0,
            'skipped': 1,
            'unreachable': 0
        }
    },
    'validation_output': []
}]


class FakeOptions(object):
    def __init__(self):
        self.debug = True


class FakeApp(object):
    def __init__(self):
        _stdout = None
        self.client_manager = None
        self.stdin = sys.stdin
        self.stdout = _stdout or sys.stdout
        self.stderr = sys.stderr
        self.restapi = None
        self.command_options = None
        self.options = FakeOptions()


class FakeStackObject(object):
    stack_name = 'undercloud'
    outputs = []

    @staticmethod
    def get(*args, **kwargs):
        pass


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


class FakeClientWrapper(object):

    def __init__(self):
        self._instance = mock.Mock()
        self.object_store = FakeObjectClient()


class FakeRunnerConfig(object):
    env = dict()  # noqa
    artifact_dir = ''

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


class FakeObjectClient(object):

    def __init__(self):
        self._instance = mock.Mock()
        self.put_object = mock.Mock()

    def get_object(self, *args):
        return [None, "fake"]

    def get_container(self, *args):
        return [None, [{"name": "fake"}]]


class FakePlaybookExecution(utils.TestCommand):

    def setUp(self, ansible_mock=True):
        super(FakePlaybookExecution, self).setUp()

        self.app.options = FakeOptions()
        self.app.client_manager.auth_ref = mock.Mock(auth_token="TOKEN")
        self.baremetal = self.app.client_manager.baremetal = mock.MagicMock()
        self.app.client_manager.baremetal_introspection = mock.MagicMock()
        self.inspector = self.app.client_manager.baremetal_introspection
        self.baremetal.node.list.return_value = []
        compute = self.app.client_manager.compute = mock.Mock()
        compute.servers.list.return_value = []
        self.app.client_manager.identity = mock.Mock()
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.network = mock.Mock()
        self.tripleoclient = mock.Mock()
        stack = self.app.client_manager.orchestration = mock.Mock()
        stack.stacks.get.return_value = FakeStackObject
        tc = self.app.client_manager.tripleoclient = FakeClientWrapper()
        tc.create_mistral_context = plugin.ClientWrapper(
             instance=FakeInstanceData).create_mistral_context

        get_key = mock.patch('tripleoclient.utils.get_key')
        get_key.start()
        get_key.return_value = 'keyfile-path'
        self.addCleanup(get_key.stop)

        self.register_or_update = mock.patch(
            'tripleoclient.workflows.baremetal.register_or_update',
            autospec=True,
            return_value=[mock.Mock(uuid='MOCK_NODE_UUID')]
        )
        self.register_or_update.start()
        self.addCleanup(self.register_or_update.stop)

        if ansible_mock:
            get_stack = mock.patch('tripleoclient.utils.get_stack')
            get_stack.start()
            stack = get_stack.return_value = mock.Mock()
            stack.stack_name = 'testStack'
            self.addCleanup(get_stack.stop)

            self.gcn = mock.patch(
                'tripleo_common.utils.config.Config',
                autospec=True
            )
            self.gcn.start()
            self.addCleanup(self.gcn.stop)

            self.mkdirs = mock.patch(
                'os.makedirs',
                autospec=True
            )
            self.mkdirs.start()
            self.addCleanup(self.mkdirs.stop)


def fake_ansible_runner_run_return(rc=0):

    return 'Test Status', rc
