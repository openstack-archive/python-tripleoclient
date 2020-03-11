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
        self._mock_websocket = mock.Mock()
        self._mock_websocket.__enter__ = mock.Mock(
            return_value=self._mock_websocket)
        # Return False to avoid silencing exceptions
        self._mock_websocket.__exit__ = mock.Mock(return_value=False)
        self._mock_websocket.wait_for_messages = mock.Mock(
            return_value=iter([{
                "status": "SUCCESS",
                "message": "Success",
                "execution_id": "IDID"
            }])
        )

    def messaging_websocket(self):
        return self._mock_websocket


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
        baremetal = self.app.client_manager.baremetal = mock.Mock()
        baremetal.node.list.return_value = []
        compute = self.app.client_manager.compute = mock.Mock()
        compute.servers.list.return_value = []
        self.app.client_manager.identity = mock.Mock()
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.network = mock.Mock()
        tc = self.app.client_manager.tripleoclient = FakeClientWrapper()
        self.tripleoclient = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine = mock.Mock()
        stack = self.app.client_manager.orchestration = mock.Mock()
        stack.stacks.get.return_value = FakeStackObject
        tc.create_mistral_context = plugin.ClientWrapper(
            instance=FakeInstanceData
        ).create_mistral_context

        # NOTE(cloudnull): When mistral is gone this should be removed.
        self.execution = mock.Mock()
        self.execution.id = "IDID"
        self.workflow.executions.create.return_value = self.execution

        config_mock = mock.patch(
            'tripleo_common.actions.config.GetOvercloudConfig',
            autospec=True
        )
        config_mock.start()
        self.addCleanup(config_mock.stop)

        self.ansible = mock.patch(
            'tripleo_common.actions.ansible.AnsibleGenerateInventoryAction',
            autospec=True
        )
        self.ansible.start()
        self.addCleanup(self.ansible.stop)

        self.config_action = mock.patch(
            'tripleo_common.actions.config.DownloadConfigAction',
            autospec=True
        )
        self.config_action.start()
        self.addCleanup(self.config_action.stop)
        get_key = mock.patch('tripleoclient.utils.get_key')
        get_key.start()
        get_key.return_value = 'keyfile-path'
        self.addCleanup(get_key.stop)

        self.register_or_update = mock.patch(
            'tripleo_common.actions.baremetal.RegisterOrUpdateNodes.run',
            autospec=True,
            return_value=[mock.Mock(uuid='MOCK_NODE_UUID')]
        )
        self.register_or_update.start()
        self.addCleanup(self.register_or_update.stop)
        self.boot_action = mock.patch(
            'tripleo_common.actions.baremetal.ConfigureBootAction.run',
            autospec=True,
            return_value=None
        )
        self.boot_action.start()
        self.addCleanup(self.boot_action.stop)
        self.boot_action = mock.patch(
            'tripleo_common.actions.baremetal.ConfigureRootDeviceAction.run',
            autospec=True
        )
        self.boot_action.start()
        self.addCleanup(self.boot_action.stop)

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
