#   Copyright 2017 Red Hat, Inc.
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

from tripleoclient.exceptions import DownloadError
from tripleoclient.tests.v1.overcloud_deploy import fakes
from tripleoclient.workflows import support


class TestSupportFetchLogs(fakes.TestDeployOvercloud):

    def setUp(self):
        super(TestSupportFetchLogs, self).setUp()
        self.app.client_manager = mock.Mock()
        self.app.client_manager.workflow_engine = self.workflow = mock.Mock()
        self.tripleoclient = mock.Mock()
        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch('tripleoclient.workflows.base.wait_for_messages')
    @mock.patch('tripleoclient.workflows.base.start_workflow')
    def test_fetch_logs(self, start_wf_mock, messages_mock):
        messages_mock.return_value = []
        fetch_name = 'tripleo.support.v1.fetch_logs'
        fetch_input = {
            'server_name': 'test',
            'container': 'test',
            'queue_name': 'UUID4'
        }
        support.fetch_logs(self.app.client_manager, 'test', 'test')
        start_wf_mock.assert_called_once_with(self.workflow,
                                              fetch_name,
                                              workflow_input=fetch_input)

    @mock.patch('tripleoclient.workflows.base.wait_for_messages')
    @mock.patch('tripleoclient.workflows.base.start_workflow')
    def test_fetch_logs_with_timeout(self, start_wf_mock, messages_mock):
        messages_mock.return_value = []
        fetch_name = 'tripleo.support.v1.fetch_logs'
        fetch_input = {
            'server_name': 'test',
            'container': 'test',
            'queue_name': 'UUID4',
            'timeout': 59,
        }
        support.fetch_logs(self.app.client_manager, 'test', 'test', timeout=59)
        start_wf_mock.assert_called_once_with(self.workflow,
                                              fetch_name,
                                              workflow_input=fetch_input)

    @mock.patch('tripleoclient.workflows.base.wait_for_messages')
    @mock.patch('tripleoclient.workflows.base.start_workflow')
    def test_fetch_logs_with_concurrency(self, start_wf_mock, messages_mock):
        messages_mock.return_value = []
        fetch_name = 'tripleo.support.v1.fetch_logs'
        fetch_input = {
            'server_name': 'test',
            'container': 'test',
            'queue_name': 'UUID4',
            'concurrency': 10,
        }
        support.fetch_logs(self.app.client_manager, 'test', 'test',
                           concurrency=10)
        start_wf_mock.assert_called_once_with(self.workflow,
                                              fetch_name,
                                              workflow_input=fetch_input)


class TestSupportDeleteContainer(fakes.TestDeployOvercloud):

    def setUp(self):
        super(TestSupportDeleteContainer, self).setUp()
        self.app.client_manager = mock.Mock()
        self.app.client_manager.workflow_engine = self.workflow = mock.Mock()
        self.tripleoclient = mock.Mock()
        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch('tripleoclient.workflows.base.wait_for_messages')
    @mock.patch('tripleoclient.workflows.base.start_workflow')
    def test_delete_container(self, start_wf_mock, messages_mock):
        messages_mock.return_value = []
        fetch_name = 'tripleo.support.v1.delete_container'
        fetch_input = {
            'container': 'test',
            'queue_name': 'UUID4'
        }
        support.delete_container(self.app.client_manager, 'test')
        start_wf_mock.assert_called_once_with(self.workflow,
                                              fetch_name,
                                              workflow_input=fetch_input)

    @mock.patch('tripleoclient.workflows.base.wait_for_messages')
    @mock.patch('tripleoclient.workflows.base.start_workflow')
    def test_delete_container_with_timeout(self, start_wf_mock, messages_mock):
        messages_mock.return_value = []
        fetch_name = 'tripleo.support.v1.delete_container'
        fetch_input = {
            'container': 'test',
            'queue_name': 'UUID4',
            'timeout': 59,
        }
        support.delete_container(self.app.client_manager, 'test', timeout=59)
        start_wf_mock.assert_called_once_with(self.workflow,
                                              fetch_name,
                                              workflow_input=fetch_input)

    @mock.patch('tripleoclient.workflows.base.wait_for_messages')
    @mock.patch('tripleoclient.workflows.base.start_workflow')
    def test_delete_container_with_concurrency(self, start_wf_mock,
                                               messages_mock):
        messages_mock.return_value = []
        fetch_name = 'tripleo.support.v1.delete_container'
        fetch_input = {
            'container': 'test',
            'queue_name': 'UUID4',
            'concurrency': 10,
        }
        support.delete_container(self.app.client_manager, 'test',
                                 concurrency=10)
        start_wf_mock.assert_called_once_with(self.workflow,
                                              fetch_name,
                                              workflow_input=fetch_input)


class TestDownloadContainer(fakes.TestDeployOvercloud):
    def setUp(self):
        super(TestDownloadContainer, self).setUp()

        self.app.client_manager.workflow_engine = mock.Mock()
        self.app.client_manager.tripleoclient = mock.Mock()
        self.app.client_manager.object_store = mock.Mock()

    def test_download_files_not_enough_space(self):
        support.check_local_space = mock.MagicMock()
        support.check_local_space.return_value = False
        oc = self.app.client_manager.object_store
        oc.object_list.return_value = [{'bytes': 100}]
        self.assertRaises(DownloadError,
                          support.download_files,
                          self.app.client_manager,
                          'test',
                          'test')

    @mock.patch('os.path.exists')
    def test_download_files(self, exists_mock):
        support.check_local_space = mock.MagicMock()
        support.check_local_space.return_value = True
        exists_mock.return_value = True
        oc = self.app.client_manager.object_store
        oc.object_list.return_value = [
            {'name': 'test1'}
        ]
        oc.object_save = mock.MagicMock()
        support.download_files(self.app.client_manager, 'test', '/test')
        oc.object_save.assert_called_with(container='test',
                                          object='test1',
                                          file='/test/test1')
