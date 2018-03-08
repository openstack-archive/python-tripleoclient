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

from osc_lib.tests import utils
from tripleoclient.workflows import undercloud_backup


class TestUndercloudBackup(utils.TestCommand):

    def setUp(self):
        super(TestUndercloudBackup, self).setUp()
        self.app.client_manager = mock.Mock()
        self.app.client_manager.workflow_engine = self.workflow = mock.Mock()
        self.tripleoclient = mock.Mock()
        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient

    @mock.patch('tripleoclient.workflows.base.wait_for_messages')
    @mock.patch('tripleoclient.workflows.base.start_workflow')
    def test_run_backup(self, start_wf_mock, messages_mock):
        messages_mock.return_value = []
        fetch_name = 'tripleo.undercloud_backup.v1.backup'
        fetch_input = {
            'sources_path': '/home/stack/'
        }
        undercloud_backup.backup(self.app.client_manager, fetch_input)
        start_wf_mock.assert_called_once_with(self.workflow,
                                              fetch_name,
                                              workflow_input=fetch_input)

    @mock.patch('tripleoclient.workflows.base.wait_for_messages')
    @mock.patch('tripleoclient.workflows.base.start_workflow')
    def test_run_backup_with_args(self, start_wf_mock, messages_mock):
        messages_mock.return_value = []
        fetch_name = 'tripleo.undercloud_backup.v1.backup'
        fetch_input = {
            'sources_path': '/tmp/file1.txt,/home/stack/'
        }
        undercloud_backup.backup(self.app.client_manager, fetch_input)
        start_wf_mock.assert_called_once_with(self.workflow,
                                              fetch_name,
                                              workflow_input=fetch_input)
