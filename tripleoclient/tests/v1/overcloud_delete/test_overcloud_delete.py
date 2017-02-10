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

import mock

from tripleoclient.tests.v1.overcloud_deploy import fakes
from tripleoclient.v1 import overcloud_delete


class TestDeleteOvercloud(fakes.TestDeployOvercloud):

    def setUp(self):
        super(TestDeleteOvercloud, self).setUp()

        self.cmd = overcloud_delete.DeleteOvercloud(self.app, None)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine

    @mock.patch(
        'tripleoclient.workflows.stack_management.delete_stack', autospec=True)
    def test_stack_delete(self, mock_delete_stack):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration

        stack = mock.Mock()
        stack.id = 12345
        orchestration_client.stacks.get.return_value = stack

        self.cmd._stack_delete(clients, 'overcloud')

        orchestration_client.stacks.get.assert_called_once_with('overcloud')
        mock_delete_stack.assert_called_once_with(
            clients, stack=12345)

    def test_stack_delete_no_stack(self):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        type(orchestration_client.stacks.get).return_value = None
        self.cmd.log.warning = mock.MagicMock()

        self.cmd._stack_delete(clients, 'overcloud')

        orchestration_client.stacks.get.assert_called_once_with('overcloud')
        self.cmd.log.warning.assert_called_once_with(
            "No stack found ('overcloud'), skipping delete")

    @mock.patch(
        'tripleoclient.workflows.plan_management.delete_deployment_plan',
        autospec=True)
    def test_plan_delete(self, delete_deployment_plan_mock):
        self.cmd._plan_delete(self.workflow, 'overcloud')

        delete_deployment_plan_mock.assert_called_once_with(
            self.workflow,
            container='overcloud')
