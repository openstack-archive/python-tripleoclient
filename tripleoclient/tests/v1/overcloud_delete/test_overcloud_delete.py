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
        'tripleoclient.workflows.stack_management.plan_undeploy',
        autospec=True)
    def test_plan_undeploy(self, mock_plan_undeploy):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration

        stack = mock.Mock()
        stack.id = 12345
        stack.stack_name = "foobar"
        orchestration_client.stacks.get.return_value = stack

        self.cmd._plan_undeploy(clients, 'overcloud')

    @mock.patch(
        'tripleoclient.workflows.stack_management.base.start_workflow',
        autospec=True)
    def test_plan_undeploy_wf_params(self, mock_plan_undeploy_wf):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration

        stack = mock.Mock()
        stack.id = 12345
        stack.stack_name = "foobar"
        orchestration_client.stacks.get.return_value = stack

        self.cmd._plan_undeploy(clients, 'overcloud')
