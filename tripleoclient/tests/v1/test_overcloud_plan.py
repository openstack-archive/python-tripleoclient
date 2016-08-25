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

import mock

from openstackclient.tests import utils

from tripleoclient.v1 import overcloud_plan


class TestOvercloudPlanList(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudPlanList, self).setUp()

        self.cmd = overcloud_plan.ListPlans(self.app, None)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine

    def test_list_empty(self):
        self.workflow.action_executions.create.return_value = (
            mock.Mock(output='{"result": []}'))

        result = self.cmd.take_action(None)
        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.list_plans')

        self.assertEqual(0, len(result[1]))

    def test_list(self):
        self.workflow.action_executions.create.return_value = (
            mock.Mock(output='{"result": ["test-plan-1", "test-plan-2"]}'))

        result = self.cmd.take_action(None)
        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.list_plans')

        self.assertEqual(1, len(result[0]))
        self.assertEqual([('test-plan-1',), ('test-plan-2',)], result[1])
