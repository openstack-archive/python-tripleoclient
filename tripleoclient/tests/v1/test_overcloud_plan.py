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


class TestOvercloudDeletePlan(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudDeletePlan, self).setUp()

        self.cmd = overcloud_plan.DeletePlan(self.app, None)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine

    def test_delete_plan(self):
        parsed_args = self.check_parser(self.cmd, ['test-plan'],
                                        [('plans', ['test-plan'])])

        self.workflow.action_executions.create.return_value = (
            mock.Mock(output='{"result": null}'))

        self.cmd.take_action(parsed_args)

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.delete_plan', input={'container': 'test-plan'})

    def test_delete_multiple_plans(self):
        argslist = ['test-plan1', 'test-plan2']
        verifylist = [('plans', ['test-plan1', 'test-plan2'])]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.workflow.action_executions.create.return_value = (
            mock.Mock(output='{"result": null}'))

        self.cmd.take_action(parsed_args)

        self.workflow.action_executions.create.assert_has_calls(
            [mock.call('tripleo.delete_plan',
                       input={'container': 'test-plan1'}),
             mock.call('tripleo.delete_plan',
                       input={'container': 'test-plan2'})])
