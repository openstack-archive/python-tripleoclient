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

from osc_lib.tests import utils

from tripleoclient import exceptions
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
            'tripleo.plan.list')

        self.assertEqual(0, len(result[1]))

    def test_list(self):
        self.workflow.action_executions.create.return_value = (
            mock.Mock(output='{"result": ["test-plan-1", "test-plan-2"]}'))

        result = self.cmd.take_action(None)
        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.plan.list')

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
            'tripleo.plan.delete', input={'container': 'test-plan'})

    def test_delete_multiple_plans(self):
        argslist = ['test-plan1', 'test-plan2']
        verifylist = [('plans', ['test-plan1', 'test-plan2'])]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.workflow.action_executions.create.return_value = (
            mock.Mock(output='{"result": null}'))

        self.cmd.take_action(parsed_args)

        self.workflow.action_executions.create.assert_has_calls(
            [mock.call('tripleo.plan.delete',
                       input={'container': 'test-plan1'}),
             mock.call('tripleo.plan.delete',
                       input={'container': 'test-plan2'})])


class TestOvercloudCreatePlan(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudCreatePlan, self).setUp()

        self.cmd = overcloud_plan.CreatePlan(self.app, None)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.tripleoclient = mock.Mock()

        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient = mock.Mock()
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient

        self.workflow = self.app.client_manager.workflow_engine

        # Mock UUID4 generation for every test
        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    def test_create_default_plan(self):

        # Setup
        arglist = ['overcast']
        verifylist = [
            ('name', 'overcast'),
            ('templates', None)
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS"
        }

        # Run
        self.cmd.take_action(parsed_args)

        # Verify
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.create_default_deployment_plan',
            workflow_input={
                'container': 'overcast',
                'queue_name': 'UUID4'
            })

    def test_create_default_plan_failed(self):

        # Setup
        arglist = ['overcast']
        verifylist = [
            ('name', 'overcast'),
            ('templates', None)
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.websocket.wait_for_message.return_value = {
            "status": "ERROR", "message": "failed"
        }

        # Run
        self.assertRaises(exceptions.WorkflowServiceError,
                          self.cmd.take_action, parsed_args)

        # Verify
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.create_default_deployment_plan',
            workflow_input={
                'container': 'overcast',
                'queue_name': 'UUID4'
            })

    @mock.patch("tripleoclient.workflows.plan_management.tarball")
    def test_create_custom_plan(self, mock_tarball):

        # Setup
        arglist = ['overcast', '--templates', '/fake/path']
        verifylist = [
            ('name', 'overcast'),
            ('templates', '/fake/path')
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS"
        }
        mock_result = mock.Mock(output='{"result": null}')
        self.workflow.action_executions.create.return_value = mock_result

        # Run
        self.cmd.take_action(parsed_args)

        # Verify
        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.plan.create_container', {"container": "overcast"}
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.create_deployment_plan',
            workflow_input={
                'container': 'overcast',
                'queue_name': 'UUID4'
            })

    @mock.patch("tripleoclient.workflows.plan_management.tarball")
    def test_create_custom_plan_failed(self, mock_tarball):

        # Setup
        arglist = ['overcast', '--templates', '/fake/path']
        verifylist = [
            ('name', 'overcast'),
            ('templates', '/fake/path')
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.websocket.wait_for_message.return_value = {
            "status": "ERROR", "message": "failed"
        }
        mock_result = mock.Mock(output='{"result": null}')
        self.workflow.action_executions.create.return_value = mock_result

        # Run
        self.assertRaises(exceptions.WorkflowServiceError,
                          self.cmd.take_action, parsed_args)

        # Verify
        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.plan.create_container', {"container": "overcast"}
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.create_deployment_plan',
            workflow_input={
                'container': 'overcast',
                'queue_name': 'UUID4'
            })


class TestOvercloudDeployPlan(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudDeployPlan, self).setUp()

        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_plan.DeployPlan(self.app, app_args)

        self.workflow = self.app.client_manager.workflow_engine = mock.Mock()
        self.orch = self.app.client_manager.orchestration = mock.Mock()

        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient = mock.Mock()
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient

        # Mock UUID4 generation for every test
        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch('tripleoclient.utils.wait_for_stack_ready', autospec=True)
    def test_overcloud_deploy_plan(self, mock_for_stack_ready):

        # Setup
        arglist = ['overcast']
        verifylist = [
            ('name', 'overcast')
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # No existing stack, this is a new deploy.
        self.orch.stacks.get.return_value = None

        self.websocket.wait_for_message.return_value = {
            'status': 'SUCCESS'
        }

        mock_for_stack_ready.return_value = True

        # Run
        self.cmd.take_action(parsed_args)

        # Verify
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.deployment.v1.deploy_plan',
            workflow_input={
                'container': 'overcast',
                'queue_name': 'UUID4'
            }
        )
