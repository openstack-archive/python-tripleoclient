# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import mock

from osc_lib.tests import utils

from tripleoclient import exceptions
from tripleoclient.workflows import plan_management


class TestPlanCreationWorkflows(utils.TestCommand):

    def setUp(self):
        super(TestPlanCreationWorkflows, self).setUp()
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

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    def test_create_plan_from_templates_success(self, mock_tarball):
        output = mock.Mock(output='{"result": ""}')
        self.workflow.action_executions.create.return_value = output
        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
        }

        plan_management.create_plan_from_templates(
            self.app.client_manager,
            'test-overcloud',
            '/tht-root/')

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.plan.create_container',
            {'container': 'test-overcloud'})

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.create_deployment_plan',
            workflow_input={'queue_name': 'UUID4',
                            'container': 'test-overcloud'})

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    def test_create_plan_from_templates_container_error(self, mock_tarball):
        error = mock.Mock(output='{"result": "Error"}')
        self.workflow.action_executions.create.return_value = error

        self.assertRaises(
            exceptions.PlanCreationError,
            plan_management.create_plan_from_templates,
            self.app.client_manager,
            'test-overcloud',
            '/tht-root/')

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.plan.create_container',
            {'container': 'test-overcloud'})

        self.workflow.executions.create.assert_not_called()

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    def test_create_plan_from_templates_roles_data(self, mock_tarball):
        output = mock.Mock(output='{"result": ""}')
        self.workflow.action_executions.create.return_value = output
        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
        }

        mock_open_context = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open_context):
            plan_management.create_plan_from_templates(
                self.app.client_manager,
                'test-overcloud',
                '/tht-root/',
                'the_roles_file.yaml')

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.plan.create_container',
            {'container': 'test-overcloud'})

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.create_deployment_plan',
            workflow_input={'queue_name': 'UUID4',
                            'container': 'test-overcloud'})

        mock_open_context.assert_has_calls(
            [mock.call('the_roles_file.yaml')])

        self.tripleoclient.object_store.put_object.assert_called_once_with(
            'test-overcloud', 'roles_data.yaml', mock_open_context())
