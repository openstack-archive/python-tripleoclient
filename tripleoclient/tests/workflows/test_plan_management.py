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
from swiftclient import exceptions as swift_exc

from tripleoclient import exceptions
from tripleoclient.tests import base
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

        self.message_success = iter([{
            "execution": {"id": "IDID"},
            "status": "SUCCESS",
        }])

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    def test_create_plan_from_templates_success(self, mock_tarball):
        output = mock.Mock(output='{"result": ""}')
        self.workflow.action_executions.create.return_value = output
        self.websocket.wait_for_messages.return_value = self.message_success

        plan_management.create_plan_from_templates(
            self.app.client_manager,
            'test-overcloud',
            '/tht-root/')

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.plan.create_container',
            {'container': 'test-overcloud'},
            run_sync=True, save_result=True)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.create_deployment_plan',
            workflow_input={'queue_name': 'UUID4',
                            'container': 'test-overcloud',
                            'generate_passwords': True})

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
            {'container': 'test-overcloud'},
            run_sync=True, save_result=True)

        self.workflow.executions.create.assert_not_called()

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    def test_create_plan_from_templates_roles_data(self, mock_tarball):
        output = mock.Mock(output='{"result": ""}')
        self.workflow.action_executions.create.return_value = output
        self.websocket.wait_for_messages.return_value = self.message_success

        mock_open_context = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open_context):
            plan_management.create_plan_from_templates(
                self.app.client_manager,
                'test-overcloud',
                '/tht-root/',
                'the_roles_file.yaml')

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.plan.create_container',
            {'container': 'test-overcloud'},
            run_sync=True, save_result=True)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.create_deployment_plan',
            workflow_input={'queue_name': 'UUID4',
                            'container': 'test-overcloud',
                            'generate_passwords': True})

        mock_open_context.assert_has_calls(
            [mock.call('the_roles_file.yaml')])

        self.tripleoclient.object_store.put_object.assert_called_once_with(
            'test-overcloud', 'roles_data.yaml', mock_open_context())

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    def test_create_plan_from_templates_plan_env_data(self, mock_tarball):
        output = mock.Mock(output='{"result": ""}')
        self.workflow.action_executions.create.return_value = output
        self.websocket.wait_for_messages.return_value = self.message_success

        mock_open_context = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open_context):
            plan_management.create_plan_from_templates(
                self.app.client_manager,
                'test-overcloud',
                '/tht-root/',
                plan_env_file='the-plan-environment.yaml')

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.plan.create_container',
            {'container': 'test-overcloud'},
            run_sync=True, save_result=True)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.create_deployment_plan',
            workflow_input={'queue_name': 'UUID4',
                            'container': 'test-overcloud',
                            'generate_passwords': True})

        mock_open_context.assert_has_calls(
            [mock.call('the-plan-environment.yaml')])

        self.tripleoclient.object_store.put_object.assert_called_once_with(
            'test-overcloud', 'plan-environment.yaml', mock_open_context())

    def test_delete_plan(self):
        self.workflow.action_executions.create.return_value = (
            mock.Mock(output='{"result": null}'))

        plan_management.delete_deployment_plan(
            self.workflow,
            container='overcloud')

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.plan.delete',
            {'container': 'overcloud'},
            run_sync=True, save_result=True)

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    def test_create_plan_with_password_gen_disabled(self, mock_tarball):
        output = mock.Mock(output='{"result": ""}')
        self.workflow.action_executions.create.return_value = output
        self.websocket.wait_for_messages.return_value = self.message_success

        plan_management.create_plan_from_templates(
            self.app.client_manager,
            'test-overcloud',
            '/tht-root/',
            generate_passwords=False)

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.plan.create_container',
            {'container': 'test-overcloud'},
            run_sync=True, save_result=True)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.create_deployment_plan',
            workflow_input={'queue_name': 'UUID4',
                            'container': 'test-overcloud',
                            'generate_passwords': False})


class TestUpdatePasswords(base.TestCase):

    YAML_CONTENTS = """version: 1.0
name: overcloud
template: overcloud.yaml
parameter_defaults:
  ControllerCount: 7
"""

    def setUp(self):
        super(TestUpdatePasswords, self).setUp()
        self.swift_client = mock.MagicMock()
        self.swift_client.get_object.return_value = ({}, self.YAML_CONTENTS)

        self.plan_name = "overcast"

    def test_update_passwords(self):
        plan_management._update_passwords(self.swift_client,
                                          self.plan_name,
                                          {'AdminPassword': "1234"})

        self.swift_client.put_object.assert_called_once()
        result = self.swift_client.put_object.call_args_list[0][0][2]

        # Check new data is in
        self.assertIn("passwords:\n", result)
        self.assertIn("\n  AdminPassword: '1234'", result)
        # Check previous data still is too
        self.assertIn("name: overcloud", result)

    def test_no_passwords(self):
        plan_management._update_passwords(self.swift_client,
                                          self.plan_name,
                                          [])

        self.swift_client.put_object.assert_not_called()

    def test_no_plan_environment(self):
        self.swift_client.get_object.side_effect = (
            swift_exc.ClientException("404"))

        plan_management._update_passwords(self.swift_client,
                                          self.plan_name,
                                          {'SecretPassword': 'abcd'})

        self.swift_client.put_object.assert_not_called()
