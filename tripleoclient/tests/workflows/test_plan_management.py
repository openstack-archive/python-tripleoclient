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
            workflow_input={'container': 'test-overcloud',
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
            workflow_input={'container': 'test-overcloud',
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
            workflow_input={'container': 'test-overcloud',
                            'generate_passwords': True})

        mock_open_context.assert_has_calls(
            [mock.call('the-plan-environment.yaml')])

        self.tripleoclient.object_store.put_object.assert_called_once_with(
            'test-overcloud', 'plan-environment.yaml', mock_open_context())

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    def test_create_plan_from_templates_networks_data(self, mock_tarball):
        output = mock.Mock(output='{"result": ""}')
        self.workflow.action_executions.create.return_value = output
        self.websocket.wait_for_messages.return_value = self.message_success

        mock_open_context = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open_context):
            plan_management.create_plan_from_templates(
                self.app.client_manager,
                'test-overcloud',
                '/tht-root/',
                networks_file='the-network-data.yaml')

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.plan.create_container',
            {'container': 'test-overcloud'},
            run_sync=True, save_result=True)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.create_deployment_plan',
            workflow_input={'container': 'test-overcloud',
                            'generate_passwords': True})

        mock_open_context.assert_has_calls(
            [mock.call('the-network-data.yaml')])

        self.tripleoclient.object_store.put_object.assert_called_once_with(
            'test-overcloud', 'network_data.yaml', mock_open_context())

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
            workflow_input={'container': 'test-overcloud',
                            'generate_passwords': False})


class TestPlanUpdateWorkflows(base.TestCommand):

    def setUp(self):
        super(TestPlanUpdateWorkflows, self).setUp()
        self.app.client_manager.workflow_engine = self.workflow = mock.Mock()
        self.app.client_manager.tripleoclient = self.tripleoclient = \
            mock.Mock()
        self.tripleoclient.object_store = self.object_store = mock.Mock()

        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.workflow.action_executions.create.return_value = mock.Mock(
            output='{"result": ""}')
        self.message_success = iter([{
            "execution": {"id": "IDID"},
            "status": "SUCCESS",
        }])
        self.websocket.wait_for_messages.return_value = self.message_success

        self.object_store.get_container.return_value = (
            {},
            [
                {'name': 'plan-environment.yaml'},
                {'name': 'user-environment.yaml'},
                {'name': 'roles_data.yaml'},
                {'name': 'network_data.yaml'},
                {'name': 'user-files/somecustomfile.yaml'},
                {'name': 'user-files/othercustomfile.yaml'},
                {'name': 'this-should-not-be-persisted.yaml'},
            ]
        )

        def get_object(*args, **kwargs):
            if args[0] != 'test-overcloud':
                raise RuntimeError('Unexpected container')
            if args[1] == 'plan-environment.yaml':
                return {}, ('passwords: somepasswords\n'
                            'plan-environment.yaml: mock content\n')
            # Generic return valuebased on param,
            # e.g. 'plan-environment.yaml: mock content'
            return {}, '{0}: mock content\n'.format(args[1])
        self.object_store.get_object.side_effect = get_object

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleo_common.utils.swift.empty_container',
                autospec=True)
    def test_update_plan_from_templates_keep_env(
            self, mock_empty_container, mock_tarball):

        plan_management.update_plan_from_templates(
            self.app.client_manager,
            'test-overcloud',
            '/tht-root/',
            keep_env=True)

        mock_empty_container.assert_called_once_with(
            self.object_store, 'test-overcloud')

        # make sure we're pushing the saved files back to plan
        self.object_store.put_object.assert_has_calls(
            [
                mock.call('test-overcloud', 'plan-environment.yaml',
                          'passwords: somepasswords\n'
                          'plan-environment.yaml: mock content\n'),
                mock.call('test-overcloud', 'user-environment.yaml',
                          'user-environment.yaml: mock content\n'),
                mock.call('test-overcloud', 'roles_data.yaml',
                          'roles_data.yaml: mock content\n'),
                mock.call('test-overcloud', 'network_data.yaml',
                          'network_data.yaml: mock content\n'),
                mock.call('test-overcloud', 'user-files/somecustomfile.yaml',
                          'user-files/somecustomfile.yaml: mock content\n'),
                mock.call('test-overcloud', 'user-files/othercustomfile.yaml',
                          'user-files/othercustomfile.yaml: mock content\n'),
            ],
            any_order=True,
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.update_deployment_plan',
            workflow_input={'container': 'test-overcloud',
                            'generate_passwords': True, 'source_url': None})

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleo_common.utils.swift.empty_container',
                autospec=True)
    def test_update_plan_from_templates_recreate_env(
            self, mock_empty_container, mock_tarball):

        plan_management.update_plan_from_templates(
            self.app.client_manager,
            'test-overcloud',
            '/tht-root/')

        mock_empty_container.assert_called_once_with(
            self.object_store, 'test-overcloud')

        # make sure passwords got persisted
        self.object_store.put_object.assert_called_with(
            'test-overcloud', 'plan-environment.yaml',
            'passwords: somepasswords\n'
            'plan-environment.yaml: mock content\n'
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.update_deployment_plan',
            workflow_input={'container': 'test-overcloud',
                            'generate_passwords': True, 'source_url': None})


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
