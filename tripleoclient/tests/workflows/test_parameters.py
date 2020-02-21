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
from tripleoclient.workflows import parameters


class TestStringCapture(object):
    def __init__(self):
        self.capture_string = ''

    def write(self, msg):
        self.capture_string = self.capture_string + msg

    def getvalue(self):
        return self.capture_string


class TestParameterWorkflows(utils.TestCommand):

    def setUp(self):
        super(TestParameterWorkflows, self).setUp()
        self.app.client_manager.workflow_engine = self.workflow = mock.Mock()
        self.tripleoclient = mock.Mock()
        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        get_container = self.tripleoclient.object_store.get_container \
            = mock.MagicMock()
        get_container.return_value = ('container', [{'name': 'f1'}])
        roles = mock.patch(
            'tripleoclient.workflows.roles.list_available_roles',
            autospec=True,
            return_value=[
                {
                    'TestRole1': {
                        'TestParameter1': {}
                    }
                }
            ]
        )
        roles.start()
        self.addCleanup(roles.stop)
        flatten = mock.patch(
            'tripleo_common.actions.parameters.GetFlattenedParametersAction'
            '.run',
            autospec=True,
            return_value={
                'environment_parameters': {
                    'TestParameter1': {},
                    'TestRole1': 'TestParameter2'
                },
                'heat_resource_tree': {
                    'parameters': {
                        'TestParameter2': {
                            'name': 'TestParameter2',
                            'tags': [
                                'role_specific'
                            ]
                        }
                    },
                    'resources': {}
                }
            }
        )
        flatten.start()
        self.addCleanup(flatten.stop)

    @mock.patch('yaml.safe_load')
    @mock.patch("six.moves.builtins.open")
    def test_invoke_plan_env_workflows(self, mock_open,
                                       mock_safe_load):
        plan_env_data = {
            'name': 'overcloud',
            'workflow_parameters': {
                'tripleo.derive_params.v1.derive_parameters': {
                    'num_phy_cores_per_numa_node_for_pmd': 2
                }
            }
        }
        mock_safe_load.return_value = plan_env_data

        self.websocket.wait_for_messages.return_value = iter([{
            "execution_id": "IDID",
            "status": "SUCCESS",
            "message": "",
            "result": {}
        }])

        parameters.invoke_plan_env_workflows(
            self.app.client_manager,
            'overcloud',
            'the-plan-environment.yaml')

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.derive_params.v1.derive_parameters',
            workflow_input={
                'plan': 'overcloud',
                'user_inputs': {
                    'num_phy_cores_per_numa_node_for_pmd': 2}})

    @mock.patch('yaml.safe_load')
    @mock.patch("six.moves.builtins.open")
    def test_invoke_plan_env_workflow_failed(self, mock_open,
                                             mock_safe_load):
        plan_env_data = {
            'name': 'overcloud',
            'workflow_parameters': {
                'tripleo.derive_params.v1.derive_parameters': {
                    'num_phy_cores_per_numa_node_for_pmd': 2
                }
            }
        }
        mock_safe_load.return_value = plan_env_data

        self.websocket.wait_for_messages.return_value = iter([{
            "execution_id": "IDID",
            "status": "FAILED",
            "message": "workflow failure",
            "result": ""
        }])

        self.assertRaises(exceptions.PlanEnvWorkflowError,
                          parameters.invoke_plan_env_workflows,
                          self.app.client_manager, 'overcloud',
                          'the-plan-environment.yaml')

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.derive_params.v1.derive_parameters',
            workflow_input={
                'plan': 'overcloud',
                'user_inputs': {
                    'num_phy_cores_per_numa_node_for_pmd': 2}})

    @mock.patch('yaml.safe_load')
    @mock.patch("six.moves.builtins.open")
    def test_invoke_plan_env_workflows_no_workflow_params(
            self, mock_open, mock_safe_load):
        plan_env_data = {'name': 'overcloud'}
        mock_safe_load.return_value = plan_env_data

        parameters.invoke_plan_env_workflows(
            self.app.client_manager,
            'overcloud',
            'the-plan-environment.yaml')

        self.workflow.executions.create.assert_not_called()

    @mock.patch('yaml.safe_load')
    @mock.patch("six.moves.builtins.open")
    def test_invoke_plan_env_workflows_no_plan_env_file(
            self, mock_open, mock_safe_load):

        mock_open.side_effect = IOError('')

        self.assertRaises(exceptions.PlanEnvWorkflowError,
                          parameters.invoke_plan_env_workflows,
                          self.app.client_manager, 'overcloud',
                          'the-plan-environment.yaml')

        self.workflow.executions.create.assert_not_called()

    def test_check_deprecated_params_no_output(self):
        parameters.check_deprecated_parameters(
            self.app.client_manager,
            container='container-name')

    def test_check_deprecated_params_user_defined(self):
        with mock.patch('tripleoclient.workflows.parameters.LOG') as mock_log:
            parameters.check_deprecated_parameters(
                self.app.client_manager,
                container='container-name')
            self.assertTrue(mock_log.warning.called)

    def test_check_deprecated_params_user_not_defined(self):
        with mock.patch('tripleoclient.workflows.parameters.LOG') as mock_log:
            parameters.check_deprecated_parameters(
                self.app.client_manager,
                container='container-name')
            self.assertFalse(mock_log.log.warning.called)

    def test_check_deprecated_multiple_parameters(self):
        with mock.patch('tripleoclient.workflows.parameters.LOG') as mock_log:
            parameters.check_deprecated_parameters(
                self.app.client_manager,
                container='container-name')
            self.assertTrue(mock_log.warning.called)

    def test_check_unused_multiple_parameters(self):
        with mock.patch('tripleoclient.workflows.parameters.LOG') as mock_log:
            parameters.check_deprecated_parameters(
                self.app.client_manager,
                container='container-name')
            self.assertTrue(mock_log.warning.called)

    def test_check_invalid_role_specific_parameters(self):
        with mock.patch('tripleoclient.workflows.parameters.LOG') as mock_log:
            parameters.check_deprecated_parameters(
                self.app.client_manager,
                container='container-name')
            self.assertTrue(mock_log.warning.called)

    @mock.patch(
        'tripleo_common.actions.parameters.GenerateFencingParametersAction'
        '.run',
        autospec=True
    )
    def test_generate_fencing_parameters(self, mock_params):
        mock_params.return_value = {"parameter_defaults": {}}

        workflow_input = {
            'nodes_json': [],
            'delay': 0,
            'ipmi_level': 'test',
            'ipmi_cipher': 'test',
            'ipmi_lanplus': True
        }
        params = parameters.generate_fencing_parameters(
            self.app.client_manager,
            **workflow_input
        )
        self.assertEqual(params, {"parameter_defaults": {}})
