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
        self.orchestration = mock.Mock()
        self.tripleoclient = mock.Mock()
        self.tripleoclient.object_store = mock.MagicMock()
        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient
        self.app.client_manager.orchestration = self.orchestration
        self.app.client_manager.baremetal = mock.Mock()
        self.app.client_manager.compute = mock.Mock()
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        get_container = self.tripleoclient.object_store.get_container \
            = mock.MagicMock()
        get_container.return_value = ('container', [{'name': 'f1'}])

        flatten = mock.patch(
            'tripleo_common.utils.stack_parameters.get_flattened_parameters',
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
    @mock.patch('tripleoclient.utils.run_ansible_playbook', autospec=True)
    @mock.patch('tripleoclient.utils.get_tripleo_ansible_inventory',
                autospec=True)
    def test_invoke_plan_env_workflows_single_playbook(self,
                                                       mock_inventory,
                                                       mock_playbook,
                                                       mock_open,
                                                       mock_safe_load):
        plan_env_data = {
            'name': 'overcloud',
            'playbook_parameters': {
                'sample-playbook-1.yaml': {
                    'num_phy_cores_per_numa_node_for_pmd': 2
                }
            }
        }
        mock_safe_load.return_value = plan_env_data
        parameters.invoke_plan_env_workflows(
            self.app.client_manager,
            'overcloud',
            'the-plan-environment.yaml'
        )
        calls = [
            mock.call(
                playbook='sample-playbook-1.yaml',
                inventory=mock.ANY,
                workdir=mock.ANY,
                playbook_dir=mock.ANY,
                verbosity=0,
                extra_vars={'num_phy_cores_per_numa_node_for_pmd': 2}
            )
        ]
        mock_playbook.assert_has_calls(calls, any_order=True)

    @mock.patch('yaml.safe_load')
    @mock.patch("six.moves.builtins.open")
    @mock.patch('tripleoclient.utils.run_ansible_playbook', autospec=True)
    @mock.patch('tripleoclient.utils.get_tripleo_ansible_inventory',
                autospec=True)
    def test_invoke_plan_env_workflows_multi_playbook(self,
                                                      mock_inventory,
                                                      mock_playbook,
                                                      mock_open,
                                                      mock_safe_load):
        plan_env_data = {
            'name': 'overcloud',
            'playbook_parameters': {
                'sample-playbook-1.yaml': {
                    'num_phy_cores_per_numa_node_for_pmd': 2
                },
                '/playbook/dir-1/sample-playbook-2.yaml': {
                    'some_opt': 0
                }
            }
        }
        mock_safe_load.return_value = plan_env_data
        parameters.invoke_plan_env_workflows(
            self.app.client_manager,
            'overcloud',
            'the-plan-environment.yaml'
        )
        calls = [
            mock.call(
                playbook='sample-playbook-1.yaml',
                inventory=mock.ANY,
                workdir=mock.ANY,
                playbook_dir=mock.ANY,
                verbosity=0,
                extra_vars={'num_phy_cores_per_numa_node_for_pmd': 2}
            ),
            mock.call(
                playbook='sample-playbook-2.yaml',
                inventory=mock.ANY,
                workdir=mock.ANY,
                playbook_dir='/playbook/dir-1',
                verbosity=0,
                extra_vars={'some_opt': 0}
            )
        ]
        mock_playbook.assert_has_calls(calls, any_order=True)

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
        'tripleo_common.utils.stack_parameters.generate_fencing_parameters',
        return_value={})
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
