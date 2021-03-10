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
        self.app.client_manager.baremetal = mock.Mock()

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
            'the-plan-environment.yaml',
            stack_data=mock.Mock(),
            role_list=mock.Mock(),
            derived_environment_path=mock.Mock()
        )
        calls = [
            mock.call(
                playbook='sample-playbook-1.yaml',
                inventory=mock.ANY,
                workdir=mock.ANY,
                playbook_dir=mock.ANY,
                verbosity=0,
                extra_vars_file={
                    'tripleo_get_flatten_params': {
                        'stack_data': mock.ANY},
                    'tripleo_role_list': {'roles': mock.ANY}},
                extra_vars={'num_phy_cores_per_numa_node_for_pmd': 2,
                            'derived_environment_path': mock.ANY}
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
            'the-plan-environment.yaml',
            stack_data=mock.Mock(),
            role_list=mock.Mock(),
            derived_environment_path=mock.Mock()
        )
        calls = [
            mock.call(
                playbook='sample-playbook-1.yaml',
                inventory=mock.ANY,
                workdir=mock.ANY,
                playbook_dir=mock.ANY,
                verbosity=0,
                extra_vars_file={
                    'tripleo_get_flatten_params': {
                        'stack_data': mock.ANY},
                    'tripleo_role_list': {'roles': mock.ANY}},
                extra_vars={'num_phy_cores_per_numa_node_for_pmd': 2,
                            'derived_environment_path': mock.ANY}
            ),
            mock.call(
                playbook='sample-playbook-2.yaml',
                inventory=mock.ANY,
                workdir=mock.ANY,
                playbook_dir='/playbook/dir-1',
                verbosity=0,
                extra_vars_file={
                    'tripleo_get_flatten_params': {
                        'stack_data': mock.ANY},
                    'tripleo_role_list': {'roles': mock.ANY}},
                extra_vars={'some_opt': 0,
                            'derived_environment_path': mock.ANY}
            )
        ]
        mock_playbook.assert_has_calls(calls, any_order=True)

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
            **workflow_input
        )
        self.assertEqual(params, {"parameter_defaults": {}})
