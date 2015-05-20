#   Copyright 2015 Red Hat, Inc.
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

from rdomanager_oscplugin.tests.v1.overcloud_deploy import fakes
from rdomanager_oscplugin.v1 import overcloud_deploy


class TestDeployOvercloud(fakes.TestDeployOvercloud):

    def setUp(self):
        super(TestDeployOvercloud, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_deploy.DeployOvercloud(self.app, None)

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('os_cloud_config.keystone.initialize', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.remove_known_hosts', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.wait_for_stack_ready',
                autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.set_nodes_state', autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'process_multiple_environments_and_files', autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('os_cloud_config.keystone_pki.generate_certs_into_json',
                autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.create_environment_file',
                autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.get_hiera_key', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.check_hypervisor_stats',
                autospec=True)
    def test_tht_deploy(self, mock_check_hypervisor_stats, mock_get_key,
                        mock_create_env, generate_certs_mock,
                        mock_get_templte_contents, mock_process_multiple_env,
                        set_nodes_state_mock, wait_for_stack_ready_mock,
                        mock_remove_known_hosts, mock_keystone_initialize,
                        mock_sleep):

        arglist = ['--use-tripleo-heat-templates', ]
        verifylist = [
            ('use_tht', True),
        ]

        clients = self.app.client_manager
        orchestration_client = clients.rdomanager_oscplugin.orchestration()
        mock_stack = fakes.create_to_dict_mock(
            outputs=[{
                'output_key': 'KeystoneURL',
                'output_value': 'Overcloud endpoint'
            }]
        )
        orchestration_client.stacks.get.return_value = mock_stack

        mock_check_hypervisor_stats.return_value = {
            'count': 4,
            'memory_mb': 4096,
            'vcpus': 8,
        }
        mock_get_key.return_value = "PASSWORD"
        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_create_env.return_value = "/fake/path"
        mock_process_multiple_env.return_value = [{}, "env"]
        mock_get_templte_contents.return_value = [{}, "template"]
        wait_for_stack_ready_mock.return_value = True

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        args, kwargs = orchestration_client.stacks.update.call_args

        self.assertEqual(args, (orchestration_client.stacks.get().id, ))

        # The parameters output contains lots of output and some in random.
        # So lets just check that it is present
        self.assertTrue('parameters' in kwargs)

        self.assertEqual(kwargs['files'], {})
        self.assertEqual(kwargs['template'], 'template')
        self.assertEqual(kwargs['environment'], 'env')
        self.assertEqual(kwargs['stack_name'], 'overcloud')
