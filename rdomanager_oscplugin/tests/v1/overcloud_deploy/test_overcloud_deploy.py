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

import sys

import mock

from tuskarclient.v2.plans import Plan

from openstackclient.tests import utils as oscutils
from rdomanager_oscplugin.tests.v1.overcloud_deploy import fakes
from rdomanager_oscplugin.tests.v1.utils import (
    generate_overcloud_passwords_mock)
from rdomanager_oscplugin.v1 import overcloud_deploy


class TestDeployOvercloud(fakes.TestDeployOvercloud):

    def setUp(self):
        super(TestDeployOvercloud, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_deploy.DeployOvercloud(self.app, None)

        self._get_passwords = generate_overcloud_passwords_mock

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_update_nodesjson')
    @mock.patch('rdomanager_oscplugin.utils.generate_overcloud_passwords')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_create_overcloudrc')
    @mock.patch('os_cloud_config.keystone.setup_endpoints', autospec=True)
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
    @mock.patch('rdomanager_oscplugin.utils.get_config_value', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.check_hypervisor_stats',
                autospec=True)
    def test_tht_deploy(self, mock_check_hypervisor_stats, mock_get_key,
                        mock_create_env, generate_certs_mock,
                        mock_get_templte_contents, mock_process_multiple_env,
                        set_nodes_state_mock, wait_for_stack_ready_mock,
                        mock_remove_known_hosts, mock_keystone_initialize,
                        mock_sleep, mock_setup_endpoints,
                        mock_create_overcloudrc,
                        mock_generate_overcloud_passwords,
                        mock_update_nodesjson,
                        mock_deploy_postconfig):

        arglist = ['--use-tripleo-heat-templates', ]
        verifylist = [
            ('use_tht', True),
        ]

        mock_generate_overcloud_passwords.return_value = self._get_passwords()

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

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_update_nodesjson')
    @mock.patch('rdomanager_oscplugin.utils.get_config_value', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.generate_overcloud_passwords')
    @mock.patch('heatclient.common.template_utils.'
                'process_multiple_environments_and_files')
    @mock.patch('heatclient.common.template_utils.get_template_contents')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_get_stack')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_pre_heat_deploy')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_create_overcloudrc')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy')
    def test_tuskar_deploy(self, mock_heat_deploy, mock_create_overcloudrc,
                           most_pre_deploy, mock_get_stack,
                           mock_get_templte_contents,
                           mock_process_multiple_env,
                           mock_generate_overcloud_passwords,
                           mock_get_key, mock_update_nodesjson,
                           mock_deploy_postconfig):

        arglist = ['--plan', 'undercloud', '--output-dir', 'fake',
                   '--compute-flavor', 'baremetal',
                   '--neutron-bridge-mappings', 'datacentre:br-test',
                   '--neutron-disable-tunneling',
                   '--control-scale', '3']

        verifylist = [
            ('use_tht', False),
            ('plan', 'undercloud'),
            ('output_dir', 'fake'),
        ]

        clients = self.app.client_manager
        management = clients.rdomanager_oscplugin.management()

        management.plans.templates.return_value = {}
        management.plans.resource_class = Plan

        mock_plan = mock.Mock()
        mock_plan.configure_mock(name="undercloud")
        management.plans.list.return_value = [mock_plan, ]

        mock_get_templte_contents.return_value = ({}, "template")
        mock_process_multiple_env.return_value = ({}, "envs")
        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }

        mock_get_key.return_value = "PASSWORD"

        mock_generate_overcloud_passwords.return_value = self._get_passwords()

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        parameters = {
            'Controller-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Compute-1::NeutronPassword': 'password',
            'Controller-1::NeutronPassword': 'password',
            'Cinder-Storage-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Compute-1::CeilometerMeteringSecret': 'password',
            'NeutronControlPlaneID': 'network id',
            'Compute-1::NeutronBridgeMappings': 'datacentre:br-test',
            'Controller-1::AdminPassword': 'password',
            'Compute-1::Flavor': 'baremetal',
            'Compute-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Controller-1::NeutronEnableTunnelling': False,
            'Compute-1::NeutronEnableTunnelling': False,
            'Controller-1::count': 3,
            'Compute-1::CeilometerPassword': 'password',
            'Controller-1::CinderPassword': 'password',
            'Controller-1::CeilometerPassword': 'password',
            'Compute-1::AdminPassword': 'password',
            'Controller-1::HeatPassword': 'password',
            'Controller-1::HeatStackDomainAdminPassword': 'password',
            'Controller-1::CeilometerMeteringSecret': 'password',
            'Controller-1::SwiftPassword': 'password',
            'Controller-1::NeutronBridgeMappings': 'datacentre:br-test',
            'Controller-1::NovaPassword': 'password',
            'Controller-1::SwiftHashSuffix': 'password',
            'Compute-1::NovaPassword': 'password',
            'Controller-1::GlancePassword': 'password',
            'Swift-Storage-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Controller-1::AdminToken': 'password',
            'Controller-1::NeutronL3HA': True,
            'Controller-1::NeutronAllowL3AgentFailover': False,
            'Compute-1::NeutronL3HA': True,
            'Compute-1::NeutronAllowL3AgentFailover': False,
        }

        mock_heat_deploy.assert_called_with(
            mock_get_stack(),
            'fake/plan.yaml',
            parameters,
            ['fake/environment.yaml']
        )

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_update_nodesjson')
    @mock.patch('rdomanager_oscplugin.utils.get_config_value', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.generate_overcloud_passwords')
    @mock.patch('heatclient.common.template_utils.'
                'process_multiple_environments_and_files')
    @mock.patch('heatclient.common.template_utils.get_template_contents')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_get_stack')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_pre_heat_deploy')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_create_overcloudrc')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy')
    def test_tuskar_deploy_extra_config(self, mock_heat_deploy,
                                        mock_create_overcloudrc,
                                        most_pre_deploy, mock_get_stack,
                                        mock_get_templte_contents,
                                        mock_process_multiple_env,
                                        mock_generate_overcloud_passwords,
                                        mock_get_key, mock_update_nodesjson,
                                        mock_deploy_postconfig):

        arglist = ['--plan', 'undercloud', '--output-dir', 'fake',
                   '--compute-flavor', 'baremetal',
                   '--neutron-bridge-mappings', 'datacentre:br-test',
                   '--neutron-disable-tunneling',
                   '--control-scale', '3',
                   '-e', 'extra_registry.yaml',
                   '-e', 'extra_environment.yaml']

        verifylist = [
            ('use_tht', False),
            ('plan', 'undercloud'),
            ('output_dir', 'fake'),
            ('extra_templates', ['extra_registry.yaml',
                                 'extra_environment.yaml'])
        ]

        clients = self.app.client_manager
        management = clients.rdomanager_oscplugin.management()

        management.plans.templates.return_value = {}
        management.plans.resource_class = Plan

        mock_plan = mock.Mock()
        mock_plan.configure_mock(name="undercloud")
        management.plans.list.return_value = [mock_plan, ]

        mock_get_templte_contents.return_value = ({}, "template")
        mock_process_multiple_env.return_value = ({}, "envs")
        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }

        mock_get_key.return_value = "PASSWORD"

        mock_generate_overcloud_passwords.return_value = self._get_passwords()

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        parameters = {
            'Controller-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Compute-1::NeutronPassword': 'password',
            'Controller-1::NeutronPassword': 'password',
            'Cinder-Storage-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Compute-1::CeilometerMeteringSecret': 'password',
            'NeutronControlPlaneID': 'network id',
            'Compute-1::NeutronBridgeMappings': 'datacentre:br-test',
            'Controller-1::AdminPassword': 'password',
            'Compute-1::Flavor': 'baremetal',
            'Compute-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Controller-1::NeutronEnableTunnelling': False,
            'Compute-1::NeutronEnableTunnelling': False,
            'Controller-1::count': 3,
            'Compute-1::CeilometerPassword': 'password',
            'Controller-1::CinderPassword': 'password',
            'Controller-1::CeilometerPassword': 'password',
            'Compute-1::AdminPassword': 'password',
            'Controller-1::HeatPassword': 'password',
            'Controller-1::HeatStackDomainAdminPassword': 'password',
            'Controller-1::CeilometerMeteringSecret': 'password',
            'Controller-1::SwiftPassword': 'password',
            'Controller-1::NeutronBridgeMappings': 'datacentre:br-test',
            'Controller-1::NovaPassword': 'password',
            'Controller-1::SwiftHashSuffix': 'password',
            'Compute-1::NovaPassword': 'password',
            'Controller-1::GlancePassword': 'password',
            'Swift-Storage-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Controller-1::AdminToken': 'password',
            'Controller-1::NeutronL3HA': True,
            'Controller-1::NeutronAllowL3AgentFailover': False,
            'Compute-1::NeutronL3HA': True,
            'Compute-1::NeutronAllowL3AgentFailover': False,
        }

        mock_heat_deploy.assert_called_with(
            mock_get_stack(),
            'fake/plan.yaml',
            parameters,
            ['fake/environment.yaml',
             'extra_registry.yaml',
             'extra_environment.yaml']
        )

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tuskar', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_pre_heat_deploy', autospec=True)
    def test_invalid_deploy_call(self, mock_pre_deploy, mock_deploy_tht,
                                 mock_deploy_tuskar):

        arglist = ['--plan', 'undercloud', '--use-tripleo-heat-templates']
        verifylist = [
            ('use_tht', True),
            ('plan', 'undercloud'),
        ]

        try:
            oldstderr = sys.stderr
            sys.stderr = self.fake_stdout
            self.assertRaises(oscutils.ParserException, self.check_parser,
                              self.cmd, arglist, verifylist)
        finally:
            sys.stderr = oldstderr

        self.assertFalse(mock_deploy_tht.called)
        self.assertFalse(mock_deploy_tuskar.called)
