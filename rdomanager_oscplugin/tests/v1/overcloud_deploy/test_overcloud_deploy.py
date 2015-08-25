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
import six

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
                '_create_tempest_deployer_input', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.generate_overcloud_passwords')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_create_overcloudrc')
    @mock.patch('os_cloud_config.keystone.setup_endpoints', autospec=True)
    @mock.patch('time.sleep', return_value=None)
    @mock.patch('os_cloud_config.keystone.initialize', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.remove_known_hosts', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.wait_for_stack_ready',
                autospec=True)
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
    @mock.patch('rdomanager_oscplugin.utils.create_cephx_key',
                autospec=True)
    @mock.patch('uuid.uuid1', autospec=True)
    def test_tht_scale(self, mock_uuid1, mock_create_cephx_key,
                       mock_check_hypervisor_stats, mock_get_key,
                       mock_create_env, generate_certs_mock,
                       mock_get_templte_contents, mock_process_multiple_env,
                       wait_for_stack_ready_mock,
                       mock_remove_known_hosts, mock_keystone_initialize,
                       mock_sleep, mock_setup_endpoints,
                       mock_create_overcloudrc,
                       mock_generate_overcloud_passwords,
                       mock_create_tempest_deployer_input,
                       mock_deploy_postconfig):

        arglist = ['--templates', '--ceph-storage-scale', '3']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]

        mock_create_cephx_key.return_value = "cephx_key"
        mock_uuid1.return_value = "uuid"

        mock_generate_overcloud_passwords.return_value = self._get_passwords()

        clients = self.app.client_manager
        orchestration_client = clients.rdomanager_oscplugin.orchestration()
        mock_stack = fakes.create_to_dict_mock(
            outputs=[{
                'output_key': 'KeystoneURL',
                'output_value': 'Overcloud endpoint'
            }],
            stack_name='overcloud',
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

        expected_parameters = {
            'AdminPassword': 'password',
            'AdminToken': 'password',
            'BlockStorageImage': 'overcloud-full',
            'CeilometerMeteringSecret': 'password',
            'CeilometerPassword': 'password',
            'CephStorageCount': 3,
            'CephStorageImage': 'overcloud-full',
            'CinderISCSIHelper': 'lioadm',
            'CinderPassword': 'password',
            'CloudName': 'overcloud',
            'controllerImage': 'overcloud-full',
            'Debug': 'True',
            'ExtraConfig': '{}',
            'GlancePassword': 'password',
            'HeatPassword': 'password',
            'HeatStackDomainAdminPassword': 'password',
            'HypervisorNeutronPhysicalBridge': 'br-ex',
            'HypervisorNeutronPublicInterface': 'nic1',
            'NeutronAllowL3AgentFailover': False,
            'NeutronBridgeMappings': 'datacentre:br-ex',
            'NeutronControlPlaneID': 'network id',
            'NeutronDhcpAgentsPerNetwork': 3,
            'NeutronDnsmasqOptions': 'dhcp-option-force=26,1400',
            'NeutronFlatNetworks': 'datacentre',
            'NeutronL3HA': False,
            'NeutronNetworkVLANRanges': 'datacentre:1:1000',
            'NeutronPassword': 'password',
            'NeutronPublicInterface': 'nic1',
            'NovaImage': 'overcloud-full',
            'NovaPassword': 'password',
            'NtpServer': '',
            'OvercloudBlockStorageFlavor': 'baremetal',
            'OvercloudCephStorageFlavor': 'baremetal',
            'OvercloudComputeFlavor': 'baremetal',
            'OvercloudControlFlavor': 'baremetal',
            'OvercloudSwiftStorageFlavor': 'baremetal',
            'SnmpdReadonlyUserPassword': 'PASSWORD',
            'SwiftHashSuffix': 'password',
            'SwiftPassword': 'password',
            'SwiftStorageImage': 'overcloud-full',
        }
        self.assertEqual(set(kwargs['parameters'].keys())
                         ^ set(expected_parameters.keys()), set())
        self.assertEqual(kwargs['parameters'], expected_parameters)

        self.assertEqual(kwargs['files'], {})
        self.assertEqual(kwargs['template'], 'template')
        self.assertEqual(kwargs['environment'], 'env')
        self.assertEqual(kwargs['stack_name'], 'overcloud')

        mock_get_templte_contents.assert_called_with(
            ('/usr/share/openstack-tripleo-heat-templates/overcloud-without-'
             'mergepy.yaml'))

        mock_create_tempest_deployer_input.assert_called_with(self.cmd)

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_create_tempest_deployer_input', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.generate_overcloud_passwords')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_create_overcloudrc')
    @mock.patch('os_cloud_config.keystone.setup_endpoints', autospec=True)
    @mock.patch('time.sleep', return_value=None)
    @mock.patch('os_cloud_config.keystone.initialize', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.remove_known_hosts', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.wait_for_stack_ready',
                autospec=True)
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
    @mock.patch('rdomanager_oscplugin.utils.create_cephx_key',
                autospec=True)
    @mock.patch('uuid.uuid1', autospec=True)
    def test_tht_deploy(self, mock_uuid1, mock_create_cephx_key,
                        mock_check_hypervisor_stats, mock_get_key,
                        mock_create_env, generate_certs_mock,
                        mock_get_templte_contents, mock_process_multiple_env,
                        wait_for_stack_ready_mock,
                        mock_remove_known_hosts, mock_keystone_initialize,
                        mock_sleep, mock_setup_endpoints,
                        mock_create_overcloudrc,
                        mock_generate_overcloud_passwords,
                        mock_create_tempest_deployer_input,
                        mock_deploy_postconfig):

        arglist = ['--templates', '--ceph-storage-scale', '3']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]

        mock_create_cephx_key.return_value = "cephx_key"
        mock_uuid1.return_value = "uuid"

        mock_generate_overcloud_passwords.return_value = self._get_passwords()

        clients = self.app.client_manager
        orchestration_client = clients.rdomanager_oscplugin.orchestration()
        mock_stack = fakes.create_to_dict_mock(
            outputs=[{
                'output_key': 'KeystoneURL',
                'output_value': 'Overcloud endpoint'
            }],
            stack_name='overcloud',
        )
        orchestration_client.stacks.get.return_value = None

        def _orch_clt_create(**kwargs):
            orchestration_client.stacks.get.return_value = mock_stack

        orchestration_client.stacks.create.side_effect = _orch_clt_create

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

        args, kwargs = orchestration_client.stacks.create.call_args

        expected_parameters = {
            'AdminPassword': 'password',
            'AdminToken': 'password',
            'BlockStorageImage': 'overcloud-full',
            'CeilometerMeteringSecret': 'password',
            'CeilometerPassword': 'password',
            'CephAdminKey': 'cephx_key',
            'CephClusterFSID': 'uuid',
            'CephMonKey': 'cephx_key',
            'CephStorageCount': 3,
            'CephStorageImage': 'overcloud-full',
            'CinderISCSIHelper': 'lioadm',
            'CinderPassword': 'password',
            'CloudName': 'overcloud',
            'controllerImage': 'overcloud-full',
            'Debug': 'True',
            'ExtraConfig': '{}',
            'GlancePassword': 'password',
            'HeatPassword': 'password',
            'HeatStackDomainAdminPassword': 'password',
            'HypervisorNeutronPhysicalBridge': 'br-ex',
            'HypervisorNeutronPublicInterface': 'nic1',
            'NeutronAllowL3AgentFailover': False,
            'NeutronBridgeMappings': 'datacentre:br-ex',
            'NeutronControlPlaneID': 'network id',
            'NeutronDhcpAgentsPerNetwork': 3,
            'NeutronDnsmasqOptions': 'dhcp-option-force=26,1400',
            'NeutronEnableTunnelling': 'True',
            'NeutronFlatNetworks': 'datacentre',
            'NeutronL3HA': False,
            'NeutronNetworkType': 'gre',
            'NeutronNetworkVLANRanges': 'datacentre:1:1000',
            'NeutronPassword': 'password',
            'NeutronPublicInterface': 'nic1',
            'NeutronTunnelIdRanges': '1:1000',
            'NeutronTunnelTypes': 'gre',
            'NeutronVniRanges': '1:1000',
            'NovaComputeLibvirtType': 'kvm',
            'NovaImage': 'overcloud-full',
            'NovaPassword': 'password',
            'NtpServer': '',
            'OvercloudBlockStorageFlavor': 'baremetal',
            'OvercloudCephStorageFlavor': 'baremetal',
            'OvercloudComputeFlavor': 'baremetal',
            'OvercloudControlFlavor': 'baremetal',
            'OvercloudSwiftStorageFlavor': 'baremetal',
            'SnmpdReadonlyUserPassword': 'PASSWORD',
            'SwiftHashSuffix': 'password',
            'SwiftPassword': 'password',
            'SwiftStorageImage': 'overcloud-full',
        }

        self.assertEqual(set(kwargs['parameters'].keys())
                         ^ set(expected_parameters.keys()), set())
        self.assertEqual(kwargs['parameters'], expected_parameters)

        self.assertEqual(kwargs['files'], {})
        self.assertEqual(kwargs['template'], 'template')
        self.assertEqual(kwargs['environment'], 'env')
        self.assertEqual(kwargs['stack_name'], 'overcloud')

        mock_get_templte_contents.assert_called_with(
            ('/usr/share/openstack-tripleo-heat-templates/overcloud-without-'
             'mergepy.yaml'))

        mock_create_tempest_deployer_input.assert_called_with(self.cmd)

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_create_tempest_deployer_input', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.generate_overcloud_passwords')
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_create_overcloudrc')
    @mock.patch('os_cloud_config.keystone.setup_endpoints', autospec=True)
    @mock.patch('time.sleep', return_value=None)
    @mock.patch('os_cloud_config.keystone.initialize', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.remove_known_hosts', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.wait_for_stack_ready',
                autospec=True)
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
    def test_deploy_custom_templates(self, mock_check_hypervisor_stats,
                                     mock_get_key,
                                     mock_create_env, generate_certs_mock,
                                     mock_get_templte_contents,
                                     mock_process_multiple_env,
                                     wait_for_stack_ready_mock,
                                     mock_remove_known_hosts,
                                     mock_keystone_initialize,
                                     mock_sleep, mock_setup_endpoints,
                                     mock_create_overcloudrc,
                                     mock_generate_overcloud_passwords,
                                     mock_create_tempest_deployer_input,
                                     mock_deploy_postconfig):

        arglist = ['--templates', '/home/stack/tripleo-heat-templates']
        verifylist = [
            ('templates', '/home/stack/tripleo-heat-templates'),
        ]

        mock_generate_overcloud_passwords.return_value = self._get_passwords()

        clients = self.app.client_manager
        orchestration_client = clients.rdomanager_oscplugin.orchestration()
        mock_stack = fakes.create_to_dict_mock(
            outputs=[{
                'output_key': 'KeystoneURL',
                'output_value': 'Overcloud endpoint'
            }],
            stack_name='overcloud',
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

        # The parameters output contains lots of output and some is random.
        # So lets just check that it is present
        self.assertTrue('parameters' in kwargs)

        self.assertEqual(kwargs['files'], {})
        self.assertEqual(kwargs['template'], 'template')
        self.assertEqual(kwargs['environment'], 'env')
        self.assertEqual(kwargs['stack_name'], 'overcloud')

        mock_get_templte_contents.assert_called_with(
            '/home/stack/tripleo-heat-templates/overcloud-without-mergepy.yaml'
        )

        mock_create_tempest_deployer_input.assert_called_with(self.cmd)

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig')
    @mock.patch('rdomanager_oscplugin.utils.get_config_value', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_create_tempest_deployer_input', autospec=True)
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
                           mock_create_tempest_deployer_input,
                           mock_get_key,
                           mock_deploy_postconfig):

        arglist = ['--plan', 'undercloud', '--output-dir', 'fake',
                   '--compute-flavor', 'baremetal',
                   '--neutron-bridge-mappings', 'datacentre:br-test',
                   '--neutron-disable-tunneling',
                   '--control-scale', '3',
                   '--neutron-mechanism-drivers', 'linuxbridge',
                   '--ntp-server', 'ntp.local']

        verifylist = [
            ('templates', None),
            ('plan', 'undercloud'),
            ('output_dir', 'fake'),
            ('ntp_server', 'ntp.local')
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
            'Cinder-Storage-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Compute-1::AdminPassword': 'password',
            'Compute-1::CeilometerMeteringSecret': 'password',
            'Compute-1::CeilometerPassword': 'password',
            'Compute-1::Flavor': 'baremetal',
            'Compute-1::NeutronAllowL3AgentFailover': False,
            'Compute-1::NeutronBridgeMappings': 'datacentre:br-test',
            'Compute-1::NeutronL3HA': True,
            'Compute-1::NeutronMechanismDrivers': 'linuxbridge',
            'Compute-1::NeutronPassword': 'password',
            'Compute-1::NovaPassword': 'password',
            'Compute-1::NtpServer': 'ntp.local',
            'Compute-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Controller-1::AdminPassword': 'password',
            'Controller-1::AdminToken': 'password',
            'Controller-1::CeilometerMeteringSecret': 'password',
            'Controller-1::CeilometerPassword': 'password',
            'Controller-1::CinderPassword': 'password',
            'Controller-1::count': 3,
            'Controller-1::GlancePassword': 'password',
            'Controller-1::HeatPassword': 'password',
            'Controller-1::HeatStackDomainAdminPassword': 'password',
            'Controller-1::NeutronAllowL3AgentFailover': False,
            'Controller-1::NeutronBridgeMappings': 'datacentre:br-test',
            'Controller-1::NeutronDhcpAgentsPerNetwork': 3,
            'Controller-1::NeutronL3HA': True,
            'Controller-1::NeutronMechanismDrivers': 'linuxbridge',
            'Controller-1::NeutronPassword': 'password',
            'Controller-1::NovaPassword': 'password',
            'Controller-1::NtpServer': 'ntp.local',
            'Controller-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Controller-1::SwiftHashSuffix': 'password',
            'Controller-1::SwiftPassword': 'password',
            'NeutronControlPlaneID': 'network id',
            'Swift-Storage-1::SnmpdReadonlyUserPassword': "PASSWORD",
        }

        mock_heat_deploy.assert_called_with(
            mock_get_stack(),
            'overcloud',
            'fake/plan.yaml',
            parameters,
            ['fake/environment.yaml'],
            240
        )

        mock_create_tempest_deployer_input.assert_called_with(self.cmd)

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig')
    @mock.patch('rdomanager_oscplugin.utils.get_config_value', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_create_tempest_deployer_input', autospec=True)
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
    def test_tuskar_scale(self, mock_heat_deploy, mock_create_overcloudrc,
                          most_pre_deploy, mock_get_stack,
                          mock_get_templte_contents,
                          mock_process_multiple_env,
                          mock_generate_overcloud_passwords,
                          mock_create_tempest_deployer_input,
                          mock_get_key,
                          mock_deploy_postconfig):

        arglist = ['--plan', 'undercloud', '--output-dir', 'fake',
                   '--compute-flavor', 'baremetal',
                   '--neutron-bridge-mappings', 'datacentre:br-test',
                   '--neutron-disable-tunneling',
                   '--control-scale', '3',
                   '--ntp-server', 'ntp.local',
                   '--neutron-mechanism-drivers', 'linuxbridge']

        verifylist = [
            ('templates', None),
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
            'Cinder-Storage-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Compute-1::AdminPassword': 'password',
            'Compute-1::CeilometerMeteringSecret': 'password',
            'Compute-1::CeilometerPassword': 'password',
            'Compute-1::Flavor': 'baremetal',
            'Compute-1::NeutronAllowL3AgentFailover': False,
            'Compute-1::NeutronBridgeMappings': 'datacentre:br-test',
            'Compute-1::NeutronL3HA': True,
            'Compute-1::NeutronMechanismDrivers': 'linuxbridge',
            'Compute-1::NeutronPassword': 'password',
            'Compute-1::NovaPassword': 'password',
            'Compute-1::NtpServer': 'ntp.local',
            'Compute-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Controller-1::AdminPassword': 'password',
            'Controller-1::AdminToken': 'password',
            'Controller-1::CeilometerMeteringSecret': 'password',
            'Controller-1::CeilometerPassword': 'password',
            'Controller-1::CinderPassword': 'password',
            'Controller-1::count': 3,
            'Controller-1::GlancePassword': 'password',
            'Controller-1::HeatPassword': 'password',
            'Controller-1::HeatStackDomainAdminPassword': 'password',
            'Controller-1::NeutronAllowL3AgentFailover': False,
            'Controller-1::NeutronBridgeMappings': 'datacentre:br-test',
            'Controller-1::NeutronDhcpAgentsPerNetwork': 3,
            'Controller-1::NeutronL3HA': True,
            'Controller-1::NeutronMechanismDrivers': 'linuxbridge',
            'Controller-1::NeutronPassword': 'password',
            'Controller-1::NovaPassword': 'password',
            'Controller-1::NtpServer': 'ntp.local',
            'Controller-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Controller-1::SwiftHashSuffix': 'password',
            'Controller-1::SwiftPassword': 'password',
            'NeutronControlPlaneID': 'network id',
            'Swift-Storage-1::SnmpdReadonlyUserPassword': "PASSWORD",
        }

        mock_heat_deploy.assert_called_with(
            mock_get_stack(),
            'overcloud',
            'fake/plan.yaml',
            parameters,
            ['fake/environment.yaml'],
            240
        )

        mock_create_tempest_deployer_input.assert_called_with(self.cmd)

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig')
    @mock.patch('rdomanager_oscplugin.utils.get_config_value', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_create_tempest_deployer_input', autospec=True)
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
                                        mock_create_tempest_deployer_input,
                                        mock_get_key,
                                        mock_deploy_postconfig):

        arglist = ['--plan', 'undercloud', '--output-dir', 'fake',
                   '--compute-flavor', 'baremetal',
                   '--neutron-bridge-mappings', 'datacentre:br-test',
                   '--neutron-disable-tunneling',
                   '--control-scale', '3',
                   '--ntp-server', 'ntp.local',
                   '-e', 'extra_registry.yaml',
                   '-e', 'extra_environment.yaml',
                   '-t', '120', ]

        verifylist = [
            ('templates', None),
            ('plan', 'undercloud'),
            ('output_dir', 'fake'),
            ('environment_files', ['extra_registry.yaml',
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
            'Cinder-Storage-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Compute-1::AdminPassword': 'password',
            'Compute-1::CeilometerMeteringSecret': 'password',
            'Compute-1::CeilometerPassword': 'password',
            'Compute-1::Flavor': 'baremetal',
            'Compute-1::NeutronAllowL3AgentFailover': False,
            'Compute-1::NeutronBridgeMappings': 'datacentre:br-test',
            'Compute-1::NeutronL3HA': True,
            'Compute-1::NeutronPassword': 'password',
            'Compute-1::NovaPassword': 'password',
            'Compute-1::NtpServer': 'ntp.local',
            'Compute-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Controller-1::AdminPassword': 'password',
            'Controller-1::AdminToken': 'password',
            'Controller-1::CeilometerMeteringSecret': 'password',
            'Controller-1::CeilometerPassword': 'password',
            'Controller-1::CinderPassword': 'password',
            'Controller-1::count': 3,
            'Controller-1::GlancePassword': 'password',
            'Controller-1::HeatPassword': 'password',
            'Controller-1::HeatStackDomainAdminPassword': 'password',
            'Controller-1::NeutronAllowL3AgentFailover': False,
            'Controller-1::NeutronBridgeMappings': 'datacentre:br-test',
            'Controller-1::NeutronDhcpAgentsPerNetwork': 3,
            'Controller-1::NeutronL3HA': True,
            'Controller-1::NeutronPassword': 'password',
            'Controller-1::NovaPassword': 'password',
            'Controller-1::NtpServer': 'ntp.local',
            'Controller-1::SnmpdReadonlyUserPassword': "PASSWORD",
            'Controller-1::SwiftHashSuffix': 'password',
            'Controller-1::SwiftPassword': 'password',
            'NeutronControlPlaneID': 'network id',
            'Swift-Storage-1::SnmpdReadonlyUserPassword': "PASSWORD",
        }

        mock_heat_deploy.assert_called_with(
            mock_get_stack(),
            'overcloud',
            'fake/plan.yaml',
            parameters,
            ['fake/environment.yaml',
             'extra_registry.yaml',
             'extra_environment.yaml'],
            120
        )

        # We can't use assert_called_with() here, as we need to compare
        # two lists that may have different ordering, although the ordering
        # does not matter:
        call_args = dict([(x['name'], x['value']) for x in
                          management.plans.patch.call_args_list[0][0][1]])
        target = dict([(k, six.text_type(v)) for k, v in parameters.items()])
        self.assertEqual(call_args, target)
        self.assertEqual(management.plans.patch.call_count, 1)

        mock_create_tempest_deployer_input.assert_called_with(self.cmd)

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tuskar', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_pre_heat_deploy', autospec=True)
    def test_invalid_deploy_call(self, mock_pre_deploy, mock_deploy_tht,
                                 mock_deploy_tuskar):

        arglist = ['--plan', 'undercloud', '--templates']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
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

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tuskar', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_pre_heat_deploy', autospec=True)
    def test_missing_sat_url(self, mock_pre_deploy, mock_deploy_tht,
                             mock_deploy_tuskar):

        arglist = ['--templates', '--rhel-reg',
                   '--reg-method', 'satellite', '--reg-org', '123456789',
                   '--reg-activation-key', 'super-awesome-key']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('rhel_reg', True),
            ('reg_method', 'satellite'),
            ('reg_org', '123456789'),
            ('reg_activation_key', 'super-awesome-key')
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)
        self.assertFalse(mock_deploy_tht.called)
        self.assertFalse(mock_deploy_tuskar.called)

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_create_tempest_deployer_input', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_create_overcloudrc', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_get_overcloud_endpoint', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tuskar', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_pre_heat_deploy', autospec=True)
    def test_rhel_reg_params_provided(self, mock_pre_deploy, mock_deploy_tht,
                                      mock_deploy_tuskar, mock_oc_endpoint,
                                      mock_create_ocrc,
                                      mock_create_tempest_deployer_input):

        arglist = ['--templates', '--rhel-reg',
                   '--reg-sat-url', 'https://example.com',
                   '--reg-method', 'satellite', '--reg-org', '123456789',
                   '--reg-activation-key', 'super-awesome-key']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('rhel_reg', True),
            ('reg_sat_url', 'https://example.com'),
            ('reg_method', 'satellite'),
            ('reg_org', '123456789'),
            ('reg_activation_key', 'super-awesome-key')
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)
        self.assertTrue(mock_deploy_tht.called)
        self.assertTrue(mock_oc_endpoint.called)
        self.assertTrue(mock_create_ocrc.called)
        self.assertFalse(mock_deploy_tuskar.called)

        mock_create_tempest_deployer_input.assert_called_with(self.cmd)
