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

import fixtures
import json
import os
import six
import tempfile

import mock

from openstackclient.common import exceptions as oscexc

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient.tests.v1.overcloud_deploy import fakes
from tripleoclient.tests.v1.utils import (
    generate_overcloud_passwords_mock)
from tripleoclient.v1 import overcloud_deploy


class TestDeployOvercloud(fakes.TestDeployOvercloud):

    def setUp(self):
        super(TestDeployOvercloud, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_deploy.DeployOvercloud(self.app, app_args)

        # mock validations for all deploy tests
        # for validator tests, see test_overcloud_deploy_validators.py
        validator_mock = mock.Mock(return_value=(0, 0))
        self.cmd._predeploy_verify_capabilities = validator_mock

        self._get_passwords = generate_overcloud_passwords_mock

        self.parameter_defaults_env_file = (
            tempfile.NamedTemporaryFile(mode='w', delete=False).name)

    def tearDown(self):
        super(TestDeployOvercloud, self).tearDown()
        os.unlink(self.parameter_defaults_env_file)

    @mock.patch("heatclient.common.event_utils.get_events")
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_create_parameters_env')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig')
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.generate_overcloud_passwords')
    @mock.patch('tripleoclient.utils.create_overcloudrc')
    @mock.patch('os_cloud_config.keystone.setup_endpoints', autospec=True)
    @mock.patch('time.sleep', return_value=None)
    @mock.patch('os_cloud_config.keystone.initialize', autospec=True)
    @mock.patch('tripleoclient.utils.remove_known_hosts', autospec=True)
    @mock.patch('tripleoclient.utils.wait_for_stack_ready',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'process_multiple_environments_and_files', autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('os_cloud_config.keystone_pki.generate_certs_into_json',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_environment_file',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_config_value', autospec=True)
    @mock.patch('tripleoclient.utils.check_hypervisor_stats',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_cephx_key',
                autospec=True)
    @mock.patch('uuid.uuid1', autospec=True)
    @mock.patch('time.time', autospec=True)
    def test_tht_scale(self, mock_time, mock_uuid1, mock_create_cephx_key,
                       mock_check_hypervisor_stats, mock_get_key,
                       mock_create_env, generate_certs_mock,
                       mock_get_templte_contents, mock_process_multiple_env,
                       wait_for_stack_ready_mock,
                       mock_remove_known_hosts, mock_keystone_initialize,
                       mock_sleep, mock_setup_endpoints,
                       mock_create_overcloudrc,
                       mock_generate_overcloud_passwords,
                       mock_create_tempest_deployer_input,
                       mock_deploy_postconfig,
                       mock_create_parameters_env,
                       mock_breakpoints_cleanupm,
                       mock_events):

        arglist = ['--templates', '--ceph-storage-scale', '3']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]

        mock_create_cephx_key.return_value = "cephx_key"
        mock_uuid1.return_value = "uuid"
        mock_time.return_value = 123456789

        mock_generate_overcloud_passwords.return_value = self._get_passwords()

        clients = self.app.client_manager
        orchestration_client = clients.tripleoclient.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_event = mock.Mock()
        mock_event.id = '1234'
        mock_events.return_value = [mock_events]

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

        baremetal = clients.tripleoclient.baremetal
        baremetal.node.list.return_value = range(10)

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
            'ExtraConfig': '{}',
            'GlancePassword': 'password',
            'HeatPassword': 'password',
            'HeatStackDomainAdminPassword': 'password',
            'HypervisorNeutronPhysicalBridge': 'br-ex',
            'HypervisorNeutronPublicInterface': 'nic1',
            'NeutronAllowL3AgentFailover': False,
            'NeutronBridgeMappings': 'datacentre:br-ex',
            'NeutronDhcpAgentsPerNetwork': 1,
            'NeutronDnsmasqOptions': 'dhcp-option-force=26,1400',
            'NeutronFlatNetworks': 'datacentre',
            'NeutronL3HA': False,
            'NeutronMetadataProxySharedSecret': 'password',
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
            'DeployIdentifier': 123456789,
        }

        def _custom_create_params_env(parameters):
            for key, value in six.iteritems(parameters):
                self.assertEqual(value, expected_parameters[key])
            parameter_defaults = {"parameter_defaults": parameters}
            with open(self.parameter_defaults_env_file, 'w') as temp_file:
                temp_file.write(json.dumps(parameter_defaults))
            return [self.parameter_defaults_env_file]

        mock_create_parameters_env.side_effect = _custom_create_params_env

        result = self.cmd.take_action(parsed_args)
        self.assertTrue(result)

        args, kwargs = orchestration_client.stacks.update.call_args

        self.assertEqual(args, (orchestration_client.stacks.get().id, ))

        self.assertEqual(kwargs['files'], {})
        self.assertEqual(kwargs['template'], 'template')
        self.assertEqual(kwargs['environment'], 'env')
        self.assertEqual(kwargs['stack_name'], 'overcloud')

        mock_get_templte_contents.assert_called_with(
            '/usr/share/openstack-tripleo-heat-templates/' +
            constants.OVERCLOUD_YAML_NAMES[0])

        mock_create_tempest_deployer_input.assert_called_with()
        mock_process_multiple_env.assert_called_with(
            [self.parameter_defaults_env_file])

    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_validate_args')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_create_parameters_env')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig')
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.generate_overcloud_passwords')
    @mock.patch('tripleoclient.utils.create_overcloudrc')
    @mock.patch('os_cloud_config.keystone.setup_endpoints', autospec=True)
    @mock.patch('time.sleep', return_value=None)
    @mock.patch('os_cloud_config.keystone.initialize', autospec=True)
    @mock.patch('tripleoclient.utils.remove_known_hosts', autospec=True)
    @mock.patch('tripleoclient.utils.wait_for_stack_ready',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'process_multiple_environments_and_files', autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('os_cloud_config.keystone_pki.generate_certs_into_json',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_environment_file',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_config_value', autospec=True)
    @mock.patch('tripleoclient.utils.check_hypervisor_stats',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_cephx_key',
                autospec=True)
    @mock.patch('uuid.uuid1', autospec=True)
    @mock.patch('time.time', autospec=True)
    def test_tht_deploy(self, mock_time, mock_uuid1, mock_create_cephx_key,
                        mock_check_hypervisor_stats, mock_get_key,
                        mock_create_env, generate_certs_mock,
                        mock_get_templte_contents, mock_process_multiple_env,
                        wait_for_stack_ready_mock,
                        mock_remove_known_hosts, mock_keystone_initialize,
                        mock_sleep, mock_setup_endpoints,
                        mock_create_overcloudrc,
                        mock_generate_overcloud_passwords,
                        mock_create_tempest_deployer_input,
                        mock_deploy_postconfig,
                        mock_create_parameters_env, mock_validate_args,
                        mock_breakpoints_cleanup):

        arglist = ['--templates', '--ceph-storage-scale', '3']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]

        mock_create_cephx_key.return_value = "cephx_key"
        mock_uuid1.return_value = "uuid"
        mock_time.return_value = 123456789

        mock_generate_overcloud_passwords.return_value = self._get_passwords()

        clients = self.app.client_manager
        orchestration_client = clients.tripleoclient.orchestration
        mock_stack = fakes.create_tht_stack()
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

        baremetal = clients.tripleoclient.baremetal
        baremetal.node.list.return_value = range(10)

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
            'ExtraConfig': '{}',
            'GlancePassword': 'password',
            'HeatPassword': 'password',
            'HeatStackDomainAdminPassword': 'password',
            'HypervisorNeutronPhysicalBridge': 'br-ex',
            'HypervisorNeutronPublicInterface': 'nic1',
            'NeutronAllowL3AgentFailover': False,
            'NeutronBridgeMappings': 'datacentre:br-ex',
            'NeutronDhcpAgentsPerNetwork': 1,
            'NeutronDnsmasqOptions': 'dhcp-option-force=26,1400',
            'NeutronEnableTunnelling': 'True',
            'NeutronFlatNetworks': 'datacentre',
            'NeutronL3HA': False,
            'NeutronNetworkType': 'gre',
            'NeutronNetworkVLANRanges': 'datacentre:1:1000',
            'NeutronMetadataProxySharedSecret': 'password',
            'NeutronPassword': 'password',
            'NeutronPublicInterface': 'nic1',
            'NeutronTunnelIdRanges': ['1:1000'],
            'NeutronTunnelTypes': 'gre',
            'NeutronVniRanges': ['1:1000'],
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
            'DeployIdentifier': 123456789,
        }

        def _custom_create_params_env(parameters):
            for key, value in six.iteritems(parameters):
                self.assertEqual(value, expected_parameters[key])
            parameter_defaults = {"parameter_defaults": parameters}
            with open(self.parameter_defaults_env_file, 'w') as temp_file:
                temp_file.write(json.dumps(parameter_defaults))
            return [self.parameter_defaults_env_file]

        mock_create_parameters_env.side_effect = _custom_create_params_env

        result = self.cmd.take_action(parsed_args)
        self.assertTrue(result)

        args, kwargs = orchestration_client.stacks.create.call_args

        self.assertEqual(kwargs['files'], {})
        self.assertEqual(kwargs['template'], 'template')
        self.assertEqual(kwargs['environment'], 'env')
        self.assertEqual(kwargs['stack_name'], 'overcloud')

        mock_get_templte_contents.assert_called_with(
            '/usr/share/openstack-tripleo-heat-templates/' +
            constants.OVERCLOUD_YAML_NAMES[0])

        mock_create_tempest_deployer_input.assert_called_with()
        mock_process_multiple_env.assert_called_with(
            ['/usr/share/openstack-tripleo-heat-templates/overcloud-resource-'
             'registry-puppet.yaml', '/fake/path',
             self.parameter_defaults_env_file])

        mock_validate_args.assert_called_once_with(parsed_args)

    @mock.patch("heatclient.common.event_utils.get_events")
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig')
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.generate_overcloud_passwords')
    @mock.patch('tripleoclient.utils.create_overcloudrc')
    @mock.patch('os_cloud_config.keystone.setup_endpoints', autospec=True)
    @mock.patch('time.sleep', return_value=None)
    @mock.patch('os_cloud_config.keystone.initialize', autospec=True)
    @mock.patch('tripleoclient.utils.remove_known_hosts', autospec=True)
    @mock.patch('tripleoclient.utils.wait_for_stack_ready',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'process_multiple_environments_and_files', autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('os_cloud_config.keystone_pki.generate_certs_into_json',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_environment_file',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_config_value', autospec=True)
    @mock.patch('tripleoclient.utils.check_hypervisor_stats',
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
                                     mock_deploy_postconfig,
                                     mock_breakpoints_cleanup,
                                     mock_events):

        arglist = ['--templates', '/home/stack/tripleo-heat-templates']
        verifylist = [
            ('templates', '/home/stack/tripleo-heat-templates'),
        ]

        mock_generate_overcloud_passwords.return_value = self._get_passwords()

        clients = self.app.client_manager
        orchestration_client = clients.tripleoclient.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_events.return_value = []

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

        baremetal = clients.tripleoclient.baremetal
        baremetal.node.list.return_value = range(10)

        with mock.patch('tempfile.mkstemp') as mkstemp:
            mkstemp.return_value = (os.open(self.parameter_defaults_env_file,
                                            os.O_RDWR),
                                    self.parameter_defaults_env_file)
            result = self.cmd.take_action(parsed_args)
        self.assertTrue(result)

        args, kwargs = orchestration_client.stacks.update.call_args

        self.assertEqual(args, (orchestration_client.stacks.get().id, ))

        self.assertEqual(kwargs['files'], {})
        self.assertEqual(kwargs['template'], 'template')
        self.assertEqual(kwargs['environment'], 'env')
        self.assertEqual(kwargs['stack_name'], 'overcloud')

        mock_get_templte_contents.assert_called_with(
            '/home/stack/tripleo-heat-templates/' +
            constants.OVERCLOUD_YAML_NAMES[0])

        mock_create_tempest_deployer_input.assert_called_with()
        mock_process_multiple_env.assert_called_with(
            [self.parameter_defaults_env_file])

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_pre_heat_deploy', autospec=True)
    def test_missing_sat_url(self, mock_pre_deploy, mock_deploy_tht):

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
        result = self.cmd.take_action(parsed_args)
        self.assertFalse(result)
        self.assertFalse(mock_deploy_tht.called)

    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.utils.check_nodes_count', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_update_parameters', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_pre_heat_deploy', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_environment_dirs(self, mock_deploy_heat, mock_pre_heat,
                              mock_update_parameters, mock_post_config,
                              mock_utils_check_nodes, mock_utils_endpoint,
                              mock_utils_createrc, mock_utils_tempest):

        mock_update_parameters.return_value = {}
        mock_utils_endpoint.return_value = 'foo.bar'

        tmp_dir = self.useFixture(fixtures.TempDir())
        test_env = os.path.join(tmp_dir.path, 'foo.yaml')

        env_dirs = [os.path.join(os.environ.get('HOME', ''), '.tripleo',
                    'environments'), tmp_dir.path]

        with open(test_env, 'w') as temp_file:
            temp_file.write('#just a comment')

        arglist = ['--templates', '--environment-directory', tmp_dir.path]
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('environment_directories', env_dirs),
        ]

        def _fake_heat_deploy(self, stack, stack_name, template_path,
                              parameters, environments, timeout):
            assert test_env in environments

        mock_deploy_heat.side_effect = _fake_heat_deploy

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)
        self.assertTrue(result)

    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.utils.check_nodes_count', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_update_parameters', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_pre_heat_deploy', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_environment_dirs_env(self, mock_deploy_heat, mock_pre_heat,
                                  mock_update_parameters, mock_post_config,
                                  mock_utils_check_nodes, mock_utils_endpoint,
                                  mock_utils_createrc, mock_utils_tempest):

        mock_update_parameters.return_value = {}
        mock_utils_endpoint.return_value = 'foo.bar'

        tmp_dir = tempfile.NamedTemporaryFile(mode='w', delete=False).name
        os.unlink(tmp_dir)
        os.mkdir(tmp_dir)
        test_env = os.path.join(tmp_dir, 'foo.yaml')
        with open(test_env, 'w') as temp_file:
            temp_file.write('#just a comment')

        arglist = ['--templates']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]
        os.environ['TRIPLEO_ENVIRONMENT_DIRECTORY'] = tmp_dir

        def _fake_heat_deploy(self, stack, stack_name, template_path,
                              parameters, environments, timeout):
            assert test_env in environments

        mock_deploy_heat.side_effect = _fake_heat_deploy

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)
        self.assertTrue(result)
        os.unlink(test_env)
        os.rmdir(tmp_dir)

    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_pre_heat_deploy', autospec=True)
    def test_rhel_reg_params_provided(self, mock_pre_deploy, mock_deploy_tht,
                                      mock_oc_endpoint,
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
        result = self.cmd.take_action(parsed_args)
        self.assertTrue(result)
        self.assertTrue(mock_deploy_tht.called)
        self.assertTrue(mock_oc_endpoint.called)
        self.assertTrue(mock_create_ocrc.called)

        mock_create_tempest_deployer_input.assert_called_with()

    def test_validate_args_correct(self):
        arglist = ['--templates',
                   '--neutron-network-type', 'nettype',
                   '--neutron-tunnel-types', 'nettype']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('neutron_network_type', 'nettype'),
            ('neutron_tunnel_types', 'nettype'),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd._validate_args(parsed_args)

    def test_validate_args_mismatch(self):
        arglist = ['--templates',
                   '--neutron-network-type', 'nettype1',
                   '--neutron-tunnel-types', 'nettype2']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('neutron_network_type', 'nettype1'),
            ('neutron_tunnel_types', 'nettype2'),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaises(oscexc.CommandError,
                          self.cmd._validate_args,
                          parsed_args)

    def test_validate_args_no_tunnel_type(self):
        arglist = ['--templates',
                   '--neutron-network-type', 'nettype']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('neutron_network_type', 'nettype'),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaises(oscexc.CommandError,
                          self.cmd._validate_args,
                          parsed_args)

    def test_validate_args_no_tunnel_types(self):
        arglist = ['--templates',
                   '--neutron-tunnel-types', 'nettype']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('neutron_tunnel_types', 'nettype'),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaises(oscexc.CommandError,
                          self.cmd._validate_args,
                          parsed_args)

    def test_validate_args_tunneling_disabled_with_network_type(self):
        arglist = ['--templates',
                   '--neutron-disable-tunneling',
                   '--neutron-network-type', 'nettype']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('neutron_disable_tunneling', True),
            ('neutron_network_type', 'nettype')
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # If this call does not raise an error, then call is validated
        self.cmd._validate_args(parsed_args)

    def test_validate_args_tunneling_disabled_with_tunnel_types(self):
        arglist = ['--templates',
                   '--neutron-disable-tunneling',
                   '--neutron-tunnel-types', 'nettype']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('neutron_disable_tunneling', True),
            ('neutron_tunnel_types', 'nettype')
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # If this call does not raise an error, then call is validated
        self.cmd._validate_args(parsed_args)

    def test_validate_args_vlan_as_network_type_no_vlan_range(self):
        arglist = ['--templates',
                   '--neutron-network-type', 'vlan']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('neutron_network_type', 'vlan')
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaises(oscexc.CommandError,
                          self.cmd._validate_args,
                          parsed_args)

    @mock.patch('tripleoclient.utils.check_hypervisor_stats',
                autospec=True)
    def test_pre_heat_deploy_failed(self, mock_check_hypervisor_stats):
        clients = self.app.client_manager
        orchestration_client = clients.tripleoclient.orchestration
        orchestration_client.stacks.get.return_value = None
        mock_check_hypervisor_stats.return_value = None
        arglist = ['--templates']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/')
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)
        self.assertFalse(result)
        self.assertRaises(exceptions.DeploymentError,
                          self.cmd._pre_heat_deploy)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_try_overcloud_deploy_with_first_template_existing(
            self, mock_heat_deploy_func):
        result = self.cmd._try_overcloud_deploy_with_compat_yaml(
            '/fake/path', {}, 'overcloud', {}, ['~/overcloud-env.json'], 1)
        # If it returns None it succeeded
        self.assertIsNone(result)
        mock_heat_deploy_func.assert_called_once_with(
            self.cmd, {}, 'overcloud',
            '/fake/path/' + constants.OVERCLOUD_YAML_NAMES[0], {},
            ['~/overcloud-env.json'], 1)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy')
    def test_try_overcloud_deploy_w_only_second_template_existing(
            self, mock_heat_deploy_func):
        mock_heat_deploy_func.side_effect = [
            six.moves.urllib.error.URLError('error'), None]
        result = self.cmd._try_overcloud_deploy_with_compat_yaml(
            '/fake/path', {}, 'overcloud', {}, ['~/overcloud-env.json'], 1)
        # If it returns None it succeeded
        self.assertIsNone(result)
        mock_heat_deploy_func.assert_has_calls(
            [mock.call({}, 'overcloud',
                       '/fake/path/' + constants.OVERCLOUD_YAML_NAMES[0], {},
                       ['~/overcloud-env.json'], 1),
             mock.call({}, 'overcloud',
                       '/fake/path/' + constants.OVERCLOUD_YAML_NAMES[1], {},
                       ['~/overcloud-env.json'], 1)])

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_try_overcloud_deploy_with_no_templates_existing(
            self, mock_heat_deploy_func):
        mock_heat_deploy_func.side_effect = [
            six.moves.urllib.error.URLError('error')
            for stack_file in constants.OVERCLOUD_YAML_NAMES]
        self.assertRaises(ValueError,
                          self.cmd._try_overcloud_deploy_with_compat_yaml,
                          '/fake/path', mock.ANY, mock.ANY, mock.ANY,
                          mock.ANY, mock.ANY)

    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_pre_heat_deploy', autospec=True)
    def test_dry_run(self, mock_pre_deploy, mock_deploy_tht,
                     mock_oc_endpoint,
                     mock_create_ocrc,
                     mock_create_tempest_deployer_input):

        arglist = ['--templates', '--dry-run']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('dry_run', True),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)
        self.assertTrue(result)
        self.assertFalse(mock_deploy_tht.called)
        self.assertFalse(mock_oc_endpoint.called)
        self.assertFalse(mock_create_ocrc.called)
        self.assertFalse(mock_create_tempest_deployer_input.called)
