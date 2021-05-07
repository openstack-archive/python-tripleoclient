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
import os
import shutil
import six
import tempfile
import yaml

import mock
import openstack
from osc_lib import exceptions as oscexc
from osc_lib.tests import utils

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient.tests.fixture_data import deployment
from tripleoclient.tests.v1.overcloud_deploy import fakes
from tripleoclient.v1 import overcloud_deploy


class TestDeployOvercloud(fakes.TestDeployOvercloud):

    def setUp(self):
        super(TestDeployOvercloud, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_deploy.DeployOvercloud(self.app, app_args)

        self.parameter_defaults_env_file = (
            tempfile.NamedTemporaryFile(mode='w', delete=False).name)
        self.tmp_dir = self.useFixture(fixtures.TempDir())

        # Mock the history command to avoid leaking files
        history_patcher = mock.patch('tripleoclient.utils.store_cli_param',
                                     autospec=True)
        history_patcher.start()
        self.addCleanup(history_patcher.stop)

        self.real_shutil = shutil.rmtree

        self.uuid1_value = "uuid"
        mock_uuid1 = mock.patch('uuid.uuid1', return_value=self.uuid1_value,
                                autospec=True)
        mock_uuid1.start()
        self.addCleanup(mock_uuid1.stop)
        mock_uuid4 = mock.patch('uuid.uuid4', return_calue='uuid4',
                                autospec=True)
        mock_uuid4.start()
        self.addCleanup(mock_uuid4.stop)

        # Mock time to get predicdtable DeployIdentifiers
        self.time_value = 12345678
        mock_time = mock.patch('time.time', return_value=self.time_value,
                               autospec=True)
        mock_time.start()
        self.addCleanup(mock_time.stop)

        # Mock copytree to avoid creating temporary templates
        mock_copytree = mock.patch('shutil.copytree',
                                   autospec=True)
        mock_copytree.start()
        self.addCleanup(mock_copytree.stop)

        # Mock sleep to reduce time of test
        mock_sleep = mock.patch('time.sleep', autospec=True)
        mock_sleep.start()
        self.addCleanup(mock_sleep.stop)

        mock_run_command = mock.patch(
            'tripleoclient.utils.run_command_and_log',
            autospec=True,
            return_value=0)
        mock_run_command.start()
        self.addCleanup(mock_run_command.stop)

        # Mock playbook runner
        playbook_runner = mock.patch(
            'tripleoclient.utils.run_ansible_playbook',
            autospec=True
        )
        self.mock_playbook = playbook_runner.start()
        self.addCleanup(playbook_runner.stop)

        # Mock horizon url return
        horizon_url = mock.patch(
            'tripleoclient.workflows.deployment.get_horizon_url',
            autospec=True
        )
        horizon_url.start()
        horizon_url.return_value = 'fake://url:12345'
        self.addCleanup(horizon_url.stop)

    def tearDown(self):
        super(TestDeployOvercloud, self).tearDown()
        os.unlink(self.parameter_defaults_env_file)
        shutil.rmtree = self.real_shutil

    @mock.patch('tripleoclient.utils.check_service_vips_migrated_to_service')
    @mock.patch('tripleoclient.utils.build_stack_data', autospec=True)
    @mock.patch('tripleo_common.utils.plan.default_image_params',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_rc_params',
                autospec=True)
    @mock.patch('tripleo_common.utils.plan.generate_passwords',
                return_value={})
    @mock.patch(
        'tripleo_common.image.kolla_builder.container_images_prepare_multi',
        return_value={})
    @mock.patch('tripleoclient.workflows.roles.get_roles_data',
                autospec=True, return_value={})
    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', autospec=True)
    @mock.patch('tripleoclient.utils.check_nic_config_with_ansible')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_ctlplane_attrs', autospec=True, return_value={})
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.utils.check_stack_network_matches_env_files')
    @mock.patch('tripleoclient.utils.check_ceph_fsid_matches_env_files')
    @mock.patch('tripleoclient.utils.check_swift_and_rgw')
    @mock.patch("heatclient.common.event_utils.get_events")
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_parameters_env', autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    def test_tht_scale(self, mock_get_template_contents,
                       mock_create_tempest_deployer_input,
                       mock_create_parameters_env,
                       mock_breakpoints_cleanup,
                       mock_events, mock_stack_network_check,
                       mock_ceph_fsid, mock_swift_rgw,
                       mock_get_undercloud_host_entry, mock_copy,
                       mock_get_ctlplane_attrs, mock_nic_ansiblei,
                       mock_process_env, mock_roles_data,
                       mock_container_prepare, mock_generate_password,
                       mock_rc_params, mock_default_image_params,
                       mock_stack_data, mock_check_service_vip_migr):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack()
        orchestration_client.stacks.get.return_value = mock_stack
        utils_fixture = deployment.UtilsFixture()
        self.useFixture(utils_fixture)
        arglist = ['--templates']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_event = mock.Mock()
        mock_event.id = '1234'
        mock_events.return_value = [mock_events]
        mock_roles_data.return_value = []
        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_get_template_contents.return_value = [{}, "template"]
        mock_stack_data.return_value = {'environment_parameters': {},
                                        'heat_resource_tree': {}}
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)

        expected_parameters = {
            'CephClusterFSID': self.uuid1_value,
            'CephStorageCount': 3,
            'ExtraConfig': '{}',
            'HypervisorNeutronPhysicalBridge': 'br-ex',
            'HypervisorNeutronPublicInterface': 'nic1',
            'NeutronDnsmasqOptions': 'dhcp-option-force=26,1400',
            'NeutronFlatNetworks': 'datacentre',
            'NeutronPublicInterface': 'nic1',
            'NtpServer': '',
            'SnmpdReadonlyUserPassword': 'PASSWORD',
            'DeployIdentifier': 12345678,
            'RootStackName': 'overcloud',
            'StackAction': 'UPDATE',
            'UndercloudHostsEntries': [
                '192.168.0.1 uc.ctlplane.localhost uc.ctlplane'],
            'CtlplaneNetworkAttributes': {},
        }

        def _custom_create_params_env(parameters, tht_root,
                                      stack):
            for key, value in six.iteritems(parameters):
                self.assertEqual(value, expected_parameters[key])
            parameter_defaults = {"parameter_defaults": parameters}
            return parameter_defaults

        mock_create_parameters_env.side_effect = _custom_create_params_env
        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}
        mock_process_env.return_value = {}, {
            'parameter_defaults': expected_parameters}
        self.cmd.take_action(parsed_args)

        self.assertTrue(orchestration_client.stacks.update.called)

        mock_get_template_contents.assert_called_with(
            template_file=mock.ANY)

        mock_create_tempest_deployer_input.assert_called_with(
            output_dir=self.cmd.working_dir)
        mock_copy.assert_called_once()

    @mock.patch('tripleoclient.utils.build_stack_data', autospec=True)
    @mock.patch('tripleo_common.utils.plan.default_image_params',
                return_value={})
    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleo_common.utils.plan.generate_passwords',
                return_value={})
    @mock.patch(
        'tripleo_common.image.kolla_builder.container_images_prepare_multi',
        return_value={})
    @mock.patch('tripleoclient.workflows.roles.get_roles_data',
                autospec=True, return_value={})
    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_ctlplane_attrs', autospec=True, return_value={})
    @mock.patch('tripleoclient.workflows.deployment.create_overcloudrc',
                autospec=True)
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.workflows.parameters.invoke_plan_env_workflows',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_validate_args')
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('os.chmod', autospec=True)
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    @mock.patch('tripleoclient.utils.makedirs')
    def test_tht_deploy(self, mock_md, mock_tmpdir, mock_cd, mock_chmod,
                        mock_get_template_contents, mock_validate_args,
                        mock_breakpoints_cleanup, mock_postconfig,
                        mock_invoke_plan_env_wf,
                        mock_get_undercloud_host_entry,
                        mock_copy, mock_overcloudrc,
                        mock_get_ctlplane_attrs,
                        mock_process_env, mock_roles_data,
                        mock_container_prepare, mock_generate_password,
                        mock_rc_params, mock_default_image_params,
                        mock_stack_data):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        utils_fixture = deployment.UtilsFixture()
        self.useFixture(utils_fixture)
        utils_overcloud_fixture = deployment.UtilsOvercloudFixture()
        self.useFixture(utils_overcloud_fixture)
        arglist = ['--templates', '--no-cleanup']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]
        mock_stack_data.return_value = {'environment_parameters': {},
                                        'heat_resource_tree': {}}
        mock_tmpdir.return_value = self.tmp_dir.path

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack()
        orchestration_client.stacks.get.side_effect = [None, mock_stack]

        def _orch_clt_create(**kwargs):
            orchestration_client.stacks.get.return_value = mock_stack

        orchestration_client.stacks.create.side_effect = _orch_clt_create

        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_get_template_contents.return_value = [{}, "template"]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)
        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}

        parameters_env = {
            'parameter_defaults': {
                'StackAction': 'CREATE',
                'DeployIdentifier': 12345678,
                'RootStackName': 'overcloud',
                'UndercloudHostsEntries':
                    ['192.168.0.1 uc.ctlplane.localhost uc.ctlplane'],
                'CtlplaneNetworkAttributes': {}}}
        mock_process_env.return_value = {}, parameters_env
        mock_open_context = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open_context):
            self.cmd.take_action(parsed_args)

        self.assertTrue(orchestration_client.stacks.create.called)

        mock_get_template_contents.assert_called_with(
            template_file=mock.ANY)

        utils_overcloud_fixture.mock_deploy_tht.assert_called_with(
            output_dir=self.cmd.working_dir)

        mock_validate_args.assert_called_once_with(parsed_args)
        self.assertFalse(mock_invoke_plan_env_wf.called)

    @mock.patch('tripleoclient.utils.build_stack_data', autospec=True)
    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleo_common.utils.plan.generate_passwords',
                return_value={})
    @mock.patch(
        'tripleo_common.image.kolla_builder.container_images_prepare_multi',
        return_value={})
    @mock.patch('tripleoclient.workflows.roles.get_roles_data',
                autospec=True, return_value={})
    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', autospec=True)
    @mock.patch('os.chdir')
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.utils.check_stack_network_matches_env_files')
    @mock.patch('tripleoclient.utils.check_ceph_fsid_matches_env_files')
    @mock.patch('tripleoclient.utils.check_swift_and_rgw')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_validate_args')
    @mock.patch('tripleoclient.utils.create_parameters_env', autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('shutil.rmtree', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_tht_deploy_skip_deploy_identifier(
            self, mock_tmpdir, mock_rm,
            mock_get_template_contents,
            mock_create_parameters_env, mock_validate_args,
            mock_breakpoints_cleanup,
            mock_postconfig, mock_stack_network_check,
            mock_ceph_fsid, mock_swift_rgw,
            mock_get_undercloud_host_entry, mock_copy,
            mock_chdir,
            mock_process_env, mock_roles_data,
            mock_image_prepare, mock_generate_password,
            mock_rc_params, mock_stack_data):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        utils_fixture = deployment.UtilsFixture()
        self.useFixture(utils_fixture)
        utils_overcloud_fixture = deployment.UtilsOvercloudFixture()
        self.useFixture(utils_overcloud_fixture)

        arglist = ['--templates', '--skip-deploy-identifier']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('skip_deploy_identifier', True)
        ]
        mock_stack_data.return_value = {'environment_parameters': {},
                                        'heat_resource_tree': {}}
        mock_tmpdir.return_value = "/tmp/tht"

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack()
        orchestration_client.stacks.get.side_effect = [None, mock_stack]

        def _orch_clt_create(**kwargs):
            orchestration_client.stacks.get.return_value = mock_stack

        orchestration_client.stacks.create.side_effect = _orch_clt_create

        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_get_template_contents.return_value = [{}, "template"]

        mock_process_env.return_value = {}, {}
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)
        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}

        self.cmd.take_action(parsed_args)
        mock_copy.assert_called_once()

    @mock.patch('tripleoclient.utils.check_service_vips_migrated_to_service')
    @mock.patch('tripleoclient.utils.build_stack_data', autospec=True)
    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleo_common.utils.plan.generate_passwords',
                return_value={})
    @mock.patch(
        'tripleo_common.image.kolla_builder.container_images_prepare_multi',
        return_value={})
    @mock.patch('tripleoclient.workflows.roles.get_roles_data',
                autospec=True, return_value={})
    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', autospec=True)
    @mock.patch('tripleoclient.utils.check_nic_config_with_ansible')
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.utils.check_stack_network_matches_env_files')
    @mock.patch('tripleoclient.utils.check_ceph_fsid_matches_env_files')
    @mock.patch('tripleoclient.utils.check_swift_and_rgw')
    @mock.patch("heatclient.common.event_utils.get_events", autospec=True)
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    def test_deploy_custom_templates(self, mock_get_template_contents,
                                     mock_create_tempest_deployer_input,
                                     mock_deploy_postconfig,
                                     mock_breakpoints_cleanup,
                                     mock_events, mock_stack_network_check,
                                     mock_ceph_fsid, mock_swift_rgw,
                                     mock_get_undercloud_host_entry,
                                     mock_copy, mock_nic_ansible,
                                     mock_process_env,
                                     mock_roles_data,
                                     mock_image_prepare,
                                     mock_generate_password,
                                     mock_rc_params,
                                     mock_stack_data,
                                     mock_check_service_vip_migr):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        utils_fixture = deployment.UtilsFixture()
        self.useFixture(utils_fixture)

        arglist = ['--templates', '/home/stack/tripleo-heat-templates']
        verifylist = [
            ('templates', '/home/stack/tripleo-heat-templates'),
        ]

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_events.return_value = []

        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_get_template_contents.return_value = [{}, "template"]
        mock_stack_data.return_value = {'environment_parameters': {},
                                        'heat_resource_tree': {}}
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)
        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}

        env = {'parameter_defaults': {},
               'resource_registry': {}}
        mock_process_env.return_value = {}, env
        with mock.patch('tempfile.mkstemp') as mkstemp:
            mkstemp.return_value = (os.open(self.parameter_defaults_env_file,
                                            os.O_RDWR),
                                    self.parameter_defaults_env_file)
            self.cmd.take_action(parsed_args)

        self.assertTrue(orchestration_client.stacks.update.called)

        mock_get_template_contents.assert_called_with(
            template_file=mock.ANY)

        mock_create_tempest_deployer_input.assert_called_with(
            output_dir=self.cmd.working_dir)
        mock_copy.assert_called_once()

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'create_env_files', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'deploy_tripleo_heat_templates', autospec=True)
    def test_jinja2_env_path(self, mock_deploy_tht, mock_create_env):

        arglist = ['--templates', '-e', 'bad_path.j2.yaml', '-e', 'other.yaml',
                   '-e', 'bad_path2.j2.yaml']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('environment_files', ['bad_path.j2.yaml', 'other.yaml',
                                   'bad_path2.j2.yaml'])
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.assertRaises(
            oscexc.CommandError,
            self.cmd.take_action, parsed_args)
        self.assertFalse(mock_deploy_tht.called)

    @mock.patch('tripleoclient.utils.check_service_vips_migrated_to_service')
    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleoclient.utils.process_multiple_environments',
                autospec=True)
    @mock.patch('tripleoclient.utils.check_nic_config_with_ansible')
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.utils.check_stack_network_matches_env_files')
    @mock.patch('tripleoclient.utils.check_ceph_fsid_matches_env_files')
    @mock.patch('tripleoclient.utils.check_swift_and_rgw')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_update_parameters', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'create_env_files', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_environment_dirs(self, mock_deploy_heat, mock_create_env,
                              mock_update_parameters, mock_post_config,
                              mock_stack_network_check, mock_ceph_fsid,
                              mock_swift_rgw, mock_copy, mock_nic_ansible,
                              mock_process_env, mock_rc_params,
                              mock_check_service_vip_migr):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        utils_overcloud_fixture = deployment.UtilsOvercloudFixture()
        self.useFixture(utils_overcloud_fixture)

        clients = self.app.client_manager
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_update_parameters.return_value = {}
        utils_overcloud_fixture.mock_utils_endpoint.return_value = 'foo.bar'

        test_env = os.path.join(self.tmp_dir.path, 'foo1.yaml')

        env_dirs = [os.path.join(os.environ.get('HOME', ''), '.tripleo',
                    'environments'), self.tmp_dir.path]

        env = {'parameter_defaults': {},
               'resource_registry': {
                   'Test': 'OS::Heat::None',
                   'resources': {'*': {'*': {
                       'UpdateDeployment': {'hooks': []}}}}}}

        mock_process_env.return_value = {}, env
        with open(test_env, 'w') as temp_file:
            temp_file.write('resource_registry:\n  Test: OS::Heat::None')

        arglist = ['--templates', '--environment-directory', self.tmp_dir.path]
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('environment_directories', env_dirs),
        ]

        def assertEqual(*args):
            self.assertEqual(*args)

        def _fake_heat_deploy(self, stack, stack_name, template_path,
                              environments, timeout, tht_root,
                              env, run_validations,
                              roles_file,
                              env_files_tracker=None,
                              deployment_options=None):
            assertEqual(
                {'parameter_defaults': {},
                 'resource_registry': {
                     'Test': 'OS::Heat::None',
                     'resources': {'*': {'*': {
                         'UpdateDeployment': {'hooks': []}}}}}}, env)

        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}
        mock_deploy_heat.side_effect = _fake_heat_deploy
        mock_create_env.return_value = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)
        mock_copy.assert_called_once()

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_update_parameters', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_environment_dirs_env_dir_not_found(self, mock_deploy_heat,
                                                mock_update_parameters,
                                                mock_post_config):
        utils_fixture = deployment.UtilsOvercloudFixture()
        self.useFixture(utils_fixture)

        mock_update_parameters.return_value = {}
        utils_fixture.mock_utils_endpoint.return_value = 'foo.bar'
        os.mkdir(self.tmp_dir.join('env'))
        os.mkdir(self.tmp_dir.join('common'))

        arglist = ['--templates', '--environment-directory', '/tmp/notthere']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        error = self.assertRaises(oscexc.CommandError, self.cmd.take_action,
                                  parsed_args)
        self.assertIn('/tmp/notthere', str(error))

    def test_validate_args_missing_environment_files(self):
        arglist = ['--templates',
                   '-e', 'nonexistent.yaml']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('environment_files', ['nonexistent.yaml']),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaises(oscexc.CommandError,
                          self.cmd._validate_args,
                          parsed_args)

    @mock.patch('os.path.isfile', autospec=True)
    def test_validate_args_missing_rendered_files(self, mock_isfile):
        tht_path = '/usr/share/openstack-tripleo-heat-templates/'
        env_path = os.path.join(tht_path, 'noexist.yaml')
        arglist = ['--templates',
                   '-e', env_path]
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('environment_files', [env_path]),
        ]

        mock_isfile.side_effect = [False, True]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd._validate_args(parsed_args)
        calls = [mock.call(env_path),
                 mock.call(env_path.replace(".yaml", ".j2.yaml"))]
        mock_isfile.assert_has_calls(calls)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_try_overcloud_deploy_with_first_template_existing(
            self, mock_heat_deploy_func):
        result = self.cmd._try_overcloud_deploy_with_compat_yaml(
            '/fake/path', {}, 'overcloud', ['~/overcloud-env.json'], 1,
            {}, False, None, None)
        # If it returns None it succeeded
        self.assertIsNone(result)
        mock_heat_deploy_func.assert_called_once_with(
            self.cmd, {}, 'overcloud',
            '/fake/path/' + constants.OVERCLOUD_YAML_NAME,
            ['~/overcloud-env.json'], 1, '/fake/path', {}, False,
            None, deployment_options=None, env_files_tracker=None)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_try_overcloud_deploy_with_no_templates_existing(
            self, mock_heat_deploy_func):
        mock_heat_deploy_func.side_effect = Exception('error')
        self.assertRaises(ValueError,
                          self.cmd._try_overcloud_deploy_with_compat_yaml,
                          '/fake/path', mock.ANY, mock.ANY,
                          mock.ANY, mock.ANY, mock.ANY, mock.ANY, mock.ANY,
                          None)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_try_overcloud_deploy_show_missing_file(
            self, mock_heat_deploy_func):
        mock_heat_deploy_func.side_effect = \
            Exception('/fake/path not found')
        try:
            self.cmd._try_overcloud_deploy_with_compat_yaml(
                '/fake/path', mock.ANY, mock.ANY,
                mock.ANY, mock.ANY, mock.ANY, mock.ANY, mock.ANY,
                None)
        except ValueError as value_error:
            self.assertIn('/fake/path', str(value_error))

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'create_env_files', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'deploy_tripleo_heat_templates', autospec=True)
    def test_dry_run(self, mock_deploy, mock_create_env,
                     mock_get_undercloud_host_entry):
        utils_fixture = deployment.UtilsOvercloudFixture()
        self.useFixture(utils_fixture)
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack()
        orchestration_client.stacks.get.return_value = mock_stack
        arglist = ['--templates', '--dry-run']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('dry_run', True),
        ]

        mock_create_env.return_value = ({}, [])
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)
        self.assertFalse(utils_fixture.mock_deploy_tht.called)
        self.assertFalse(mock_deploy.called)

    @mock.patch('tripleoclient.utils.check_service_vips_migrated_to_service')
    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleo_common.utils.plan.generate_passwords',
                return_value={})
    @mock.patch(
        'tripleo_common.image.kolla_builder.container_images_prepare_multi',
        return_value={})
    @mock.patch('tripleoclient.workflows.roles.get_roles_data',
                autospec=True, return_value={})
    @mock.patch('tripleoclient.utils.check_nic_config_with_ansible')
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.utils.check_stack_network_matches_env_files')
    @mock.patch('tripleoclient.utils.check_ceph_fsid_matches_env_files')
    @mock.patch('tripleoclient.utils.check_swift_and_rgw')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    @mock.patch('shutil.rmtree', autospec=True)
    def test_answers_file(self, mock_rmtree, mock_tmpdir,
                          mock_heat_deploy, mock_stack_network_check,
                          mock_ceph_fsid, mock_swift_rgw,
                          mock_get_undercloud_host_entry,
                          mock_copy, mock_nic_ansible,
                          mock_roles_data, mock_image_prepare,
                          mock_generate_password, mock_rc_params,
                          mock_check_service_vip_migr):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack()
        orchestration_client.stacks.get.return_value = mock_stack
        utils_fixture = deployment.UtilsOvercloudFixture()
        self.useFixture(utils_fixture)

        clients = self.app.client_manager

        mock_tmpdir.return_value = self.tmp_dir.path
        mock_rmtree.return_value = None
        network_client = clients.network
        network_client.stacks.get.return_value = None
        net = network_client.api.find_attr('networks', 'ctlplane')
        net.configure_mock(__getitem__=lambda x, y: 'testnet')

        test_env = self.tmp_dir.join('foo1.yaml')
        with open(test_env, 'w') as temp_file:
            temp_file.write('resource_registry:\n  Test: OS::Heat::None')

        test_env2 = self.tmp_dir.join('foo2.yaml')
        with open(test_env2, 'w') as temp_file:
            temp_file.write('resource_registry:\n  Test2: OS::Heat::None')

        os.makedirs(self.tmp_dir.join('tripleo-heat-templates'))
        reg_file = self.tmp_dir.join(
            'tripleo-heat-templates/overcloud-resource-registry-puppet.yaml')
        with open(reg_file, 'w+') as temp_file:
            temp_file.write('resource_registry:\n  Test2: OS::Heat::None')

        test_answerfile = self.tmp_dir.join('answerfile')
        with open(test_answerfile, 'w') as answerfile:
            yaml.dump(
                {'templates':
                 '/usr/share/openstack-tripleo-heat-templates/',
                 'environments': [test_env]
                 },
                answerfile
            )

        arglist = ['--answers-file', test_answerfile,
                   '--environment-file', test_env2,
                   '--disable-password-generation',
                   '--working-dir', self.tmp_dir.path]
        verifylist = [
            ('answers_file', test_answerfile),
            ('environment_files', [test_env2]),
            ('disable_password_generation', True)]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}

        self.cmd.take_action(parsed_args)

        self.assertTrue(mock_heat_deploy.called)
        self.assertTrue(utils_fixture.mock_deploy_tht.called)

        # Check that Heat was called with correct parameters:
        call_args = mock_heat_deploy.call_args[0]
        self.assertEqual(call_args[3],
                         self.tmp_dir.join(
                             'tripleo-heat-templates/overcloud.yaml'))
        self.assertEqual(call_args[6],
                         self.tmp_dir.join('tripleo-heat-templates'))
        self.assertIn('Test', call_args[7]['resource_registry'])
        self.assertIn('Test2', call_args[7]['resource_registry'])

        utils_fixture.mock_deploy_tht.assert_called_with(
            output_dir=self.cmd.working_dir)
        mock_copy.assert_called_once()

    @mock.patch('tripleoclient.utils.build_stack_data', autospec=True)
    @mock.patch('tripleo_common.utils.plan.default_image_params',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleo_common.utils.plan.generate_passwords',
                return_value={})
    @mock.patch(
        'tripleo_common.image.kolla_builder.container_images_prepare_multi',
        return_value={})
    @mock.patch('tripleoclient.workflows.roles.get_roles_data',
                autospec=True, return_value={})
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_ctlplane_attrs', autospec=True, return_value={})
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.utils.check_stack_network_matches_env_files')
    @mock.patch('tripleoclient.utils.check_ceph_fsid_matches_env_files')
    @mock.patch('tripleoclient.utils.check_swift_and_rgw')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_validate_args')
    @mock.patch('tripleoclient.utils.create_parameters_env', autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    def test_tht_deploy_with_ntp(self, mock_get_template_contents,
                                 mock_process_env,
                                 mock_create_tempest_deployer_input,
                                 mock_create_parameters_env,
                                 mock_validate_args,
                                 mock_breakpoints_cleanup,
                                 mock_deploy_post_config,
                                 mock_stack_network_check,
                                 mock_ceph_fsid, mock_swift_rgw,
                                 mock_get_undercloud_host_entry, mock_copy,
                                 mock_get_ctlplane_attrs,
                                 mock_roles_data,
                                 mock_image_prepare,
                                 mock_generate_password,
                                 mock_rc_params,
                                 mock_default_image_params,
                                 mock_stack_data):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        utils_fixture = deployment.UtilsFixture()
        self.useFixture(utils_fixture)

        mock_stack_data.return_value = {'environment_parameters': {},
                                        'heat_resource_tree': {}}
        arglist = ['--templates', '--ntp-server', 'ntp']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack()
        orchestration_client.stacks.get.side_effect = [
            None,
            mock_stack
        ]

        def _orch_clt_create(**kwargs):
            orchestration_client.stacks.get.return_value = mock_stack

        orchestration_client.stacks.create.side_effect = _orch_clt_create

        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_env = fakes.create_env_with_ntp()
        mock_process_env.return_value = [{}, mock_env]
        mock_get_template_contents.return_value = [{}, "template"]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)

        expected_parameters = {
            'CephClusterFSID': self.uuid1_value,
            'ExtraConfig': '{}',
            'HypervisorNeutronPhysicalBridge': 'br-ex',
            'HypervisorNeutronPublicInterface': 'nic1',
            'NeutronDnsmasqOptions': 'dhcp-option-force=26,1400',
            'NeutronFlatNetworks': 'datacentre',
            'NeutronNetworkType': 'gre',
            'NeutronPublicInterface': 'nic1',
            'NeutronTunnelTypes': 'gre',
            'SnmpdReadonlyUserPassword': 'PASSWORD',
            'StackAction': 'CREATE',
            'DeployIdentifier': 12345678,
            'RootStackName': 'overcloud',
            'NtpServer': 'ntp',
            'UndercloudHostsEntries': [
                '192.168.0.1 uc.ctlplane.localhost uc.ctlplane'
            ],
            'CtlplaneNetworkAttributes': {},
        }

        def _custom_create_params_env(parameters, tht_root,
                                      stack):
            for key, value in six.iteritems(parameters):
                self.assertEqual(value, expected_parameters[key])
            parameter_defaults = {"parameter_defaults": parameters}
            return parameter_defaults

        mock_create_parameters_env.side_effect = _custom_create_params_env

        self.cmd.take_action(parsed_args)

        mock_get_template_contents.assert_called_with(
            template_file=mock.ANY)

        mock_create_tempest_deployer_input.assert_called_with(
            output_dir=self.cmd.working_dir)

        mock_validate_args.assert_called_once_with(parsed_args)
        mock_copy.assert_called_once()

    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'create_env_files', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'deploy_tripleo_heat_templates', autospec=True)
    def test_deployed_server(self, mock_deploy, mock_create_env,
                             mock_get_undercloud_host_entry,
                             mock_copy, mock_rc_params):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        utils_fixture = deployment.UtilsOvercloudFixture()
        self.useFixture(utils_fixture)
        arglist = ['--templates', '--deployed-server', '--disable-validations']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('deployed_server', True),
            ('disable_validations', True),
        ]

        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}
        clients = self.app.client_manager
        clients.baremetal = mock.Mock()
        clients.compute = mock.Mock()
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_create_env.return_value = ({}, [])
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)
        self.assertTrue(mock_deploy.called)
        self.assertNotCalled(clients.baremetal)
        self.assertNotCalled(clients.compute)
        self.assertTrue(utils_fixture.mock_deploy_tht.called)
        mock_copy.assert_called_once()

    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'create_env_files', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'deploy_tripleo_heat_templates', autospec=True)
    def test_config_download(
            self, mock_deploy, mock_create_env,
            mock_get_undercloud_host_entry,
            mock_copy, mock_rc_params):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        utils_fixture = deployment.UtilsOvercloudFixture()
        self.useFixture(utils_fixture)
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()

        arglist = ['--templates', '--config-download']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('config_download', True),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}
        mock_create_env.return_value = ({}, [])
        self.cmd.take_action(parsed_args)
        self.assertTrue(mock_deploy.called)
        self.assertTrue(fixture.mock_get_hosts_and_enable_ssh_admin.called)
        self.assertTrue(fixture.mock_config_download.called)
        self.assertTrue(fixture.mock_set_deployment_status.called)
        self.assertEqual(
            'DEPLOY_SUCCESS',
            fixture.mock_set_deployment_status.call_args[-1]['status']
        )
        mock_copy.assert_called_once()

    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'create_env_files', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'deploy_tripleo_heat_templates', autospec=True)
    def test_config_download_setup_only(
            self, mock_deploy, mock_create_env,
            mock_get_undercloud_host_entry,
            mock_copy, mock_rc_params):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        utils_fixture = deployment.UtilsOvercloudFixture()
        self.useFixture(utils_fixture)
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_create_env.return_value = ({}, [])

        arglist = ['--templates', '--config-download', '--setup-only']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('config_download', True),
            ('setup_only', True)
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}
        self.cmd.take_action(parsed_args)
        self.assertTrue(fixture.mock_get_hosts_and_enable_ssh_admin.called)
        self.assertTrue(fixture.mock_config_download.called)
        self.assertTrue(fixture.mock_set_deployment_status.called)
        self.assertEqual(
            'DEPLOY_SUCCESS',
            fixture.mock_set_deployment_status.call_args[-1]['status']
        )
        mock_copy.assert_called_once()

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'create_env_files', autospec=True)
    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'deploy_tripleo_heat_templates', autospec=True)
    def test_config_download_only(
            self, mock_deploy,
            mock_get_undercloud_host_entry,
            mock_copy, mock_rc_params,
            mock_create_parameters_env):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        utils_fixture = deployment.UtilsOvercloudFixture()
        self.useFixture(utils_fixture)
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_create_parameters_env.return_value = (mock.Mock(), mock.Mock())

        arglist = ['--templates', '--config-download-only']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('config_download_only', True),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}

        self.cmd.take_action(parsed_args)
        self.assertFalse(mock_deploy.called)
        self.assertFalse(fixture.mock_get_hosts_and_enable_ssh_admin.called)
        self.assertTrue(fixture.mock_config_download.called)
        self.assertTrue(fixture.mock_set_deployment_status.called)
        self.assertEqual(
            'DEPLOY_SUCCESS',
            fixture.mock_set_deployment_status.call_args[-1]['status'])
        mock_copy.assert_called_once()

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'create_env_files', autospec=True)
    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'deploy_tripleo_heat_templates', autospec=True)
    def test_config_download_fails(
            self, mock_deploy,
            mock_overcloud_endpoint,
            mock_create_tempest_deployer_input,
            mock_get_undercloud_host_entry,
            mock_copy, mock_rc_params,
            mock_create_parameters_env):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_create_parameters_env.return_value = (mock.Mock(), mock.Mock())

        arglist = ['--templates', '--config-download-only']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('config_download_only', True),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}

        fixture.mock_config_download.side_effect = \
            exceptions.DeploymentError('fails')
        self.assertRaises(
            exceptions.DeploymentError,
            self.cmd.take_action,
            parsed_args)
        self.assertFalse(mock_deploy.called)
        self.assertTrue(fixture.mock_config_download.called)
        self.assertTrue(fixture.mock_set_deployment_status.called)
        self.assertEqual(
            'DEPLOY_FAILED',
            fixture.mock_set_deployment_status.call_args[-1]['status'])

    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'create_env_files', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'deploy_tripleo_heat_templates', autospec=True)
    def test_override_ansible_cfg(
            self, mock_deploy, mock_create_env,
            mock_get_undercloud_host_entry,
            mock_copy, mock_rc_params):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        utils_fixture = deployment.UtilsOvercloudFixture()
        self.useFixture(utils_fixture)
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()

        arglist = ['--templates',
                   '--override-ansible-cfg', 'ansible.cfg']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('override_ansible_cfg', 'ansible.cfg')
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}

        mock_create_env.return_value = ({}, [])
        self.cmd.take_action(parsed_args)
        self.assertTrue(fixture.mock_get_hosts_and_enable_ssh_admin.called)
        self.assertTrue(fixture.mock_config_download.called)
        mock_copy.assert_called_once()

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'create_env_files', autospec=True)
    @mock.patch('tripleoclient.utils.check_service_vips_migrated_to_service')
    @mock.patch('tripleo_common.utils.plan.default_image_params',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleo_common.utils.plan.generate_passwords',
                return_value={})
    @mock.patch(
        'tripleo_common.image.kolla_builder.container_images_prepare_multi',
        return_value={})
    @mock.patch('tripleoclient.workflows.roles.get_roles_data',
                autospec=True, return_value={})
    @mock.patch('tripleoclient.utils.process_multiple_environments',
                autospec=True)
    @mock.patch('tripleoclient.utils.check_nic_config_with_ansible')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_ctlplane_attrs', autospec=True, return_value={})
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    @mock.patch('tripleoclient.utils.check_stack_network_matches_env_files')
    @mock.patch('tripleoclient.utils.check_ceph_fsid_matches_env_files')
    @mock.patch('tripleoclient.utils.check_swift_and_rgw')
    @mock.patch('heatclient.common.template_utils.deep_update', autospec=True)
    def test_config_download_timeout(
            self, mock_hc, mock_stack_network_check,
            mock_ceph_fsid, mock_swift_rgw, mock_hd,
            mock_get_undercloud_host_entry, mock_copy,
            mock_get_ctlplane_attrs, mock_nic_ansible,
            mock_process_env, mock_roles_data,
            mock_container_prepare, mock_generate_password,
            mock_rc_params, mock_default_image_params,
            mock_check_service_vip_migr,
            mock_create_parameters_env):
        fixture = deployment.DeploymentWorkflowFixture()
        self.useFixture(fixture)
        utils_fixture = deployment.UtilsOvercloudFixture()
        self.useFixture(utils_fixture)
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_create_parameters_env.return_value = []

        arglist = ['--templates', '--overcloud-ssh-port-timeout', '42',
                   '--timeout', '451']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('overcloud_ssh_port_timeout', 42), ('timeout', 451)
        ]
        mock_process_env.return_value = {}, {}
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}
        # assuming heat deploy consumed a 3m out of total 451m timeout
        with mock.patch('time.time', side_effect=[1585820346,
                                                  12345678, 0, 0,
                                                  1585820526]):
            self.cmd.take_action(parsed_args)
        self.assertIn(
            [mock.call(mock.ANY, mock.ANY, 'overcloud', mock.ANY,
                       mock.ANY, 451, mock.ANY, mock.ANY, False, None,
                       deployment_options={}, env_files_tracker=mock.ANY)],
            mock_hd.mock_calls)
        self.assertIn(
            [mock.call(mock.ANY, mock.ANY, mock.ANY, 'ctlplane',
                       os.path.join(
                           self.cmd.working_dir,
                           'config-download'),
                       None,
                       deployment_options={},
                       deployment_timeout=448,  # 451 - 3, total time left
                       in_flight_validations=False, limit_hosts=None,
                       setup_only=False, skip_tags=None, tags=None, timeout=42,
                       verbosity=3, forks=None)],
            fixture.mock_config_download.mock_calls)
        fixture.mock_config_download.assert_called()
        mock_copy.assert_called_once()

    @mock.patch('tripleoclient.workflows.deployment.make_config_download_dir')
    @mock.patch('tripleoclient.utils.get_rc_params', autospec=True)
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_update_parameters')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'create_env_files', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'deploy_tripleo_heat_templates', autospec=True)
    def test_config_download_only_timeout(
            self, mock_deploy, mock_create_env,
            mock_get_undercloud_host_entry, mock_update,
            mock_copyi, mock_rc_params, mock_cd_dir):
        utils_fixture = deployment.UtilsOvercloudFixture()
        self.useFixture(utils_fixture)
        utils_fixture2 = deployment.UtilsFixture()
        self.useFixture(utils_fixture2)
        clients = self.app.client_manager
        stack = fakes.create_tht_stack()
        stack.stack_name = 'overcloud'
        stack.output_show.return_value = {'output': {'output_value': []}}
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = stack

        arglist = ['--templates', '--config-download-only',
                   '--overcloud-ssh-port-timeout', '42',
                   '--config-download-timeout', '240']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('config_download_only', True),
            ('config_download_timeout', 240),
            ('overcloud_ssh_port_timeout', 42)
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        mock_rc_params.return_value = {'password': 'password',
                                       'region': 'region1'}

        mock_create_env.return_value = ({}, [])
        self.cmd.take_action(parsed_args)
        playbook = os.path.join(os.environ.get(
            'HOME'), self.cmd.working_dir,
            'config-download/overcloud/deploy_steps_playbook.yaml')
        self.assertIn(
            [mock.call(
                ansible_cfg=None, ansible_timeout=42,
                extra_env_variables={'ANSIBLE_BECOME': True}, extra_vars=None,
                inventory=mock.ANY, key=mock.ANY, limit_hosts=None,
                playbook=playbook, playbook_dir=mock.ANY,
                reproduce_command=True, skip_tags='opendev-validation',
                ssh_user='tripleo-admin', tags=None,
                timeout=240,
                verbosity=3, workdir=mock.ANY, forks=None)],
            utils_fixture2.mock_run_ansible_playbook.mock_calls)

    @mock.patch('tripleoclient.utils.write_user_environment', autospec=True)
    def test_provision_baremetal(self, mock_write):
        mock_write.return_value = (
            '/tmp/tht/user-environments/baremetal-deployed.yaml',
            'overcloud/user-environments/baremetal-deployed.yaml'
        )
        baremetal_deployed = {
            'parameter_defaults': {'foo': 'bar'}
        }

        bm_deploy_path = self.tmp_dir.join('bm_deploy.yaml')
        deploy_data = [
            {'name': 'Compute', 'count': 10},
            {'name': 'Controller', 'count': 3},
        ]
        with open(bm_deploy_path, 'w') as temp_file:
            yaml.safe_dump(deploy_data, temp_file)

        ssh_key_path = self.tmp_dir.join('id_rsa.pub')
        with open(ssh_key_path, 'w') as temp_file:
            temp_file.write('sekrit')

        with open('{}.pub'.format(ssh_key_path), 'w') as f:
            f.write('sekrit')

        arglist = [
            '--baremetal-deployment', bm_deploy_path,
            '--overcloud-ssh-key', ssh_key_path
        ]
        verifylist = [
            ('baremetal_deployment', bm_deploy_path),
            ('overcloud_ssh_key', ssh_key_path),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        tht_root = self.tmp_dir.join('tht')
        env_dir = os.path.join(tht_root, 'user-environments')
        env_path = os.path.join(env_dir, 'baremetal-deployed.yaml')
        os.makedirs(env_dir)
        with open(env_path, 'w') as f:
            yaml.safe_dump(baremetal_deployed, f)

        result = self.cmd._provision_baremetal(parsed_args, tht_root)
        self.cmd._unprovision_baremetal(parsed_args)
        self.assertEqual([env_path], result)
        self.mock_playbook.assert_has_calls([
            mock.call(
                extra_vars={
                    'stack_name': 'overcloud',
                    'baremetal_deployment': [
                        {'count': 10, 'name': 'Compute'},
                        {'count': 3, 'name': 'Controller'}
                    ],
                    'baremetal_deployed_path': env_path,
                    'ssh_public_keys': 'sekrit',
                    'ssh_user_name': 'heat-admin'
                },
                inventory='localhost,',
                playbook='cli-overcloud-node-provision.yaml',
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=3,
                workdir=mock.ANY
            ),
            mock.call(
                extra_vars={
                    'stack_name': 'overcloud',
                    'baremetal_deployment': [
                        {'count': 10, 'name': 'Compute'},
                        {'count': 3, 'name': 'Controller'}
                    ],
                    'prompt': False
                },
                inventory='localhost,',
                playbook='cli-overcloud-node-unprovision.yaml',
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=3,
                workdir=mock.ANY
            )
        ])
        mock_write.assert_called_once_with(
            {'parameter_defaults': {'foo': 'bar'}},
            'baremetal-deployed.yaml',
            tht_root,
            'overcloud'
        )

    @mock.patch('subprocess.Popen', autospec=True)
    def test__get_undercloud_host_entry(self, mock_popen):
        mock_process = mock.Mock()
        mock_hosts = {
            'fd12::1 uc.ctlplane.localdomain uc.ctlplane':
                'fd12::1 uc.ctlplane.localdomain uc.ctlplane',
            'fd12::1 uc.ctlplane.localdomain uc.ctlplane\n'
            'fd12::1 uc.ctlplane.localdomain uc.ctlplane':
                'fd12::1 uc.ctlplane.localdomain uc.ctlplane',
            '1.2.3.4 uc.ctlplane foo uc.ctlplane bar uc.ctlplane':
                '1.2.3.4 uc.ctlplane foo bar'
        }
        for value, expected in mock_hosts.items():
            mock_process.communicate.return_value = (value, '')
            mock_process.returncode = 0
            mock_popen.return_value = mock_process
            self.assertEqual(expected, self.cmd._get_undercloud_host_entry())

    def test_check_limit_warning(self):
        mock_warning = mock.MagicMock()
        mock_log = mock.MagicMock()
        mock_log.warning = mock_warning
        env = {'parameter_defaults': {}}

        old_logger = self.cmd.log
        self.cmd.log = mock_log
        self.cmd._check_limit_skiplist_warning(env)
        self.cmd.log = old_logger
        mock_warning.assert_not_called()

    def test_check_limit_warning_empty(self):
        mock_warning = mock.MagicMock()
        mock_log = mock.MagicMock()
        mock_log.warning = mock_warning
        env = {'parameter_defaults': {'DeploymentServerBlacklist': []}}

        old_logger = self.cmd.log
        self.cmd.log = mock_log
        self.cmd._check_limit_skiplist_warning(env)
        self.cmd.log = old_logger
        mock_warning.assert_not_called()

    def test_check_limit_warning_warns(self):
        mock_warning = mock.MagicMock()
        mock_log = mock.MagicMock()
        mock_log.warning = mock_warning
        env = {'parameter_defaults': {'DeploymentServerBlacklist': ['a']}}

        old_logger = self.cmd.log
        self.cmd.log = mock_log
        self.cmd._check_limit_skiplist_warning(env)
        self.cmd.log = old_logger
        expected_message = ('[WARNING] DeploymentServerBlacklist is defined '
                            'and will be ignored because --limit has been '
                            'specified.')
        mock_warning.assert_called_once_with(expected_message)

    @mock.patch('openstack.connect', autospec=True)
    def test__get_ctlplane_attrs_no_config(self, mock_connect):
        mock_connect.side_effect = openstack.exceptions.ConfigException
        function = overcloud_deploy.DeployOvercloud._get_ctlplane_attrs

        expected = dict()
        self.assertEqual(expected, function(mock.ANY))

    @mock.patch('openstack.connect', autospec=True)
    @mock.patch.object(openstack.connection, 'Connection', autospec=True)
    def test__get_ctlplane_attrs_no_network(self, mock_conn, mock_connect):
        mock_connect.return_value = mock_conn
        function = overcloud_deploy.DeployOvercloud._get_ctlplane_attrs

        mock_conn.network.find_network.return_value = None
        expected = dict()
        self.assertEqual(expected, function(mock.ANY))

    @mock.patch('openstack.connect', autospec=True)
    @mock.patch.object(openstack.connection, 'Connection', autospec=True)
    def test__get_ctlplane_attrs(self, mock_conn, mock_connect):
        mock_connect.return_value = mock_conn
        function = overcloud_deploy.DeployOvercloud._get_ctlplane_attrs

        fake_network = fakes.FakeNeutronNetwork(
            name='net_name',
            mtu=1440,
            dns_domain='ctlplane.localdomain.',
            tags=[],
            subnet_ids=['subnet_id'])
        fake_subnet = fakes.FakeNeutronSubnet(
            id='subnet_id',
            name='subnet_name',
            cidr='192.168.24.0/24',
            gateway_ip='192.168.24.1',
            host_routes=[
                {'destination': '192.168.25.0/24', 'nexthop': '192.168.24.1'}],
            dns_nameservers=['192.168.24.254'],
            ip_version=4
        )
        mock_conn.network.find_network.return_value = fake_network
        mock_conn.network.get_subnet.return_value = fake_subnet
        expected = {
            'network': {
                'dns_domain': 'ctlplane.localdomain.',
                'mtu': 1440,
                'name': 'net_name',
                'tags': []},
            'subnets': {
                'subnet_name': {
                    'cidr': '192.168.24.0/24',
                    'dns_nameservers': ['192.168.24.254'],
                    'gateway_ip': '192.168.24.1',
                    'host_routes': [{'destination': '192.168.25.0/24',
                                     'nexthop': '192.168.24.1'}],
                    'ip_version': 4,
                    'name': 'subnet_name'}
            }
        }
        self.assertEqual(expected, function(mock.ANY))


class TestArgumentValidation(fakes.TestDeployOvercloud):

    def setUp(self):
        super(TestArgumentValidation, self).setUp()

        def is_dir(arg):
            if arg == '/tmp/real_dir':
                return True
            else:
                return False

        patcher = mock.patch('os.path.isdir')
        mock_isdir = patcher.start()
        mock_isdir.side_effect = is_dir
        self.addCleanup(patcher.stop)

        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.validate = overcloud_deploy.DeployOvercloud(
            self.app, app_args)._validate_args_environment_directory

    def test_validate_env_dir(self):
        self.assertIsNone(self.validate(['/tmp/real_dir']))

    def test_validate_env_dir_empty(self):
        self.assertIsNone(self.validate([]))

    def test_validate_env_dir_not_a_real_directory(self):
        self.assertRaises(oscexc.CommandError,
                          self.validate,
                          ['/tmp/not_a_real_dir'])

    def test_validate_env_dir_ignore_default_not_existing(self):
        full_path = os.path.expanduser(constants.DEFAULT_ENV_DIRECTORY)
        self.assertIsNone(self.validate([full_path]))


class TestGetDeploymentStatus(utils.TestCommand):

    def setUp(self):
        super(TestGetDeploymentStatus, self).setUp()
        self.cmd = overcloud_deploy.GetDeploymentStatus(self.app, None)
        self.app.client_manager = mock.Mock()

    @mock.patch("tripleoclient.workflows.deployment.get_deployment_status")
    def test_get_deployment_status(self, mock_get_deployment_status):
        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.app.stdout = six.StringIO()
        status = 'DEPLOY_SUCCESS'
        mock_get_deployment_status.return_value = status

        self.cmd.take_action(parsed_args)

        expected = (
            '+------------+-------------------+\n'
            '| Stack Name | Deployment Status |\n'
            '+------------+-------------------+\n'
            '| overcloud  |   DEPLOY_SUCCESS  |\n'
            '+------------+-------------------+\n')

        self.assertEqual(expected, self.cmd.app.stdout.getvalue())
