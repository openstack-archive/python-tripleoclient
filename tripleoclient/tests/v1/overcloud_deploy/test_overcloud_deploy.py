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
import six
import tempfile
import yaml

from heatclient import exc as hc_exc
import mock
from osc_lib import exceptions as oscexc
from swiftclient.exceptions import ClientException as ObjectClientException

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient.tests.v1.overcloud_deploy import fakes
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
        self.real_predeploy_verify_capabilities = \
            self.cmd._predeploy_verify_capabilities
        self.cmd._predeploy_verify_capabilities = validator_mock

        self.parameter_defaults_env_file = (
            tempfile.NamedTemporaryFile(mode='w', delete=False).name)
        self.tmp_dir = self.useFixture(fixtures.TempDir())

    def tearDown(self):
        super(TestDeployOvercloud, self).tearDown()
        os.unlink(self.parameter_defaults_env_file)

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch("heatclient.common.event_utils.get_events")
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_create_parameters_env', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.remove_known_hosts', autospec=True)
    @mock.patch('tripleoclient.utils.wait_for_stack_ready',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('tripleoclient.utils.check_hypervisor_stats',
                autospec=True)
    @mock.patch('uuid.uuid1', autospec=True)
    @mock.patch('time.time', autospec=True)
    @mock.patch('shutil.copytree', autospec=True)
    def test_tht_scale(self, mock_copy, mock_time, mock_uuid1,
                       mock_check_hypervisor_stats,
                       mock_get_template_contents,
                       wait_for_stack_ready_mock,
                       mock_remove_known_hosts,
                       mock_write_overcloudrc,
                       mock_create_tempest_deployer_input,
                       mock_deploy_postconfig,
                       mock_create_parameters_env,
                       mock_breakpoints_cleanupm,
                       mock_events, mock_tarball):

        arglist = ['--templates', '--ceph-storage-scale', '3']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('ceph_storage_scale', 3)
        ]

        mock_uuid1.return_value = "uuid"
        mock_time.return_value = 123456789

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_event = mock.Mock()
        mock_event.id = '1234'
        mock_events.return_value = [mock_events]
        workflow_client = clients.workflow_engine
        workflow_client.environments.get.return_value = mock.MagicMock(
            variables={'environments': []})
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        mock_check_hypervisor_stats.return_value = {
            'count': 4,
            'memory_mb': 4096,
            'vcpus': 8,
        }
        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_get_template_contents.return_value = [{}, "template"]
        wait_for_stack_ready_mock.return_value = True

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)

        expected_parameters = {
            'CephClusterFSID': 'uuid',
            'CephStorageCount': 3,
            'ExtraConfig': '{}',
            'HypervisorNeutronPhysicalBridge': 'br-ex',
            'HypervisorNeutronPublicInterface': 'nic1',
            'NeutronDnsmasqOptions': 'dhcp-option-force=26,1400',
            'NeutronFlatNetworks': 'datacentre',
            'NeutronPublicInterface': 'nic1',
            'NtpServer': '',
            'SnmpdReadonlyUserPassword': 'PASSWORD',
            'DeployIdentifier': 123456789,
            'UpdateIdentifier': '',
            'StackAction': 'UPDATE',
        }

        testcase = self

        def _custom_create_params_env(self, parameters):
            for key, value in six.iteritems(parameters):
                testcase.assertEqual(value, expected_parameters[key])
            parameter_defaults = {"parameter_defaults": parameters}
            return parameter_defaults

        mock_create_parameters_env.side_effect = _custom_create_params_env

        self.cmd.take_action(parsed_args)

        self.assertFalse(orchestration_client.stacks.update.called)

        mock_get_template_contents.assert_called_with(
            object_request=mock.ANY,
            template_object=constants.OVERCLOUD_YAML_NAME)

        mock_create_tempest_deployer_input.assert_called_with()

    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_validate_args')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_create_parameters_env', autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.remove_known_hosts', autospec=True)
    @mock.patch('tripleoclient.utils.wait_for_stack_ready',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('tripleoclient.utils.check_hypervisor_stats',
                autospec=True)
    @mock.patch('uuid.uuid1', autospec=True)
    @mock.patch('time.time', autospec=True)
    @mock.patch('shutil.copytree', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_tht_deploy(self, mock_tmpdir, mock_copy, mock_time,
                        mock_uuid1,
                        mock_check_hypervisor_stats,
                        mock_get_template_contents,
                        wait_for_stack_ready_mock,
                        mock_remove_known_hosts,
                        mock_write_overcloudrc,
                        mock_create_tempest_deployer_input,
                        mock_create_parameters_env, mock_validate_args,
                        mock_breakpoints_cleanup, mock_tarball,
                        mock_postconfig, mock_get_overcloud_endpoint):

        arglist = ['--templates', '--ceph-storage-scale', '3']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('ceph_storage_scale', 3)
        ]

        mock_tmpdir.return_value = "/tmp/tht"
        mock_uuid1.return_value = "uuid"
        mock_time.return_value = 123456789

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack()
        orchestration_client.stacks.get.side_effect = [None, mock.Mock()]
        workflow_client = clients.workflow_engine
        workflow_client.environments.get.return_value = mock.MagicMock(
            variables={'environments': []})
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        def _orch_clt_create(**kwargs):
            orchestration_client.stacks.get.return_value = mock_stack

        orchestration_client.stacks.create.side_effect = _orch_clt_create

        mock_check_hypervisor_stats.return_value = {
            'count': 4,
            'memory_mb': 4096,
            'vcpus': 8,
        }
        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_get_template_contents.return_value = [{}, "template"]
        wait_for_stack_ready_mock.return_value = True

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)

        expected_parameters = {
            'CephClusterFSID': 'uuid',
            'CephStorageCount': 3,
            'ExtraConfig': '{}',
            'HypervisorNeutronPhysicalBridge': 'br-ex',
            'HypervisorNeutronPublicInterface': 'nic1',
            'NeutronDnsmasqOptions': 'dhcp-option-force=26,1400',
            'NeutronFlatNetworks': 'datacentre',
            'NeutronNetworkType': 'gre',
            'NeutronPublicInterface': 'nic1',
            'NeutronTunnelTypes': 'gre',
            'NtpServer': '',
            'SnmpdReadonlyUserPassword': 'PASSWORD',
            'DeployIdentifier': 123456789,
            'UpdateIdentifier': '',
            'StackAction': 'CREATE',
        }

        testcase = self

        def _custom_create_params_env(self, parameters):
            for key, value in six.iteritems(parameters):
                testcase.assertEqual(value, expected_parameters[key])
            parameter_defaults = {"parameter_defaults": parameters}
            return parameter_defaults

        mock_create_parameters_env.side_effect = _custom_create_params_env

        self.cmd.take_action(parsed_args)

        self.assertFalse(orchestration_client.stacks.create.called)

        mock_get_template_contents.assert_called_with(
            object_request=mock.ANY,
            template_object=constants.OVERCLOUD_YAML_NAME)

        mock_create_tempest_deployer_input.assert_called_with()

        mock_validate_args.assert_called_once_with(parsed_args)

        mock_tarball.create_tarball.assert_called_with(
            '/tmp/tht/tripleo-heat-templates', mock.ANY)
        mock_tarball.tarball_extract_to_swift_container.assert_called_with(
            clients.tripleoclient.object_store, mock.ANY, 'overcloud')

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch("heatclient.common.event_utils.get_events", autospec=True)
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.remove_known_hosts', autospec=True)
    @mock.patch('tripleoclient.utils.wait_for_stack_ready',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('tripleoclient.utils.check_hypervisor_stats',
                autospec=True)
    @mock.patch('shutil.copytree', autospec=True)
    def test_deploy_custom_templates(self, mock_copy,
                                     mock_check_hypervisor_stats,
                                     mock_get_template_contents,
                                     wait_for_stack_ready_mock,
                                     mock_remove_known_hosts,
                                     mock_write_overcloudrc,
                                     mock_create_tempest_deployer_input,
                                     mock_deploy_postconfig,
                                     mock_breakpoints_cleanup,
                                     mock_events, mock_tarball):

        arglist = ['--templates', '/home/stack/tripleo-heat-templates']
        verifylist = [
            ('templates', '/home/stack/tripleo-heat-templates'),
        ]

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_events.return_value = []

        mock_check_hypervisor_stats.return_value = {
            'count': 4,
            'memory_mb': 4096,
            'vcpus': 8,
        }
        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_get_template_contents.return_value = [{}, "template"]
        wait_for_stack_ready_mock.return_value = True

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)

        workflow_client = clients.workflow_engine
        workflow_client.environments.get.return_value = mock.MagicMock(
            variables={'environments': []})
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        with mock.patch('tempfile.mkstemp') as mkstemp:
            mkstemp.return_value = (os.open(self.parameter_defaults_env_file,
                                            os.O_RDWR),
                                    self.parameter_defaults_env_file)
            self.cmd.take_action(parsed_args)

        self.assertFalse(orchestration_client.stacks.update.called)

        mock_get_template_contents.assert_called_with(
            object_request=mock.ANY,
            template_object=constants.OVERCLOUD_YAML_NAME)

        mock_create_tempest_deployer_input.assert_called_with()

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    def test_missing_sat_url(self, mock_deploy_tht):

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
        self.assertRaises(exceptions.DeploymentError,
                          self.cmd.take_action,
                          parsed_args)
        self.assertFalse(mock_deploy_tht.called)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    def test_jinja2_env_path(self, mock_deploy_tht):

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

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.utils.check_nodes_count', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_update_parameters', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    @mock.patch('shutil.copytree', autospec=True)
    def test_environment_dirs(self, mock_copy, mock_deploy_heat,
                              mock_update_parameters, mock_post_config,
                              mock_utils_check_nodes, mock_utils_endpoint,
                              mock_utils_createrc, mock_utils_tempest,
                              mock_tarball):

        clients = self.app.client_manager
        workflow_client = clients.workflow_engine
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        mock_update_parameters.return_value = {}
        mock_utils_endpoint.return_value = 'foo.bar'

        test_env = os.path.join(self.tmp_dir.path, 'foo1.yaml')

        env_dirs = [os.path.join(os.environ.get('HOME', ''), '.tripleo',
                    'environments'), self.tmp_dir.path]

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
                              parameters, environments, timeout, tht_root,
                              env, update_plan_only, run_validations):
            assertEqual(
                {'parameter_defaults': {},
                 'resource_registry': {
                     'Test': 'OS::Heat::None',
                     'resources': {'*': {'*': {
                         'UpdateDeployment': {'hooks': []}}}}}}, env)

        mock_deploy_heat.side_effect = _fake_heat_deploy

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.utils.get_stack', autospec=True)
    @mock.patch('tripleoclient.utils.check_nodes_count', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_update_parameters', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    @mock.patch('shutil.copytree', autospec=True)
    def test_environment_dirs_env(self, mock_copy, mock_deploy_heat,
                                  mock_update_parameters, mock_post_config,
                                  mock_utils_check_nodes, mock_utils_get_stack,
                                  mock_utils_endpoint, mock_utils_createrc,
                                  mock_utils_tempest, mock_tarball):

        clients = self.app.client_manager
        workflow_client = clients.workflow_engine
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        mock_update_parameters.return_value = {}
        mock_utils_get_stack.return_value = None
        mock_utils_endpoint.return_value = 'foo.bar'

        test_env = self.tmp_dir.join('foo2.yaml')

        with open(test_env, 'w') as temp_file:
            temp_file.write('resource_registry:\n  Test: OS::Heat::None')

        arglist = ['--templates', '--update-plan-only']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]
        self.useFixture(
            fixtures.EnvironmentVariable('TRIPLEO_ENVIRONMENT_DIRECTORY',
                                         self.tmp_dir.path))

        def assertEqual(*args):
            self.assertEqual(*args)

        def _fake_heat_deploy(self, stack, stack_name, template_path,
                              parameters, environments, timeout, tht_root,
                              env, update_plan_only, run_validations):
            # Should be no breakpoint cleanup because utils.get_stack = None
            assertEqual(
                {'parameter_defaults': {},
                 'resource_registry': {'Test': u'OS::Heat::None'}}, env)

        mock_deploy_heat.side_effect = _fake_heat_deploy

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.utils.check_nodes_count', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_update_parameters', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    @mock.patch('shutil.copytree', autospec=True)
    def test_environment_dirs_env_files_not_found(self, mock_copy,
                                                  mock_deploy_heat,
                                                  mock_update_parameters,
                                                  mock_post_config,
                                                  mock_utils_check_nodes,
                                                  mock_utils_endpoint,
                                                  mock_utils_createrc,
                                                  mock_utils_tempest,
                                                  mock_tarball):

        clients = self.app.client_manager
        workflow_client = clients.workflow_engine
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        mock_update_parameters.return_value = {}
        mock_utils_endpoint.return_value = 'foo.bar'
        os.mkdir(self.tmp_dir.join('env'))
        os.mkdir(self.tmp_dir.join('common'))

        test_env = self.tmp_dir.join('env/foo2.yaml')

        with open(test_env, 'w') as temp_file:
            temp_file.write('resource_registry:\n  '
                            'Test1: ../common/bar.yaml\n  '
                            'Test2: /tmp/doesnexit.yaml')

        test_sub_env = self.tmp_dir.join('common/bar.yaml')
        with open(test_sub_env, 'w') as temp_file:
            temp_file.write('outputs:\n  data:\n    value: 1')

        arglist = ['--templates']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]
        self.useFixture(
            fixtures.EnvironmentVariable('TRIPLEO_ENVIRONMENT_DIRECTORY',
                                         self.tmp_dir.join('env')))

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        error = self.assertRaises(hc_exc.CommandError, self.cmd.take_action,
                                  parsed_args)
        self.assertIn('tmp/doesnexit.yaml', str(error))

    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    @mock.patch('shutil.copytree', autospec=True)
    def test_rhel_reg_params_provided(self, mock_copytree, mock_deploy_tht,
                                      mock_oc_endpoint,
                                      mock_create_ocrc,
                                      mock_create_tempest_deployer_input):

        clients = self.app.client_manager
        workflow_client = clients.workflow_engine
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

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
        self.assertTrue(mock_create_ocrc.called)

        mock_create_tempest_deployer_input.assert_called_with()

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch("heatclient.common.event_utils.get_events", autospec=True)
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.remove_known_hosts', autospec=True)
    @mock.patch('tripleoclient.utils.wait_for_stack_ready',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('tripleoclient.utils.check_hypervisor_stats',
                autospec=True)
    @mock.patch('shutil.copytree', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    @mock.patch('shutil.rmtree', autospec=True)
    def test_deploy_rhel_reg(self, mock_rmtree, mock_tmpdir, mock_copy,
                             mock_check_hypervisor_stats,
                             mock_get_template_contents,
                             mock_process_env,
                             wait_for_stack_ready_mock,
                             mock_remove_known_hosts,
                             mock_write_overcloudrc,
                             mock_create_tempest_deployer_input,
                             mock_deploy_postconfig,
                             mock_breakpoints_cleanup,
                             mock_events, mock_tarball):

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

        mock_tmpdir.return_value = None
        mock_tmpdir.return_value = '/tmp/tht'
        mock_process_env.return_value = [{}, fakes.create_env()]
        mock_get_template_contents.return_value = [{}, "template"]
        wait_for_stack_ready_mock.return_value = True

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_events.return_value = []
        workflow_client = clients.workflow_engine
        workflow_client.environments.get.return_value = mock.MagicMock(
            variables={'environments': []})
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        mock_check_hypervisor_stats.return_value = {
            'count': 4,
            'memory_mb': 4096,
            'vcpus': 8,
        }
        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)

        self.cmd.take_action(parsed_args)

        tht_prefix = ('/tmp/tht/tripleo-heat-templates/extraconfig/'
                      'pre_deploy/rhel-registration/')
        calls = [
            mock.call(env_path=tht_prefix +
                      'rhel-registration-resource-registry.yaml'), ]
        mock_process_env.assert_has_calls(calls)

    @mock.patch('tripleoclient.tests.v1.overcloud_deploy.fakes.'
                'FakeObjectClient.get_object', autospec=True)
    def test_validate_args_missing_environment_files(self, mock_obj):
        arglist = ['--templates',
                   '-e', 'nonexistent.yaml']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('environment_files', ['nonexistent.yaml']),
        ]

        mock_obj.side_effect = ObjectClientException(mock.Mock(
                                                     '/fake/path not found'))
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
            '/fake/path', {}, 'overcloud', {}, ['~/overcloud-env.json'], 1,
            {}, False, True)
        # If it returns None it succeeded
        self.assertIsNone(result)
        mock_heat_deploy_func.assert_called_once_with(
            self.cmd, {}, 'overcloud',
            '/fake/path/' + constants.OVERCLOUD_YAML_NAME, {},
            ['~/overcloud-env.json'], 1, '/fake/path', {}, False, True)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_try_overcloud_deploy_with_no_templates_existing(
            self, mock_heat_deploy_func):
        mock_heat_deploy_func.side_effect = ObjectClientException('error')
        self.assertRaises(ValueError,
                          self.cmd._try_overcloud_deploy_with_compat_yaml,
                          '/fake/path', mock.ANY, mock.ANY, mock.ANY,
                          mock.ANY, mock.ANY, mock.ANY, mock.ANY, mock.ANY)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_try_overcloud_deploy_show_missing_file(
            self, mock_heat_deploy_func):
        mock_heat_deploy_func.side_effect = \
            ObjectClientException('/fake/path not found')
        try:
            self.cmd._try_overcloud_deploy_with_compat_yaml(
                '/fake/path', mock.ANY, mock.ANY, mock.ANY,
                mock.ANY, mock.ANY, mock.ANY, mock.ANY, mock.ANY)
        except ValueError as value_error:
            self.assertIn('/fake/path', str(value_error))

    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    def test_dry_run(self, mock_deploy_tht,
                     mock_oc_endpoint,
                     mock_create_ocrc,
                     mock_create_tempest_deployer_input):

        arglist = ['--templates', '--dry-run']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('dry_run', True),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)
        self.assertFalse(mock_deploy_tht.called)
        self.assertFalse(mock_create_ocrc.called)
        self.assertFalse(mock_create_tempest_deployer_input.called)

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleoclient.utils.check_nodes_count',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    @mock.patch('shutil.copytree', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    @mock.patch('shutil.rmtree', autospec=True)
    def test_answers_file(self, mock_rmtree, mock_tmpdir, mock_copy,
                          mock_heat_deploy,
                          mock_oc_endpoint,
                          mock_create_ocrc,
                          mock_create_tempest_deployer_input,
                          mock_check_nodes_count, mock_tarball):
        clients = self.app.client_manager

        workflow_client = clients.workflow_engine
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

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
                   '--block-storage-scale', '3',
                   '--disable-password-generation']
        verifylist = [
            ('answers_file', test_answerfile),
            ('environment_files', [test_env2]),
            ('block_storage_scale', 3),
            ('disable_password_generation', True)]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self.assertTrue(mock_heat_deploy.called)
        self.assertTrue(mock_create_ocrc.called)
        self.assertTrue(mock_create_tempest_deployer_input.called)

        # Check that Heat was called with correct parameters:
        call_args = mock_heat_deploy.call_args[0]
        self.assertEqual(call_args[3],
                         self.tmp_dir.join(
                             'tripleo-heat-templates/overcloud.yaml'))
        self.assertEqual(call_args[7],
                         self.tmp_dir.join('tripleo-heat-templates'))
        self.assertIn('Test', call_args[8]['resource_registry'])
        self.assertIn('Test2', call_args[8]['resource_registry'])
        self.assertEqual(
            3, call_args[8]['parameter_defaults']['BlockStorageCount'])

        mock_create_tempest_deployer_input.assert_called_with()

    @mock.patch('tripleoclient.utils.check_nodes_count')
    @mock.patch('tripleoclient.utils.check_hypervisor_stats')
    @mock.patch('tripleoclient.utils.assign_and_verify_profiles')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_get_default_role_counts')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_check_ironic_boot_configuration')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_collect_flavors')
    def test_predeploy_verify_capabilities_hypervisor_stats(
            self, mock_collect_flavors,
            mock_check_ironic_boot_configuration,
            mock_get_default_role_counts,
            mock_assign_and_verify_profiles,
            mock_check_hypervisor_stats,
            mock_check_nodes_count):
        self.cmd._predeploy_verify_capabilities = \
            self.real_predeploy_verify_capabilities

        stack = None
        parameters = {}
        parsed_args = mock.Mock()
        mock_assign_and_verify_profiles.return_value = (0, 0)
        mock_check_nodes_count.return_value = (True, 0, 0)

        # A None return value here indicates an error
        mock_check_hypervisor_stats.return_value = None
        self.cmd._predeploy_verify_capabilities(
            stack, parameters, parsed_args)
        self.assertEqual(1, self.cmd.predeploy_errors)

    def test_get_default_role_counts_defaults(self):
        parsed_args = mock.Mock()
        parsed_args.roles_file = None
        defaults = {
            'ControllerCount': 1,
            'ComputeCount': 1,
            'ObjectStorageCount': 0,
            'BlockStorageCount': 0,
            'CephStorageCount': 0
        }
        self.assertEqual(
            defaults,
            self.cmd._get_default_role_counts(parsed_args))

    @mock.patch("yaml.safe_load")
    @mock.patch("six.moves.builtins.open")
    def test_get_default_role_counts_custom_roles(self, mock_open,
                                                  mock_safe_load):
        parsed_args = mock.Mock()
        roles_data = [
            {'name': 'ControllerApi', 'CountDefault': 3},
            {'name': 'ControllerPcmk', 'CountDefault': 3},
            {'name': 'Compute', 'CountDefault': 3},
            {'name': 'ObjectStorage', 'CountDefault': 0},
            {'name': 'BlockStorage'}
        ]
        mock_safe_load.return_value = roles_data
        role_counts = {
            'ControllerApiCount': 3,
            'ControllerPcmkCount': 3,
            'ComputeCount': 3,
            'ObjectStorageCount': 0,
            'BlockStorageCount': 0,
        }
        self.assertEqual(
            role_counts,
            self.cmd._get_default_role_counts(parsed_args))

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_create_parameters_env')
    @mock.patch('tripleoclient.utils.write_overcloudrc')
    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('shutil.copytree', autospec=True)
    def test_ntp_server_mandatory(self, mock_copy,
                                  mock_get_template_contents,
                                  mock_process_env,
                                  mock_write_overcloudrc,
                                  mock_create_parameters_env,
                                  mock_tarball):

        arglist = ['--templates', '--control-scale', '3']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('control_scale', 3)
        ]

        clients = self.app.client_manager
        workflow_client = clients.workflow_engine
        workflow_client.environments.get.return_value = mock.MagicMock(
            variables={'environments': []})
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        def _custom_create_params_env(parameters):
            parameter_defaults = {"parameter_defaults": parameters}
            return parameter_defaults

        mock_create_parameters_env.side_effect = _custom_create_params_env

        mock_env = fakes.create_env()
        mock_process_env.return_value = [{}, mock_env]
        mock_get_template_contents.return_value = [{}, "template"]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaises(exceptions.InvalidConfiguration,
                          self.cmd.take_action,
                          parsed_args)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_validate_args')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_create_parameters_env')
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc')
    @mock.patch('tripleoclient.utils.remove_known_hosts', autospec=True)
    @mock.patch('tripleoclient.utils.wait_for_stack_ready',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('tripleoclient.utils.check_hypervisor_stats',
                autospec=True)
    @mock.patch('uuid.uuid1', autospec=True)
    @mock.patch('time.time', autospec=True)
    @mock.patch('shutil.copytree', autospec=True)
    def test_tht_deploy_with_ntp(self, mock_copy, mock_time,
                                 mock_uuid1,
                                 mock_check_hypervisor_stats,
                                 mock_get_template_contents,
                                 mock_process_env,
                                 wait_for_stack_ready_mock,
                                 mock_remove_known_hosts,
                                 mock_write_overcloudrc,
                                 mock_create_tempest_deployer_input,
                                 mock_create_parameters_env,
                                 mock_validate_args,
                                 mock_breakpoints_cleanup,
                                 mock_tarball,
                                 mock_deploy_post_config):

        arglist = ['--templates', '--ceph-storage-scale', '3',
                   '--control-scale', '3', '--ntp-server', 'ntp']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('ceph_storage_scale', 3),
            ('control_scale', 3),
        ]

        mock_uuid1.return_value = "uuid"
        mock_time.return_value = 123456789

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack()
        orchestration_client.stacks.get.side_effect = [
            None,
            mock.MagicMock()
        ]

        def _orch_clt_create(**kwargs):
            orchestration_client.stacks.get.return_value = mock_stack

        orchestration_client.stacks.create.side_effect = _orch_clt_create

        workflow_client = clients.workflow_engine
        workflow_client.environments.get.return_value = mock.MagicMock(
            variables={'environments': []})
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        mock_check_hypervisor_stats.return_value = {
            'count': 4,
            'memory_mb': 4096,
            'vcpus': 8,
        }
        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_env = fakes.create_env_with_ntp()
        mock_process_env.return_value = [{}, mock_env]
        mock_get_template_contents.return_value = [{}, "template"]
        wait_for_stack_ready_mock.return_value = True

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)

        expected_parameters = {
            'CephClusterFSID': 'uuid',
            'CephStorageCount': 3,
            'ControllerCount': 3,
            'ExtraConfig': '{}',
            'HypervisorNeutronPhysicalBridge': 'br-ex',
            'HypervisorNeutronPublicInterface': 'nic1',
            'NeutronDnsmasqOptions': 'dhcp-option-force=26,1400',
            'NeutronFlatNetworks': 'datacentre',
            'NeutronNetworkType': 'gre',
            'NeutronPublicInterface': 'nic1',
            'NeutronTunnelTypes': 'gre',
            'SnmpdReadonlyUserPassword': 'PASSWORD',
            'DeployIdentifier': 123456789,
            'UpdateIdentifier': '',
            'StackAction': 'CREATE',
            'NtpServer': 'ntp',
        }

        def _custom_create_params_env(parameters):
            for key, value in six.iteritems(parameters):
                self.assertEqual(value, expected_parameters[key])
            parameter_defaults = {"parameter_defaults": parameters}
            return parameter_defaults

        mock_create_parameters_env.side_effect = _custom_create_params_env

        self.cmd.take_action(parsed_args)

        mock_get_template_contents.assert_called_with(
            object_request=mock.ANY,
            template_object=constants.OVERCLOUD_YAML_NAME)

        mock_create_tempest_deployer_input.assert_called_with()

        mock_validate_args.assert_called_once_with(parsed_args)

    @mock.patch('tripleoclient.workflows.deployment.deploy_and_wait',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_process_and_upload_environment', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_upload_missing_files', autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('os.path.relpath', autospec=True)
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env',
                autospec=True)
    def test_heat_deploy_update_plan_only(self, mock_breakpoints_cleanup,
                                          mock_relpath,
                                          mock_get_template_contents,
                                          mock_upload_missing_files,
                                          mock_process_and_upload_env,
                                          mock_deploy_and_wait):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack()
        orchestration_client.stacks.get.side_effect = [
            None,
            mock.MagicMock()
        ]

        workflow_client = clients.workflow_engine
        workflow_client.environments.get.return_value = mock.MagicMock(
            variables={'environments': []})
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        mock_relpath.return_value = './'

        mock_get_template_contents.return_value = [{}, {}]

        self.cmd._heat_deploy(mock_stack, 'mock_stack', '/tmp', {},
                              {}, 1, '/tmp', {}, True, False)

        self.assertFalse(mock_deploy_and_wait.called)

    def test_heat_stack_busy(self):

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack(stack_status="IN_PROGRESS")
        orchestration_client.stacks.get.return_value = mock_stack

        arglist = ['--templates', ]
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaises(exceptions.StackInProgress,
                          self.cmd.take_action, parsed_args)

    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.overcloudrc',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates_tmpdir', autospec=True)
    def test_disable_validations_true(
            self, mock_deploy_tmpdir,
            mock_overcloudrc, mock_write_overcloudrc,
            mock_overcloud_endpoint):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = mock.Mock()

        arglist = ['--templates', '--disable-validations']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        self.assertNotCalled(self.cmd._predeploy_verify_capabilities)

    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.overcloudrc',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates_tmpdir', autospec=True)
    def test_disable_validations_false(
            self, mock_deploy_tmpdir,
            mock_overcloudrc, mock_write_overcloudrc,
            mock_overcloud_endpoint):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = mock.Mock()

        arglist = ['--templates']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        self.assertTrue(self.cmd._predeploy_verify_capabilities.called)

    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.overcloudrc',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates_tmpdir', autospec=True)
    def test_validations_failure_raises_exception(
            self, mock_deploy_tmpdir,
            mock_overcloudrc, mock_write_overcloudrc,
            mock_overcloud_endpoint):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = mock.Mock()
        self.cmd._predeploy_verify_capabilities = mock.Mock(
            return_value=(1, 0))

        arglist = ['--templates']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaises(exceptions.InvalidConfiguration,
                          self.cmd.take_action, parsed_args)
