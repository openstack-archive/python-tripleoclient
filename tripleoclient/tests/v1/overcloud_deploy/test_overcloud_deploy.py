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

from heatclient import exc as hc_exc
import mock
from osc_lib import exceptions as oscexc
from osc_lib.tests import utils
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

        self.parameter_defaults_env_file = (
            tempfile.NamedTemporaryFile(mode='w', delete=False).name)
        self.tmp_dir = self.useFixture(fixtures.TempDir())

        # Mock the history command to avoid leaking files
        history_patcher = mock.patch('tripleoclient.utils.store_cli_param',
                                     autospec=True)
        history_patcher.start()
        self.addCleanup(history_patcher.stop)

        # Mock this function to avoid file creation
        self.real_download_missing = self.cmd._download_missing_files_from_plan
        self.cmd._download_missing_files_from_plan = mock.Mock()

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

    def tearDown(self):
        super(TestDeployOvercloud, self).tearDown()
        os.unlink(self.parameter_defaults_env_file)
        self.cmd._download_missing_files_from_plan = self.real_download_missing
        shutil.rmtree = self.real_shutil

    @mock.patch('tripleoclient.workflows.deployment.get_overcloud_hosts')
    @mock.patch('tripleoclient.workflows.deployment.enable_ssh_admin')
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch(
        'tripleoclient.workflows.plan_management.list_deployment_plans',
        autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.get_horizon_url',
                autospec=True)
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
    def test_tht_scale(self, mock_get_template_contents,
                       wait_for_stack_ready_mock,
                       mock_remove_known_hosts,
                       mock_write_overcloudrc,
                       mock_create_tempest_deployer_input,
                       mock_deploy_postconfig,
                       mock_create_parameters_env,
                       mock_breakpoints_cleanupm,
                       mock_events, mock_tarball,
                       mock_get_horizon_url,
                       mock_list_plans,
                       mock_config_download,
                       mock_enable_ssh_admin,
                       mock_get_overcloud_hosts):
        arglist = ['--templates', '--ceph-storage-scale', '3']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('ceph_storage_scale', 3)
        ]

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_event = mock.Mock()
        mock_event.id = '1234'
        mock_events.return_value = [mock_events]
        mock_list_plans.return_value = []
        workflow_client = clients.workflow_engine
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        object_client = clients.tripleoclient.object_store
        object_client.get_object = mock.Mock()
        mock_env = yaml.safe_dump({'environments': []})
        object_client.get_object.return_value = ({}, mock_env)

        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_get_template_contents.return_value = [{}, "template"]
        wait_for_stack_ready_mock.return_value = True

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
            'DeployIdentifier': self.time_value,
            'UpdateIdentifier': '',
            'StackAction': 'UPDATE',
            'DeployIdentifier': '',
        }

        def _custom_create_params_env(_self, parameters, tht_root,
                                      container_name):
            for key, value in six.iteritems(parameters):
                self.assertEqual(value, expected_parameters[key])
            parameter_defaults = {"parameter_defaults": parameters}
            return parameter_defaults

        mock_create_parameters_env.side_effect = _custom_create_params_env

        self.cmd.take_action(parsed_args)

        self.assertFalse(orchestration_client.stacks.update.called)

        mock_get_template_contents.assert_called_with(
            object_request=mock.ANY,
            template_object=constants.OVERCLOUD_YAML_NAME)

        mock_create_tempest_deployer_input.assert_called_with()

    @mock.patch('tripleoclient.workflows.deployment.get_overcloud_hosts')
    @mock.patch('tripleoclient.workflows.deployment.enable_ssh_admin')
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch(
        'tripleoclient.workflows.plan_management.list_deployment_plans',
        autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.get_horizon_url',
                autospec=True)
    @mock.patch('tripleoclient.workflows.parameters.invoke_plan_env_workflows',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_validate_args')
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.remove_known_hosts', autospec=True)
    @mock.patch('tripleoclient.utils.wait_for_stack_ready',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_tht_deploy(self, mock_tmpdir,
                        mock_get_template_contents,
                        wait_for_stack_ready_mock,
                        mock_remove_known_hosts,
                        mock_write_overcloudrc,
                        mock_create_tempest_deployer_input,
                        mock_validate_args,
                        mock_breakpoints_cleanup, mock_tarball,
                        mock_postconfig, mock_get_overcloud_endpoint,
                        mock_invoke_plan_env_wf,
                        mock_get_horizon_url,
                        mock_list_plans,
                        mock_config_download,
                        mock_enable_ssh_admin,
                        mock_get_overcloud_hosts):

        arglist = ['--templates', '--ceph-storage-scale', '3',
                   '--control-flavor', 'oooq_control', '--no-cleanup']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('ceph_storage_scale', 3)
        ]

        mock_tmpdir.return_value = self.tmp_dir.path

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack()
        orchestration_client.stacks.get.side_effect = [None, mock.Mock()]
        mock_list_plans.return_value = []
        workflow_client = clients.workflow_engine
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        object_client = clients.tripleoclient.object_store
        object_client.get_object = mock.Mock()
        mock_env = yaml.safe_dump({'environments': []})
        object_client.get_object.return_value = ({}, mock_env)

        def _orch_clt_create(**kwargs):
            orchestration_client.stacks.get.return_value = mock_stack

        orchestration_client.stacks.create.side_effect = _orch_clt_create

        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_get_template_contents.return_value = [{}, "template"]
        wait_for_stack_ready_mock.return_value = True

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)

        parameters_env = {
            'parameter_defaults': {
                'CephStorageCount': 3,
                'OvercloudControlFlavor': 'oooq_control',
                'OvercloudControllerFlavor': 'oooq_control',
                'StackAction': 'CREATE',
                'UpdateIdentifier': '',
                'DeployIdentifier': ''}}

        mock_rm = shutil.rmtree = mock.MagicMock()
        self.cmd.take_action(parsed_args)
        mock_rm.assert_not_called()

        self.assertFalse(orchestration_client.stacks.create.called)

        mock_get_template_contents.assert_called_with(
            object_request=mock.ANY,
            template_object=constants.OVERCLOUD_YAML_NAME)

        mock_create_tempest_deployer_input.assert_called_with()

        mock_validate_args.assert_called_once_with(parsed_args)

        mock_tarball.create_tarball.assert_called_with(
            self.tmp_dir.join('tripleo-heat-templates'), mock.ANY)
        mock_tarball.tarball_extract_to_swift_container.assert_called_with(
            clients.tripleoclient.object_store, mock.ANY, 'overcloud')
        self.assertFalse(mock_invoke_plan_env_wf.called)

        calls = [
            mock.call('overcloud',
                      'user-environments/tripleoclient-parameters.yaml',
                      yaml.safe_dump(parameters_env,
                                     default_flow_style=False)),
            mock.call('overcloud',
                      'user-environment.yaml',
                      yaml.safe_dump({}, default_flow_style=False)),
            mock.call('overcloud',
                      'plan-environment.yaml',
                      yaml.safe_dump({'environments':
                                      [{'path': 'user-environment.yaml'}]},
                                     default_flow_style=False))]

        object_client = clients.tripleoclient.object_store
        object_client.put_object.assert_has_calls(calls)
        tmp_param_env = self.tmp_dir.join(
            'tripleo-heat-templates',
            'user-environments/tripleoclient-parameters.yaml')
        self.assertTrue(os.path.isfile(tmp_param_env))
        with open(tmp_param_env, 'r') as f:
            env_map = yaml.safe_load(f)
        self.assertEqual(env_map.get('parameter_defaults'),
                         parameters_env.get('parameter_defaults'))

    @mock.patch('tripleoclient.workflows.deployment.get_overcloud_hosts')
    @mock.patch('tripleoclient.workflows.deployment.enable_ssh_admin')
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch(
        'tripleoclient.workflows.plan_management.list_deployment_plans',
        autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.get_horizon_url',
                autospec=True)
    @mock.patch('tripleoclient.workflows.parameters.invoke_plan_env_workflows',
                autospec=True)
    @mock.patch('shutil.rmtree', autospec=True)
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
    @mock.patch('tripleoclient.workflows.deployment.create_overcloudrc',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.remove_known_hosts', autospec=True)
    @mock.patch('tripleoclient.utils.wait_for_stack_ready',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_tht_deploy_with_plan_environment_file(
            self, mock_tmpdir, mock_get_template_contents,
            wait_for_stack_ready_mock,
            mock_remove_known_hosts, mock_overcloudrc, mock_write_overcloudrc,
            mock_create_tempest_deployer, mock_create_parameters_env,
            mock_validate_args,
            mock_breakpoints_cleanup,
            mock_tarball, mock_postconfig,
            mock_get_overcloud_endpoint, mock_shutil_rmtree,
            mock_invoke_plan_env_wf, mock_get_horizon_url,
            mock_list_plans, mock_config_download,
            mock_enable_ssh_admin,
            mock_get_overcloud_hosts):

        arglist = ['--templates', '-p', 'the-plan-environment.yaml']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('plan_environment_file', 'the-plan-environment.yaml')
        ]

        mock_tmpdir.return_value = "/tmp/tht"

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack()
        orchestration_client.stacks.get.side_effect = [None, mock.Mock()]
        mock_list_plans.return_value = []
        workflow_client = clients.workflow_engine
        workflow_client.environments.get.return_value = mock.MagicMock(
            variables={'environments': []})
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        def _orch_clt_create(**kwargs):
            orchestration_client.stacks.get.return_value = mock_stack

        orchestration_client.stacks.create.side_effect = _orch_clt_create

        object_client = clients.tripleoclient.object_store
        object_client.get_object = mock.Mock()
        mock_env = yaml.safe_dump({'environments': []})
        object_client.get_object.return_value = ({}, mock_env)

        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_get_template_contents.return_value = [{}, "template"]
        wait_for_stack_ready_mock.return_value = True

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
            'NeutronNetworkType': 'gre',
            'NeutronPublicInterface': 'nic1',
            'NeutronTunnelTypes': 'gre',
            'NtpServer': '',
            'SnmpdReadonlyUserPassword': 'PASSWORD',
            'DeployIdentifier': self.time_value,
            'UpdateIdentifier': '',
            'StackAction': 'CREATE',
            'DeployIdentifier': '',
        }

        testcase = self

        def _custom_create_params_env(_self, parameters, tht_root,
                                      container_name):
            for key, value in six.iteritems(parameters):
                testcase.assertEqual(value, expected_parameters[key])
            parameter_defaults = {"parameter_defaults": parameters}
            return parameter_defaults

        mock_create_parameters_env.side_effect = _custom_create_params_env

        mock_open_context = mock.mock_open()

        with mock.patch('six.moves.builtins.open', mock_open_context):
            self.cmd.take_action(parsed_args)

        self.assertFalse(orchestration_client.stacks.create.called)

        mock_get_template_contents.assert_called_with(
            object_request=mock.ANY,
            template_object=constants.OVERCLOUD_YAML_NAME)

        mock_create_tempest_deployer.assert_called_with()
        mock_validate_args.assert_called_once_with(parsed_args)

        mock_tarball.create_tarball.assert_called_with(
            '/tmp/tht/tripleo-heat-templates', mock.ANY)
        mock_tarball.tarball_extract_to_swift_container.assert_called_with(
            clients.tripleoclient.object_store, mock.ANY, 'overcloud')

        workflow_client.action_executions.create.assert_called()
        workflow_client.executions.create.assert_called()

        mock_open_context.assert_has_calls(
            [mock.call('the-plan-environment.yaml')])
        clients.tripleoclient.object_store.put_object.assert_called()
        self.assertTrue(mock_invoke_plan_env_wf.called)

    @mock.patch('tripleoclient.workflows.deployment.get_overcloud_hosts')
    @mock.patch('tripleoclient.workflows.deployment.enable_ssh_admin')
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch(
        'tripleoclient.workflows.plan_management.list_deployment_plans',
        autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.get_horizon_url',
                autospec=True)
    @mock.patch('tripleoclient.workflows.parameters.'
                'check_deprecated_parameters', autospec=True)
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
    @mock.patch('shutil.rmtree', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_tht_deploy_skip_deploy_identifier(
            self, mock_tmpdir, mock_rm,
            mock_get_template_contents,
            wait_for_stack_ready_mock,
            mock_remove_known_hosts,
            mock_write_overcloudrc,
            mock_create_tempest_deployer_input,
            mock_create_parameters_env, mock_validate_args,
            mock_breakpoints_cleanup, mock_tarball,
            mock_postconfig, mock_get_overcloud_endpoint,
            mock_deprecated_params, mock_get_horizon_url,
            mock_list_plans, mock_config_downlad,
            mock_enable_ssh_admin,
            mock_get_overcloud_hosts):

        arglist = ['--templates', '--skip-deploy-identifier']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('skip_deploy_identifier', True)
        ]

        mock_tmpdir.return_value = "/tmp/tht"

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack()
        orchestration_client.stacks.get.side_effect = [None, mock.Mock()]
        mock_list_plans.return_value = []
        workflow_client = clients.workflow_engine
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        def _orch_clt_create(**kwargs):
            orchestration_client.stacks.get.return_value = mock_stack

        orchestration_client.stacks.create.side_effect = _orch_clt_create

        object_client = clients.tripleoclient.object_store
        object_client.get_object = mock.Mock()
        mock_env = yaml.safe_dump({'environments': []})
        object_client.get_object.return_value = ({}, mock_env)

        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }
        mock_get_template_contents.return_value = [{}, "template"]
        wait_for_stack_ready_mock.return_value = True

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)

        testcase = self

        def _custom_create_params_env(_self, parameters, tht_root,
                                      container_name):
            testcase.assertTrue(parameters['DeployIdentifier'] == '')
            parameter_defaults = {"parameter_defaults": parameters}
            return parameter_defaults

        mock_create_parameters_env.side_effect = _custom_create_params_env

        mock_rm = shutil.rmtree = mock.MagicMock()
        self.cmd.take_action(parsed_args)
        mock_rm.assert_called_once()
        execution_calls = workflow_client.executions.create.call_args_list
        deploy_plan_call = execution_calls[1]
        deploy_plan_call_input = deploy_plan_call[1]['workflow_input']
        self.assertTrue(deploy_plan_call_input['skip_deploy_identifier'])

    @mock.patch('tripleoclient.workflows.deployment.get_overcloud_hosts')
    @mock.patch('tripleoclient.workflows.deployment.enable_ssh_admin')
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch(
        'tripleoclient.workflows.plan_management.list_deployment_plans',
        autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.get_horizon_url',
                autospec=True)
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
    def test_deploy_custom_templates(self, mock_get_template_contents,
                                     wait_for_stack_ready_mock,
                                     mock_remove_known_hosts,
                                     mock_write_overcloudrc,
                                     mock_create_tempest_deployer_input,
                                     mock_deploy_postconfig,
                                     mock_breakpoints_cleanup,
                                     mock_events, mock_tarball,
                                     mock_get_horizon_url,
                                     mock_list_plans,
                                     mock_config_download,
                                     mock_enable_ssh_admin,
                                     mock_get_overcloud_hosts):

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
        wait_for_stack_ready_mock.return_value = True

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)

        mock_list_plans.return_value = []
        workflow_client = clients.workflow_engine
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        object_client = clients.tripleoclient.object_store
        object_client.get_object = mock.Mock()
        mock_env = yaml.safe_dump({'environments': []})
        object_client.get_object.return_value = ({}, mock_env)

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

    @mock.patch('tripleoclient.workflows.deployment.get_overcloud_hosts')
    @mock.patch('tripleoclient.workflows.deployment.enable_ssh_admin')
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch(
        'tripleoclient.workflows.plan_management.list_deployment_plans',
        autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.get_horizon_url',
                autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_update_parameters', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_environment_dirs(self, mock_deploy_heat,
                              mock_update_parameters, mock_post_config,
                              mock_utils_endpoint, mock_utils_createrc,
                              mock_utils_tempest, mock_tarball,
                              mock_get_horizon_url, mock_list_plans,
                              mock_config_download,
                              mock_enable_ssh_admin,
                              mock_get_overcloud_hosts):

        clients = self.app.client_manager
        mock_list_plans.return_value = []
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
                              env, update_plan_only, run_validations,
                              skip_deploy_identifier, plan_env_file):
            assertEqual(
                {'parameter_defaults': {'NovaComputeLibvirtType': 'qemu'},
                 'resource_registry': {
                     'Test': 'OS::Heat::None',
                     'resources': {'*': {'*': {
                         'UpdateDeployment': {'hooks': []}}}}}}, env)

        mock_deploy_heat.side_effect = _fake_heat_deploy
        object_client = clients.tripleoclient.object_store
        object_client.get_object = mock.Mock()
        mock_env = yaml.safe_dump({'parameter_defaults':
                                  {'NovaComputeLibvirtType': 'qemu'}})
        object_client.get_object.return_value = ({}, mock_env)

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

    @mock.patch(
        'tripleoclient.workflows.plan_management.list_deployment_plans',
        autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.utils.get_stack', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_update_parameters', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_environment_dirs_env(self, mock_deploy_heat,
                                  mock_update_parameters, mock_post_config,
                                  mock_utils_get_stack, mock_utils_endpoint,
                                  mock_utils_createrc, mock_utils_tempest,
                                  mock_tarball, mock_list_plans):

        clients = self.app.client_manager
        mock_list_plans.return_value = []
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
                              env, update_plan_only, run_validations,
                              skip_deploy_identifier, plan_env_file):
            # Should be no breakpoint cleanup because utils.get_stack = None
            assertEqual(
                {'parameter_defaults': {},
                 'resource_registry': {'Test': u'OS::Heat::None'}}, env)

        mock_deploy_heat.side_effect = _fake_heat_deploy

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

    @mock.patch(
        'tripleoclient.workflows.plan_management.list_deployment_plans',
        autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_update_parameters', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_environment_dirs_env_files_not_found(self, mock_deploy_heat,
                                                  mock_update_parameters,
                                                  mock_post_config,
                                                  mock_utils_endpoint,
                                                  mock_utils_createrc,
                                                  mock_utils_tempest,
                                                  mock_tarball,
                                                  mock_list_plans):

        clients = self.app.client_manager
        mock_list_plans.return_value = []
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

        object_client = clients.tripleoclient.object_store
        object_client.get_object = mock.Mock()
        mock_env = yaml.safe_dump({'parameter_defaults':
                                  {'NovaComputeLibvirtType': 'qemu'}})
        object_client.get_object.return_value = ({}, mock_env)

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        error = self.assertRaises(hc_exc.CommandError, self.cmd.take_action,
                                  parsed_args)
        self.assertIn('tmp/doesnexit.yaml', str(error))

    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_update_parameters', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_environment_dirs_env_dir_not_found(self, mock_deploy_heat,
                                                mock_update_parameters,
                                                mock_post_config,
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

        arglist = ['--templates', '--environment-directory', '/tmp/notthere']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        error = self.assertRaises(oscexc.CommandError, self.cmd.take_action,
                                  parsed_args)
        self.assertIn('/tmp/notthere', str(error))

    @mock.patch('tripleoclient.workflows.deployment.get_overcloud_hosts')
    @mock.patch('tripleoclient.workflows.deployment.enable_ssh_admin')
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch('tripleoclient.workflows.deployment.get_horizon_url',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    def test_rhel_reg_params_provided(self, mock_deploy_tht,
                                      mock_oc_endpoint,
                                      mock_create_ocrc,
                                      mock_create_tempest_deployer_input,
                                      mock_get_horizon_url,
                                      mock_config_download,
                                      mock_enable_ssh_admin,
                                      mock_get_overcloud_hosts):

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

    @mock.patch('tripleoclient.workflows.deployment.get_overcloud_hosts')
    @mock.patch('tripleoclient.workflows.deployment.enable_ssh_admin')
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch(
        'tripleoclient.workflows.plan_management.list_deployment_plans',
        autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.get_horizon_url',
                autospec=True)
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
    @mock.patch('tempfile.mkdtemp', autospec=True)
    @mock.patch('shutil.rmtree', autospec=True)
    def test_deploy_rhel_reg(self, mock_rmtree,
                             mock_tmpdir,
                             mock_get_template_contents,
                             wait_for_stack_ready_mock,
                             mock_remove_known_hosts,
                             mock_write_overcloudrc,
                             mock_create_tempest_deployer_input,
                             mock_deploy_postconfig,
                             mock_breakpoints_cleanup,
                             mock_events, mock_tarball,
                             mock_get_horizon_url,
                             mock_list_plans,
                             mock_config_download,
                             mock_enable_ssh_admin,
                             mock_get_overcloud_hosts):

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

        mock_tmpdir.return_value = self.tmp_dir.path
        test_env = self.tmp_dir.join(
            'tripleo-heat-templates/extraconfig/pre_deploy/rhel-registration/'
            'rhel-registration-resource-registry.yaml')
        os.makedirs(os.path.dirname(test_env))
        with open(test_env, 'w') as temp_file:
            temp_file.write('resource_registry:\n  Test: OS::Heat::None')
        mock_get_template_contents.return_value = [{}, "template"]
        wait_for_stack_ready_mock.return_value = True

        bp_cleanup_env = {'resource_registry': {'Cleanup': 'OS::Heat::None'}}

        def _fake_bp_cleanup(env):
            env.update(bp_cleanup_env)

        mock_breakpoints_cleanup.side_effect = _fake_bp_cleanup

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_events.return_value = []
        mock_list_plans.return_value = []
        workflow_client = clients.workflow_engine
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        object_client = clients.tripleoclient.object_store
        object_client.get_object = mock.Mock()
        mock_env = yaml.safe_dump({'environments': []})
        object_client.get_object.return_value = ({}, mock_env)

        clients.network.api.find_attr.return_value = {
            "id": "network id"
        }

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        baremetal = clients.baremetal
        baremetal.node.list.return_value = range(10)

        self.cmd.take_action(parsed_args)

        user_env = {
            'environments': [],
            'resource_registry': {'Test': 'OS::Heat::None',
                                  'Cleanup': 'OS::Heat::None'}}
        parameters_env = {
            'parameter_defaults': {
                'StackAction': 'UPDATE',
                'UpdateIdentifier': '',
                'DeployIdentifier': ''}}
        reg_env = {
            'parameter_defaults': {
                'rhel_reg_activation_key': 'super-awesome-key',
                'rhel_reg_force': False,
                'rhel_reg_method': 'satellite',
                'rhel_reg_org': '123456789',
                'rhel_reg_sat_url': 'https://example.com'}}

        calls = [
            mock.call('overcloud',
                      'user-environments/tripleoclient-parameters.yaml',
                      yaml.safe_dump(parameters_env,
                                     default_flow_style=False)),
            mock.call('overcloud',
                      'user-environments/'
                      'tripleoclient-registration-parameters.yaml',
                      yaml.safe_dump(reg_env,
                                     default_flow_style=False)),
            mock.call('overcloud',
                      'user-environments/'
                      'tripleoclient-breakpoint-cleanup.yaml',
                      yaml.safe_dump(bp_cleanup_env,
                                     default_flow_style=False)),
            mock.call('overcloud',
                      'user-environment.yaml',
                      yaml.safe_dump(user_env,
                                     default_flow_style=False)),
            mock.call('overcloud',
                      'plan-environment.yaml',
                      yaml.safe_dump({'environments':
                                      [{'path': 'user-environment.yaml'}]},
                                     default_flow_style=False))]

        object_client = clients.tripleoclient.object_store
        object_client.put_object.assert_has_calls(calls)
        tmp_param_env = self.tmp_dir.join(
            'tripleo-heat-templates',
            'user-environments/tripleoclient-parameters.yaml')
        self.assertTrue(os.path.isfile(tmp_param_env))
        with open(tmp_param_env, 'r') as f:
            env_map = yaml.safe_load(f)
        self.assertEqual(env_map.get('parameter_defaults'),
                         parameters_env.get('parameter_defaults'))

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
            {}, False, True, False, None)
        # If it returns None it succeeded
        self.assertIsNone(result)
        mock_heat_deploy_func.assert_called_once_with(
            self.cmd, {}, 'overcloud',
            '/fake/path/' + constants.OVERCLOUD_YAML_NAME, {},
            ['~/overcloud-env.json'], 1, '/fake/path', {}, False, True, False,
            None)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_try_overcloud_deploy_with_no_templates_existing(
            self, mock_heat_deploy_func):
        mock_heat_deploy_func.side_effect = ObjectClientException('error')
        self.assertRaises(ValueError,
                          self.cmd._try_overcloud_deploy_with_compat_yaml,
                          '/fake/path', mock.ANY, mock.ANY, mock.ANY,
                          mock.ANY, mock.ANY, mock.ANY, mock.ANY, mock.ANY,
                          mock.ANY, None)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    def test_try_overcloud_deploy_show_missing_file(
            self, mock_heat_deploy_func):
        mock_heat_deploy_func.side_effect = \
            ObjectClientException('/fake/path not found')
        try:
            self.cmd._try_overcloud_deploy_with_compat_yaml(
                '/fake/path', mock.ANY, mock.ANY, mock.ANY,
                mock.ANY, mock.ANY, mock.ANY, mock.ANY, mock.ANY, mock.ANY,
                None)
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

    @mock.patch('tripleoclient.workflows.deployment.get_overcloud_hosts')
    @mock.patch('tripleoclient.workflows.deployment.enable_ssh_admin')
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch(
        'tripleoclient.workflows.plan_management.list_deployment_plans',
        autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.get_horizon_url',
                autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_heat_deploy', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    @mock.patch('shutil.rmtree', autospec=True)
    def test_answers_file(self, mock_rmtree, mock_tmpdir,
                          mock_heat_deploy,
                          mock_oc_endpoint,
                          mock_create_ocrc,
                          mock_create_tempest_deployer_input,
                          mock_tarball, mock_get_horizon_url,
                          mock_list_plans,
                          mock_config_download,
                          mock_enable_ssh_admin,
                          mock_get_overcloud_hosts):
        clients = self.app.client_manager

        mock_list_plans.return_value = []

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

        object_client = clients.tripleoclient.object_store
        object_client.get_object = mock.Mock()
        mock_env = yaml.safe_dump({'parameter_defaults':
                                  {'NovaComputeLibvirtType': 'qemu'}})
        object_client.get_object.return_value = ({}, mock_env)

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

    def test_get_default_role_counts_defaults(self):
        parsed_args = self.check_parser(self.cmd, [], [])
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

    @mock.patch("tripleoclient.utils.fetch_roles_file")
    def test_get_default_role_counts_custom_roles(self, mock_roles):
        roles_data = [
            {'name': 'ControllerApi', 'CountDefault': 3},
            {'name': 'ControllerPcmk', 'CountDefault': 3},
            {'name': 'Compute', 'CountDefault': 3},
            {'name': 'ObjectStorage', 'CountDefault': 0},
            {'name': 'BlockStorage'}
        ]
        mock_roles.return_value = roles_data
        role_counts = {
            'ControllerApiCount': 3,
            'ControllerPcmkCount': 3,
            'ComputeCount': 3,
            'ObjectStorageCount': 0,
            'BlockStorageCount': 0,
        }
        self.assertEqual(
            role_counts,
            self.cmd._get_default_role_counts(mock.Mock()))

    @mock.patch(
        'tripleoclient.workflows.plan_management.list_deployment_plans',
        autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_create_parameters_env', autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc')
    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', autospec=True)
    @mock.patch('heatclient.common.template_utils.get_template_contents',
                autospec=True)
    def test_ntp_server_mandatory(self, mock_get_template_contents,
                                  mock_process_env,
                                  mock_write_overcloudrc,
                                  mock_create_parameters_env,
                                  mock_tarball,
                                  mock_list_plans):

        arglist = ['--templates', '--control-scale', '3']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('control_scale', 3)
        ]

        clients = self.app.client_manager
        workflow_client = clients.workflow_engine
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')
        mock_list_plans.return_value = []

        object_client = clients.tripleoclient.object_store
        object_client.get_object = mock.Mock()
        mock_env = yaml.safe_dump({'environments': []})
        object_client.get_object.return_value = ({}, mock_env)

        def _custom_create_params_env(_self, parameters, tht_root,
                                      container_name):
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

    @mock.patch('tripleoclient.workflows.deployment.get_overcloud_hosts')
    @mock.patch('tripleoclient.workflows.deployment.enable_ssh_admin')
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch(
        'tripleoclient.workflows.plan_management.list_deployment_plans',
        autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.get_horizon_url',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_postconfig', autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleo_common.update.add_breakpoints_cleanup_into_env')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_validate_args')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_create_parameters_env', autospec=True)
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
    def test_tht_deploy_with_ntp(self, mock_get_template_contents,
                                 mock_process_env,
                                 wait_for_stack_ready_mock,
                                 mock_remove_known_hosts,
                                 mock_write_overcloudrc,
                                 mock_create_tempest_deployer_input,
                                 mock_create_parameters_env,
                                 mock_validate_args,
                                 mock_breakpoints_cleanup,
                                 mock_tarball,
                                 mock_deploy_post_config,
                                 mock_get_horizon_url,
                                 mock_list_plans,
                                 mock_config_download,
                                 mock_enable_ssh_admin,
                                 mock_get_overcloud_hosts):

        arglist = ['--templates', '--ceph-storage-scale', '3',
                   '--control-scale', '3', '--ntp-server', 'ntp']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('ceph_storage_scale', 3),
            ('control_scale', 3),
        ]

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

        mock_list_plans.return_value = []

        workflow_client = clients.workflow_engine
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        object_client = clients.tripleoclient.object_store
        object_client.get_object = mock.Mock()
        mock_env = yaml.safe_dump({'environments': []})
        object_client.get_object.return_value = ({}, mock_env)

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
            'CephClusterFSID': self.uuid1_value,
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
            'DeployIdentifier': self.time_value,
            'UpdateIdentifier': '',
            'StackAction': 'CREATE',
            'NtpServer': 'ntp',
            'DeployIdentifier': '',
        }

        def _custom_create_params_env(_self, parameters, tht_root,
                                      container_name):
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

    @mock.patch('tripleoclient.workflows.parameters.'
                'check_deprecated_parameters', autospec=True)
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
                                          mock_deploy_and_wait,
                                          mock_deprecated_params):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        mock_stack = fakes.create_tht_stack()
        orchestration_client.stacks.get.side_effect = [
            None,
            mock.MagicMock()
        ]

        workflow_client = clients.workflow_engine
        workflow_client.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')

        object_client = clients.tripleoclient.object_store
        object_client.get_object = mock.Mock()
        mock_env = yaml.safe_dump({'environments': []})
        object_client.get_object.return_value = ({}, mock_env)

        mock_relpath.return_value = './'

        mock_get_template_contents.return_value = [{}, {}]

        self.cmd.clients = {}

        self.cmd._heat_deploy(mock_stack, 'mock_stack', '/tmp', {},
                              {}, 1, '/tmp', {}, True, False, False, None)

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

    @mock.patch('tripleoclient.workflows.deployment.get_overcloud_hosts')
    @mock.patch('tripleoclient.workflows.deployment.enable_ssh_admin')
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch('tripleoclient.workflows.deployment.get_horizon_url',
                autospec=True)
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.wait_for_provision_state')
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.create_overcloudrc',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates_tmpdir', autospec=True)
    def test_deployed_server(self, mock_deploy_tmpdir, mock_overcloudrc,
                             mock_write_overcloudrc,
                             mock_get_overcloud_endpoint,
                             mock_provision, mock_tempest_deploy_input,
                             mock_get_horizon_url,
                             mock_config_download,
                             mock_enable_ssh_admin,
                             mock_get_overcloud_hosts):
        arglist = ['--templates', '--deployed-server', '--disable-validations']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('deployed_server', True),
            ('disable_validations', True),
        ]

        clients = self.app.client_manager
        clients.baremetal = mock.Mock()
        clients.compute = mock.Mock()
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = mock.Mock()
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)
        self.assertTrue(mock_deploy_tmpdir.called)
        self.assertNotCalled(mock_provision)
        self.assertNotCalled(clients.baremetal)
        self.assertNotCalled(clients.compute)
        self.assertTrue(mock_tempest_deploy_input.called)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    def test_fail_overcloud_deploy_with_deployed_server_and_validations(
            self, mock_deploy_tmpdir):
        arglist = ['--templates', '--deployed-server']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('deployed_server', True),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.assertRaises(oscexc.CommandError,
                          self.cmd.take_action,
                          parsed_args)
        self.assertFalse(mock_deploy_tmpdir.called)

    @mock.patch('tripleoclient.workflows.deployment.get_overcloud_hosts')
    @mock.patch('tripleoclient.workflows.deployment.enable_ssh_admin')
    @mock.patch('tripleoclient.workflows.deployment.get_horizon_url',
                autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.create_overcloudrc',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates_tmpdir', autospec=True)
    def test_config_download(
            self, mock_deploy_tmpdir,
            mock_overcloudrc, mock_write_overcloudrc,
            mock_overcloud_endpoint,
            mock_create_tempest_deployer_input,
            mock_config_download, mock_get_horizon_url,
            mock_enable_ssh_admin,
            mock_get_overcloud_hosts):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = mock.Mock()

        arglist = ['--templates', '--config-download']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('config_download', True),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        self.assertTrue(mock_deploy_tmpdir.called)
        self.assertTrue(mock_enable_ssh_admin.called)
        self.assertTrue(mock_get_overcloud_hosts.called)
        self.assertTrue(mock_config_download.called)

    @mock.patch('tripleoclient.workflows.deployment.get_overcloud_hosts')
    @mock.patch('tripleoclient.workflows.deployment.enable_ssh_admin')
    @mock.patch('tripleoclient.workflows.deployment.get_horizon_url',
                autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch('tripleoclient.utils.create_tempest_deployer_input',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_overcloud_endpoint', autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.create_overcloudrc',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates_tmpdir', autospec=True)
    def test_config_download_only(
            self, mock_deploy_tmpdir,
            mock_overcloudrc, mock_write_overcloudrc,
            mock_overcloud_endpoint,
            mock_create_tempest_deployer_input,
            mock_config_download, mock_get_horizon_url,
            mock_enable_ssh_admin,
            mock_get_overcloud_hosts):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = mock.Mock()

        arglist = ['--templates', '--config-download-only']
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
            ('config_download_only', True),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        self.assertFalse(mock_deploy_tmpdir.called)
        self.assertTrue(mock_enable_ssh_admin.called)
        self.assertTrue(mock_get_overcloud_hosts.called)
        self.assertTrue(mock_config_download.called)

    def test_download_missing_files_from_plan(self):
        # Restore the real function so we don't accidentally call the mock
        self.cmd._download_missing_files_from_plan = self.real_download_missing

        # Set up the client mocks
        self.cmd._setup_clients(mock.Mock())

        dirname = '/tmp/tht-missing'

        mock_open = mock.mock_open()
        mock_makedirs = mock.Mock()
        builtin_mod = six.moves.builtins.__name__

        with mock.patch('os.makedirs', mock_makedirs):
            with mock.patch('%s.open' % builtin_mod, mock_open):
                self.cmd._download_missing_files_from_plan(dirname,
                                                           'overcast')

        mock_makedirs.assert_called_with(dirname)
        mock_open.assert_called()


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
        self.clients = self.app.client_manager

    @mock.patch(
        'tripleoclient.workflows.deployment.get_deployment_status',
        autospec=True)
    def test_get_deployment_status(self, mock_get_deployment_status):
        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.app.stdout = six.StringIO()

        status = {
            'workflow_status': {
                'payload': {
                    'execution': {
                        'created_at': 'yesterday',
                        'updated_at': 'today'
                    },
                    'plan_name': 'testplan',
                    'deployment_status': 'SUCCESS'
                }
            }
        }

        mock_get_deployment_status.return_value = status

        self.cmd.take_action(parsed_args)

        expected = (
            '+-----------+-----------+---------+-------------------+\n'
            '| Plan Name |  Created  | Updated | Deployment Status |\n'
            '+-----------+-----------+---------+-------------------+\n'
            '|  testplan | yesterday |  today  |      SUCCESS      |\n'
            '+-----------+-----------+---------+-------------------+\n')

        self.assertEqual(expected, self.cmd.app.stdout.getvalue())


class TestGetDeploymentFailures(utils.TestCommand):

    def setUp(self):
        super(TestGetDeploymentFailures, self).setUp()
        self.cmd = overcloud_deploy.GetDeploymentFailures(self.app, None)
        self.app.client_manager = mock.Mock()
        self.clients = self.app.client_manager

    @mock.patch(
        'tripleoclient.workflows.deployment.get_deployment_failures',
        autospec=True)
    def test_plan_get_deployment_status(self, mock_get_deployment_failures):
        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.app.stdout = six.StringIO()

        failures = {
            'host0': [
                ['Task1', dict(key1=1, key2=2, key3=3)],
                ['Task2', dict(key4=4, key5=5, key3=5)]
            ],
            'host1': [
                ['Task1', dict(key1=1, key2=2, key3=['a', 'b', 'c'])]
            ],
        }

        mock_get_deployment_failures.return_value = failures

        self.cmd.take_action(parsed_args)

        expected = (
            '|-> Failures for host: host0\n'
            '|--> Task: Task1\n'
            '|---> key1: 1\n'
            '|---> key2: 2\n'
            '|---> key3: 3\n'
            '|--> Task: Task2\n'
            '|---> key3: 5\n'
            '|---> key4: 4\n'
            '|---> key5: 5\n'
            '\n'
            '|-> Failures for host: host1\n'
            '|--> Task: Task1\n'
            '|---> key1: 1\n'
            '|---> key2: 2\n'
            '|---> key3: [\n'
            '    "a",\n'
            '    "b",\n'
            '    "c"\n'
            ']\n\n')

        self.assertEqual(expected, self.cmd.app.stdout.getvalue())
