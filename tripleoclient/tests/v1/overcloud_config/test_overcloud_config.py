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

import mock

from mock import call
from osc_lib.tests import utils

from tripleoclient.tests.v1.overcloud_config import fakes
from tripleoclient.v1 import overcloud_config


class TestOvercloudConfig(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudConfig, self).setUp()

        self.cmd = overcloud_config.DownloadConfig(self.app, None)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.app.client_manager.orchestration = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine

    @mock.patch('os.mkdir')
    @mock.patch('six.moves.builtins.open')
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_overcloud_config_generate_config(self, mock_tmpdir,
                                              mock_open, mock_mkdir):

        arglist = ['--name', 'overcloud', '--config-dir', '/tmp']
        verifylist = [
            ('name', 'overcloud'),
            ('config_dir', '/tmp')
        ]
        config_type_list = ['config_settings', 'global_config_settings',
                            'logging_sources', 'monitoring_subscriptions',
                            'service_config_settings',
                            'service_metadata_settings',
                            'service_names', 'step_config',
                            'upgrade_batch_tasks', 'upgrade_tasks']
        fake_role = [role for role in
                     fakes.FAKE_STACK['outputs'][0]['output_value']]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_tmpdir.return_value = "/tmp/tht"
        self.cmd.take_action(parsed_args)
        expected_mkdir_calls = [call('/tmp/tht/%s' % r) for r in fake_role]
        mock_mkdir.assert_has_calls(expected_mkdir_calls, any_order=True)
        expected_calls = []
        for config in config_type_list:
            for role in fake_role:
                if config == 'step_config':
                    expected_calls += [call('/tmp/tht/%s/%s.pp' %
                                            (role, config), 'w')]
                else:
                    expected_calls += [call('/tmp/tht/%s/%s.yaml' %
                                            (role, config), 'w')]
        mock_open.assert_has_calls(expected_calls, any_order=True)

    @mock.patch('os.mkdir')
    @mock.patch('six.moves.builtins.open')
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_overcloud_config_one_config_type(self, mock_tmpdir,  mock_open,
                                              mock_mkdir):

        arglist = ['--name', 'overcloud', '--config-dir', '/tmp',
                   '--config-type', ['config_settings']]
        verifylist = [
            ('name', 'overcloud'),
            ('config_dir', '/tmp'),
            ('config_type', ['config_settings'])
        ]
        expected_config_type = 'config_settings'
        fake_role = [role for role in
                     fakes.FAKE_STACK['outputs'][0]['output_value']]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_tmpdir.return_value = "/tmp/tht"
        self.cmd.take_action(parsed_args)
        expected_mkdir_calls = [call('/tmp/tht/%s' % r) for r in fake_role]
        mock_mkdir.assert_has_calls(expected_mkdir_calls, any_order=True)
        expected_calls = [call('/tmp/tht/%s/%s.yaml'
                          % (r, expected_config_type), 'w')
                          for r in fake_role]
        mock_open.assert_has_calls(expected_calls, any_order=True)

    @mock.patch('os.mkdir')
    @mock.patch('six.moves.builtins.open')
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_overcloud_config_wrong_config_type(self, mock_tmpdir,
                                                mock_open, mock_mkdir):

        arglist = [
            '--name', 'overcloud',
            '--config-dir',
            '/tmp', '--config-type', ['bad_config']]
        verifylist = [
            ('name', 'overcloud'),
            ('config_dir', '/tmp'),
            ('config_type', ['bad_config'])
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        clients = self.app.client_manager
        mock_tmpdir.return_value = "/tmp/tht"
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        self.assertRaises(
            KeyError,
            self.cmd.take_action, parsed_args)

    @mock.patch('tripleoclient.utils.get_role_data', autospec=True)
    @mock.patch('os.mkdir')
    @mock.patch('six.moves.builtins.open')
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_overcloud_config_upgrade_tasks(self, mock_tmpdir,
                                            mock_open,
                                            mock_mkdir,
                                            mock_get_role_data):

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        orchestration_client.stacks.get.return_value = fakes.create_tht_stack()
        mock_tmpdir.return_value = "/tmp/tht"
        fake_role = [role for role in
                     fakes.FAKE_STACK['outputs'][0]['output_value']]
        fake_playbook = {'FakeController': [{'hosts': 'FakeController',
                                             'name': 'FakeController playbook',
                                             'tasks': [{'name': 'Stop fake '
                                                                'service',
                                                        'service':
                                                        'name=fake '
                                                        'state=stopped',
                                                        'tags': 'step1'}]
                                             }],
                         'FakeCompute': [{'hosts': 'FakeCompute',
                                          'name': 'FakeCompute playbook',
                                          'tasks': [{'name': 'Stop fake '
                                                             'service',
                                                     'service':
                                                     'name=fake state=stopped',
                                                     'tags': 'step1'},
                                                    {'name': 'Stop nova-'
                                                             'compute service',
                                                     'service':
                                                     'name=openstack-nova-'
                                                     'compute state=stopped',
                                                     'tags': 'step1'}]
                                          }]
                         }
        mock_get_role_data.return_value = fake_role

        for role in fake_role:
            playbook = self.cmd._convert_playbook(fakes.
                                                  FAKE_STACK['outputs']
                                                            [0]
                                                            ['output_value']
                                                            [role]
                                                            ['upgrade_tasks'],
                                                  role)
            self.assertEqual(fake_playbook[role], playbook)
