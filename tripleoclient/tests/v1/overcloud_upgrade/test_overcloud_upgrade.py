#   Copyright 2018 Red Hat, Inc.
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

from unittest import mock

from osc_lib.tests.utils import ParserException
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient.tests.v1.overcloud_upgrade import fakes
from tripleoclient.v1 import overcloud_upgrade


class TestOvercloudUpgradePrepare(fakes.TestOvercloudUpgradePrepare):

    def setUp(self):
        super(TestOvercloudUpgradePrepare, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_upgrade.UpgradePrepare(self.app, app_args)

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch('tripleoclient.utils.ensure_run_as_normal_user')
    @mock.patch('tripleoclient.utils.prompt_user_for_confirmation',
                return_value=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'take_action')
    @mock.patch('tripleoclient.workflows.deployment.'
                'get_hosts_and_enable_ssh_admin', autospec=True)
    @mock.patch('tripleoclient.utils.prepend_environment', autospec=True)
    @mock.patch('tripleoclient.utils.get_stack')
    @mock.patch('tripleoclient.v1.overcloud_upgrade.UpgradePrepare.log',
                autospec=True)
    @mock.patch('yaml.safe_load')
    @mock.patch('builtins.open')
    def test_upgrade_out(self,
                         mock_open,
                         mock_yaml,
                         mock_logger,
                         mock_get_stack,
                         add_env,
                         mock_enable_ssh_admin,
                         mock_overcloud_deploy,
                         mock_confirm,
                         mock_usercheck):

        mock_stack = mock.Mock(parameters={'DeployIdentifier': ''})
        mock_get_stack.return_value = mock_stack
        mock_stack.stack_name = 'overcloud'
        mock_yaml.return_value = {'fake_container': 'fake_value'}
        add_env = mock.Mock()
        add_env.return_value = True
        argslist = ['--stack', 'overcloud', '--templates',
                    '--overcloud-ssh-enable-timeout', '10',
                    '--overcloud-ssh-port-timeout', '10']
        verifylist = [
            ('stack', 'overcloud'),
            ('templates', constants.TRIPLEO_HEAT_TEMPLATES),
            ('overcloud_ssh_enable_timeout', 10),
            ('overcloud_ssh_port_timeout', 10),
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.working_dir = mock.Mock()
        self.cmd.take_action(parsed_args)
        mock_usercheck.assert_called_once()

        mock_overcloud_deploy.assert_called_once_with(parsed_args)
        args, kwargs = mock_overcloud_deploy.call_args
        # Check config_download arg is set to False
        self.assertEqual(args[0].stack_only, True)
        mock_enable_ssh_admin.assert_called_once_with(
            parsed_args.stack,
            parsed_args.overcloud_ssh_network,
            parsed_args.overcloud_ssh_user,
            mock.ANY,
            parsed_args.overcloud_ssh_port_timeout,
            self.cmd.working_dir,
            mock.ANY,
            'pod'
        )

    @mock.patch('tripleoclient.utils.ensure_run_as_normal_user')
    @mock.patch('tripleoclient.utils.prompt_user_for_confirmation',
                return_value=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'take_action')
    @mock.patch('tripleoclient.utils.get_stack')
    @mock.patch('tripleoclient.utils.prepend_environment', autospec=True)
    @mock.patch('builtins.open')
    @mock.patch('yaml.safe_load')
    def test_upgrade_failed(self, mock_yaml, mock_open,
                            add_env, mock_get_stack, mock_overcloud_deploy,
                            mock_confirm, mock_usercheck):
        mock_overcloud_deploy.side_effect = exceptions.DeploymentError()
        mock_yaml.return_value = {'fake_container': 'fake_value'}
        mock_stack = mock.Mock(parameters={'DeployIdentifier': ''})
        mock_stack.stack_name = 'overcloud'
        mock_get_stack.return_value = mock_stack
        add_env = mock.Mock()
        add_env.return_value = True
        argslist = ['--stack', 'overcloud', '--templates', ]
        verifylist = [
            ('stack', 'overcloud'),
            ('templates', constants.TRIPLEO_HEAT_TEMPLATES),
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.assertRaises(exceptions.DeploymentError,
                          self.cmd.take_action, parsed_args)
        mock_usercheck.assert_called_once()
        mock_overcloud_deploy.assert_called_once_with(parsed_args)


class TestOvercloudUpgradeRun(fakes.TestOvercloudUpgradeRun):

    def setUp(self):
        super(TestOvercloudUpgradeRun, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_upgrade.UpgradeRun(self.app, app_args)

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('builtins.open')
    def test_upgrade_limit_with_playbook_and_user(
            self, mock_open, mock_execute, mock_expanduser):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--limit', 'Compute, Controller',
                    '--playbook', 'fake-playbook1.yaml',
                    'fake-playbook2.yaml', '--ssh-user', 'tripleo-admin']
        verifylist = [
            ('limit', 'Compute, Controller'),
            ('static_inventory', None),
            ('playbook', ['fake-playbook1.yaml', 'fake-playbook2.yaml'])
        ]

        self.check_parser(self.cmd, argslist, verifylist)

    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('builtins.open')
    def test_upgrade_nodes_with_playbook_no_skip_tags(
            self, mock_open, mock_execute, mock_expanduser):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--limit', 'compute-0,compute-1',
                    '--playbook', 'fake-playbook.yaml', ]
        verifylist = [
            ('limit', 'compute-0,compute-1'),
            ('static_inventory', None),
            ('playbook', ['fake-playbook.yaml']),
        ]

        self.check_parser(self.cmd, argslist, verifylist)

    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('builtins.open')
    def test_upgrade_with_no_limit(
            self, mock_open, mock_execute, mock_expanduser):
        mock_expanduser.return_value = '/home/fake/'
        argslist = []
        verifylist = []
        self.assertRaises(ParserException, lambda: self.check_parser(
            self.cmd, argslist, verifylist))
