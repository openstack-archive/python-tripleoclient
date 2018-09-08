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

import mock

from osc_lib.tests.utils import ParserException
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient.tests.v1.overcloud_ffwd_upgrade import fakes
from tripleoclient.v1 import overcloud_ffwd_upgrade


class TestFFWDUpgradePrepare(fakes.TestFFWDUpgradePrepare):

    def setUp(self):
        super(TestFFWDUpgradePrepare, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_ffwd_upgrade.FFWDUpgradePrepare(self.app,
                                                             app_args)
        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch('tripleoclient.workflows.deployment.overcloudrc',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.prepend_environment', autospec=True)
    @mock.patch('tripleoclient.utils.get_stack',
                autospec=True)
    @mock.patch(
        'tripleoclient.v1.overcloud_ffwd_upgrade.FFWDUpgradePrepare.log',
        autospec=True)
    @mock.patch('tripleoclient.workflows.package_update.update',
                autospec=True)
    @mock.patch('os.path.abspath')
    @mock.patch('yaml.load')
    @mock.patch('shutil.copytree', autospec=True)
    @mock.patch('six.moves.builtins.open')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    def test_ffwd_upgrade(self,
                          mock_deploy,
                          mock_open,
                          mock_copy,
                          mock_yaml,
                          mock_abspath,
                          mock_ffwd_upgrade,
                          mock_logger,
                          mock_get_stack,
                          mock_prepend_env,
                          mock_write_overcloudrc,
                          mock_overcloudrc):

        mock_stack = mock.Mock()
        mock_stack.stack_name = 'mystack'
        mock_get_stack.return_value = mock_stack
        mock_yaml.return_value = {'fake_container': 'fake_value'}

        argslist = ['--stack', 'mystack', '--templates',
                    '--yes']
        verifylist = [
            ('stack', 'mystack'),
            ('templates', constants.TRIPLEO_HEAT_TEMPLATES),
            ('yes', True),
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        mock_ffwd_upgrade.assert_called_once_with(
            self.app.client_manager,
            container='mystack',
            ceph_ansible_playbook='/usr/share/ceph-ansible'
                                  '/site-docker.yml.sample',
        )

        mock_overcloudrc.assert_called_once_with(mock.ANY,
                                                 container="mystack")
        mock_write_overcloudrc.assert_called_once_with("mystack",
                                                       mock.ANY)

    @mock.patch('tripleoclient.utils.prepend_environment', autospec=True)
    @mock.patch('tripleoclient.workflows.package_update.update',
                autospec=True)
    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.abspath')
    @mock.patch('yaml.load')
    @mock.patch('shutil.copytree', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    def test_ffwd_upgrade_failed(
        self, mock_deploy, mock_copy, mock_yaml, mock_abspath, mock_open,
            mock_ffwd_upgrade, mock_prepend_env):
        mock_ffwd_upgrade.side_effect = exceptions.DeploymentError()
        mock_yaml.return_value = {'fake_container': 'fake_value'}
        argslist = ['--stack', 'overcloud', '--templates',
                    '--yes', ]
        verifylist = [
            ('stack', 'overcloud'),
            ('templates', constants.TRIPLEO_HEAT_TEMPLATES),
            ('yes', True),
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.assertRaises(exceptions.DeploymentError,
                          self.cmd.take_action, parsed_args)


class TestFFWDUpgradeRun(fakes.TestFFWDUpgradeRun):

    def setUp(self):
        super(TestFFWDUpgradeRun, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_ffwd_upgrade.FFWDUpgradeRun(self.app, app_args)

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_ffwd_upgrade_playbook(
            self, mock_open, mock_execute, mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--ssh-user', 'heat-admin', '--yes']
        verifylist = [('ssh_user', 'heat-admin'), ('yes', True), ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.cmd.take_action(parsed_args)
            upgrade_ansible.assert_called_once_with(
                self.app.client_manager,
                inventory_file=mock_open().read(),
                ansible_queue_name=constants.FFWD_UPGRADE_QUEUE,
                nodes='',
                playbook=constants.FFWD_UPGRADE_PLAYBOOK,
                node_user='heat-admin',
                skip_tags=''
            )

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_ffwd_upgrade_playbook_non_default_user(
            self, mock_open, mock_execute, mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--ssh-user', 'my-user', '--yes']
        verifylist = [('ssh_user', 'my-user'), ('yes', True), ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.cmd.take_action(parsed_args)
            upgrade_ansible.assert_called_once_with(
                self.app.client_manager,
                inventory_file=mock_open().read(),
                ansible_queue_name=constants.FFWD_UPGRADE_QUEUE,
                nodes='',
                playbook=constants.FFWD_UPGRADE_PLAYBOOK,
                node_user='my-user',
                skip_tags=''
            )

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_upgrade_no_nodes_or_roles(self, mock_open, mock_execute,
                                       mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ["--nodes", "controller-1", "--roles", "foo", "--yes"]
        verifylist = []
        self.assertRaises(ParserException, lambda: self.check_parser(
            self.cmd, argslist, verifylist))


class TestFFWDUpgradeConverge(fakes.TestFFWDUpgradeConverge):

    def setUp(self):
        super(TestFFWDUpgradeConverge, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_ffwd_upgrade.FFWDUpgradeConverge(self.app,
                                                              app_args)

    @mock.patch(
        'tripleoclient.v1.overcloud_deploy.DeployOvercloud.take_action')
    def test_ffwd_upgrade_converge(self, deploy_action):
        argslist = ['--stack', 'le_overcloud', '--templates', '--yes']
        verifylist = [
            ('stack', 'le_overcloud'),
            ('templates', constants.TRIPLEO_HEAT_TEMPLATES),
            ('yes', True)
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        with mock.patch('os.path.exists') as mock_exists, \
                mock.patch('os.path.isfile') as mock_isfile:
            mock_exists.return_value = True
            mock_isfile.return_value = True
            self.cmd.take_action(parsed_args)
            assert('/usr/share/openstack-tripleo-heat-templates/'
                   'environments/lifecycle/ffwd-upgrade-converge.yaml'
                   in parsed_args.environment_files)
            deploy_action.assert_called_once_with(parsed_args)
