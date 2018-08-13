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

    @mock.patch('tripleoclient.workflows.deployment.create_overcloudrc',
                autospec=True)
    @mock.patch('tripleoclient.utils.write_overcloudrc', autospec=True)
    @mock.patch('tripleoclient.utils.prepend_environment', autospec=True)
    @mock.patch('tripleoclient.utils.get_stack',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_upgrade.UpgradePrepare.log',
                autospec=True)
    @mock.patch('tripleoclient.workflows.package_update.update',
                autospec=True)
    @mock.patch('os.path.abspath')
    @mock.patch('yaml.load')
    @mock.patch('shutil.copytree', autospec=True)
    @mock.patch('six.moves.builtins.open')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    def test_upgrade_out(self,
                         mock_deploy,
                         mock_open,
                         mock_copy,
                         mock_yaml,
                         mock_abspath,
                         mock_upgrade,
                         mock_logger,
                         mock_get_stack,
                         add_env,
                         mock_write_overcloudrc,
                         mock_overcloudrc):

        mock_stack = mock.Mock()
        mock_stack.stack_name = 'overcloud'
        mock_get_stack.return_value = mock_stack
        mock_yaml.return_value = {'fake_container': 'fake_value'}
        add_env = mock.Mock()
        add_env.return_value = True
        argslist = ['--stack', 'overcloud', '--templates', ]
        verifylist = [
            ('stack', 'overcloud'),
            ('templates', constants.TRIPLEO_HEAT_TEMPLATES),
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        mock_upgrade.assert_called_once_with(
            self.app.client_manager,
            container='overcloud',
        )

        mock_overcloudrc.assert_called_once_with(mock.ANY,
                                                 container="overcloud")
        mock_write_overcloudrc.assert_called_once_with("overcloud",
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
    def test_upgrade_failed(self, mock_deploy, mock_copy, mock_yaml,
                            mock_abspath, mock_open, mock_upgrade, add_env):
        mock_upgrade.side_effect = exceptions.DeploymentError()
        mock_yaml.return_value = {'fake_container': 'fake_value'}
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

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_upgrade_roles_with_playbook_and_user(
            self, mock_open, mock_execute, mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--roles', 'Compute, Controller',
                    '--playbook', 'fake-playbook.yaml',
                    '--ssh-user', 'tripleo-admin']
        verifylist = [
            ('roles', 'Compute, Controller'),
            ('static_inventory', None),
            ('playbook', 'fake-playbook.yaml')
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.cmd.take_action(parsed_args)
            upgrade_ansible.assert_called_once_with(
                self.app.client_manager,
                nodes='Compute, Controller',
                inventory_file=mock_open().read(),
                playbook='fake-playbook.yaml',
                ansible_queue_name=constants.UPGRADE_QUEUE,
                node_user='tripleo-admin',
                tags='',
                skip_tags=''
            )

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_upgrade_role_all_playbooks_skip_validation(
            self, mock_open, mock_execute, mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--roles', 'Compute', '--playbook', 'all',
                    '--skip-tags', 'validation']
        verifylist = [
            ('roles', 'Compute'),
            ('static_inventory', None),
            ('playbook', 'all'),
            ('skip_tags', 'validation')
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.cmd.take_action(parsed_args)
            for book in constants.MAJOR_UPGRADE_PLAYBOOKS:
                upgrade_ansible.assert_any_call(
                    self.app.client_manager,
                    nodes='Compute',
                    inventory_file=mock_open().read(),
                    playbook=book,
                    ansible_queue_name=constants.UPGRADE_QUEUE,
                    node_user='heat-admin',
                    tags='',
                    skip_tags='validation'
                )

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_upgrade_nodes_with_playbook_no_skip_tags(
            self, mock_open, mock_execute, mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--nodes', 'compute-0, compute-1',
                    '--playbook', 'fake-playbook.yaml', ]
        verifylist = [
            ('nodes', 'compute-0, compute-1'),
            ('static_inventory', None),
            ('playbook', 'fake-playbook.yaml'),
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.cmd.take_action(parsed_args)
            upgrade_ansible.assert_called_once_with(
                self.app.client_manager,
                nodes='compute-0, compute-1',
                inventory_file=mock_open().read(),
                playbook='fake-playbook.yaml',
                ansible_queue_name=constants.UPGRADE_QUEUE,
                node_user='heat-admin',
                tags='',
                skip_tags=''
            )

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_upgrade_node_all_playbooks_skip_tags_default(
            self, mock_open, mock_execute, mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--nodes', 'swift-1', '--playbook', 'all']
        verifylist = [
            ('nodes', 'swift-1'),
            ('static_inventory', None),
            ('playbook', 'all'),
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.cmd.take_action(parsed_args)
            for book in constants.MAJOR_UPGRADE_PLAYBOOKS:
                upgrade_ansible.assert_any_call(
                    self.app.client_manager,
                    nodes='swift-1',
                    inventory_file=mock_open().read(),
                    playbook=book,
                    ansible_queue_name=constants.UPGRADE_QUEUE,
                    node_user='heat-admin',
                    tags='',
                    skip_tags=''
                )

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_upgrade_node_all_playbooks_skip_tags_all_supported(
            self, mock_open, mock_execute, mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--nodes', 'swift-1', '--playbook', 'all',
                    '--skip-tags', 'pre-upgrade,validation']
        verifylist = [
            ('nodes', 'swift-1'),
            ('static_inventory', None),
            ('playbook', 'all'),
            ('skip_tags', 'pre-upgrade,validation')
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.cmd.take_action(parsed_args)
            for book in constants.MAJOR_UPGRADE_PLAYBOOKS:
                upgrade_ansible.assert_any_call(
                    self.app.client_manager,
                    nodes='swift-1',
                    inventory_file=mock_open().read(),
                    playbook=book,
                    ansible_queue_name=constants.UPGRADE_QUEUE,
                    node_user='heat-admin',
                    tags='',
                    skip_tags='pre-upgrade,validation'
                )

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_upgrade_no_nodes_or_roles(self, mock_open, mock_execute,
                                       mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = []
        verifylist = []
        self.assertRaises(ParserException, lambda: self.check_parser(
            self.cmd, argslist, verifylist))

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_upgrade_nodes_and_roles(self, mock_open, mock_execute,
                                     mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--roles', 'Compute', '--nodes', 'overcloud-controller-1']
        verifylist = [
            ('roles', 'Compute'),
            ('nodes', 'overcloud-controller-1'),
            ('static_inventory', None),
            ('playbook', 'all')
        ]
        self.assertRaises(ParserException, lambda: self.check_parser(
            self.cmd, argslist, verifylist))

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    # it is 'validation' not 'validations'
    def test_upgrade_skip_tags_validations(self, mock_open, mock_execute,
                                           mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--nodes', 'overcloud-compute-1',
                    '--skip-tags', 'validations']
        verifylist = [
            ('nodes', 'overcloud-compute-1'),
            ('static_inventory', None),
            ('playbook', 'all'),
            ('skip_tags', 'validations'),
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.assertRaises(exceptions.InvalidConfiguration,
                              lambda: self.cmd.take_action(parsed_args))

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    # should only support the constants.MAJOR_UPGRADE_SKIP_TAGS
    def test_upgrade_skip_tags_unsupported_validation_anything_else(
            self, mock_open, mock_execute, mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--nodes', 'overcloud-compute-1',
                    '--skip-tags', 'validation,anything-else']
        verifylist = [
            ('nodes', 'overcloud-compute-1'),
            ('static_inventory', None),
            ('playbook', 'all'),
            ('skip_tags', 'validation,anything-else'),
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.assertRaises(exceptions.InvalidConfiguration,
                              lambda: self.cmd.take_action(parsed_args))

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    # should only support the constants.MAJOR_UPGRADE_SKIP_TAGS
    def test_upgrade_skip_tags_unsupported_pre_upgrade_anything_else(
            self, mock_open, mock_execute, mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--nodes', 'overcloud-compute-1',
                    '--skip-tags', 'pre-upgrade,anything-else']
        verifylist = [
            ('nodes', 'overcloud-compute-1'),
            ('static_inventory', None),
            ('playbook', 'all'),
            ('skip_tags', 'pre-upgrade,anything-else'),
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.assertRaises(exceptions.InvalidConfiguration,
                              lambda: self.cmd.take_action(parsed_args))
