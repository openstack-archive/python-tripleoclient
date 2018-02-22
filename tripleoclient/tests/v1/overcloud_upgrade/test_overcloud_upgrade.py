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
    def test_upgrade_out(self, mock_deploy, mock_open, mock_copy, mock_yaml,
                         mock_abspath, mock_upgrade, mock_logger,
                         mock_get_stack):
        mock_stack = mock.Mock()
        mock_stack.stack_name = 'mystack'
        mock_get_stack.return_value = mock_stack
        mock_abspath.return_value = '/home/fake/my-fake-registry.yaml'
        mock_yaml.return_value = {'fake_container': 'fake_value'}

        argslist = ['--stack', 'overcloud', '--templates',
                    '--container-registry-file', 'my-fake-registry.yaml']
        verifylist = [
            ('stack', 'overcloud'),
            ('templates', constants.TRIPLEO_HEAT_TEMPLATES),
            ('container_registry_file', 'my-fake-registry.yaml')
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        mock_upgrade.assert_called_once_with(
            self.app.client_manager,
            container='mystack',
            container_registry={'fake_container': 'fake_value'},
            ceph_ansible_playbook='/usr/share/ceph-ansible'
                                  '/site-docker.yml.sample'
        )

    @mock.patch('tripleoclient.workflows.package_update.update',
                autospec=True)
    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.abspath')
    @mock.patch('yaml.load')
    @mock.patch('shutil.copytree', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_deploy_tripleo_heat_templates', autospec=True)
    def test_upgrade_failed(self, mock_deploy, mock_copy, mock_yaml,
                            mock_abspath, mock_open, mock_upgrade):
        mock_upgrade.side_effect = exceptions.DeploymentError()
        mock_abspath.return_value = '/home/fake/my-fake-registry.yaml'
        mock_yaml.return_value = {'fake_container': 'fake_value'}
        argslist = ['--stack', 'overcloud', '--templates',
                    '--container-registry-file', 'my-fake-registry.yaml']
        verifylist = [
            ('stack', 'overcloud'),
            ('templates', constants.TRIPLEO_HEAT_TEMPLATES),
            ('container_registry_file', 'my-fake-registry.yaml')
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
    def test_upgrade_with_playbook(self, mock_open, mock_execute,
                                   mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--nodes', 'Compute', '--playbook',
                    'fake-playbook.yaml']
        verifylist = [
            ('nodes', 'Compute'),
            ('static_inventory', None),
            ('playbook', 'fake-playbook.yaml')
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.cmd.take_action(parsed_args)
            upgrade_ansible.assert_called_once_with(
                self.app.client_manager,
                nodes='Compute',
                inventory_file=mock_open().read(),
                playbook='fake-playbook.yaml',
                ansible_queue_name=constants.UPGRADE_QUEUE
            )

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_upgrade_with_all_playbooks(self, mock_open, mock_execute,
                                        mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--nodes', 'Compute', '--playbook', 'all']
        verifylist = [
            ('nodes', 'Compute'),
            ('static_inventory', None),
            ('playbook', 'all')
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
                    ansible_queue_name=constants.UPGRADE_QUEUE
                )

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_upgrade_with_no_nodes(self, mock_open, mock_execute,
                                   mock_expanduser, upgrade_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = []
        verifylist = [
            ('static_inventory', None),
            ('playbook', 'all')
        ]
        self.assertRaises(ParserException, lambda: self.check_parser(
            self.cmd, argslist, verifylist))
