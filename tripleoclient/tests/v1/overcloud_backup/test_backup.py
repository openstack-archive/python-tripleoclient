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

from osc_lib.tests import utils

from tripleoclient import constants
from tripleoclient.tests import fakes
from tripleoclient.v1 import overcloud_backup


class TestOvercloudBackup(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudBackup, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.options = fakes.FakeOptions()
        self.cmd = overcloud_backup.BackupOvercloud(self.app, app_args)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_overcloud_backup_noargs(self, mock_playbook):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook='cli-overcloud-backup.yaml',
            inventory=parsed_args.inventory,
            skip_tags=None,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=3,
            extra_vars=None
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_overcloud_backup_init(self, mock_playbook):
        arglist = [
            '--init'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook='prepare-overcloud-backup.yaml',
            inventory=parsed_args.inventory,
            skip_tags='bar_create_recover_image, bar_setup_nfs_server',
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=3,
            extra_vars=None
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_overcloud_backup_storage_ip(self, mock_playbook):
        arglist = [
            '--init',
            '--storage-ip',
            '192.168.0.100'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        extra_vars = {
            "tripleo_backup_and_restore_nfs_server": parsed_args.storage_ip
            }

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook='prepare-overcloud-backup.yaml',
            inventory=parsed_args.inventory,
            skip_tags='bar_create_recover_image, bar_setup_nfs_server',
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=3,
            extra_vars=extra_vars
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_overcloud_backup_init_with_inventory(self, mock_playbook):
        arglist = [
            '--init',
            '--inventory',
            '/tmp/test_inventory.yaml'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook='prepare-overcloud-backup.yaml',
            inventory=parsed_args.inventory,
            skip_tags='bar_create_recover_image, bar_setup_nfs_server',
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=3,
            extra_vars=None
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_overcloud_backup_inventory(self, mock_playbook):
        arglist = [
            '--inventory',
            '/tmp/test_inventory.yaml'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook='cli-overcloud-backup.yaml',
            inventory=parsed_args.inventory,
            skip_tags=None,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=3,
            extra_vars=None
        )
