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
from tripleoclient.v1 import undercloud_backup
from unittest.mock import call


class TestUndercloudBackup(utils.TestCommand):

    def setUp(self):
        super(TestUndercloudBackup, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = undercloud_backup.BackupUndercloud(self.app, app_args)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine

    @mock.patch('tripleoclient.workflows.undercloud_backup.backup',
                autospec=True)
    def test_undercloud_backup_withargs(self, plan_mock):
        arglist = [
            '--add-path',
            '/tmp/foo.yaml',
            '--add-path',
            '/tmp/bar.yaml'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        plan_mock.assert_called_once_with(
            mock.ANY,
            {'sources_path': '/home/stack/,/tmp/bar.yaml,/tmp/foo.yaml'})

    @mock.patch('tripleoclient.workflows.undercloud_backup.backup',
                autospec=True)
    def test_undercloud_backup_withargs_remove(self, plan_mock):
        arglist = [
            '--add-path',
            '/tmp/foo.yaml',
            '--exclude-path',
            '/tmp/bar.yaml',
            '--exclude-path',
            '/home/stack/',
            '--add-path',
            '/tmp/bar.yaml'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        plan_mock.assert_called_once_with(
            mock.ANY,
            {'sources_path': '/tmp/foo.yaml'})

    @mock.patch('tripleoclient.workflows.undercloud_backup.backup',
                autospec=True)
    def test_undercloud_backup_withargs_remove_double(self, plan_mock):
        arglist = [
            '--add-path',
            '/tmp/foo.yaml',
            '--add-path',
            '/tmp/bar.yaml',
            '--exclude-path',
            '/tmp/foo.yaml',
            '--exclude-path',
            '/tmp/foo.yaml'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        plan_mock.assert_called_once_with(
            mock.ANY,
            {'sources_path': '/home/stack/,/tmp/bar.yaml'})

    @mock.patch('tripleoclient.workflows.undercloud_backup.backup',
                autospec=True)
    def test_undercloud_backup_withargs_remove_unex(self, plan_mock):
        arglist = [
            '--add-path',
            '/tmp/foo.yaml',
            '--exclude-path',
            '/tmp/non-existing-path.yaml'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        plan_mock.assert_called_once_with(
            mock.ANY,
            {'sources_path': '/home/stack/,/tmp/foo.yaml'})

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_undercloud_backup_noargs(self, mock_playbook):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            logger=mock.ANY,
            workdir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            playbook='cli-undercloud-backup.yaml',
            inventory=mock.ANY,
            tags='bar_create_recover_image',
            skip_tags=None,
            output_callback='tripleo',
            verbosity=1,
            extra_vars=None
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_undercloud_backup_init(self, mock_playbook):
        arglist = [
            '--init'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            logger=mock.ANY,
            workdir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            playbook='prepare-undercloud-backup.yaml',
            inventory=mock.ANY,
            tags='bar_setup_rear',
            skip_tags=None,
            output_callback='tripleo',
            verbosity=1,
            extra_vars=None
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_undercloud_backup_init_nfs(self, mock_playbook):
        arglist = [
            '--init',
            'nfs'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            logger=mock.ANY,
            workdir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            playbook='prepare-nfs-backup.yaml',
            inventory=mock.ANY,
            tags='bar_setup_nfs_server',
            output_callback='tripleo',
            skip_tags=None,
            verbosity=1,
            extra_vars=None
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_undercloud_backup_setup_nfs(self, mock_playbook):
        arglist = [
            '--setup-nfs'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            logger=mock.ANY,
            workdir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            playbook='prepare-nfs-backup.yaml',
            inventory=mock.ANY,
            output_callback='tripleo',
            tags='bar_setup_nfs_server',
            skip_tags=None,
            verbosity=1,
            extra_vars=None
            )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_undercloud_backup_setup_rear(self, mock_playbook):
        arglist = [
            '--setup-rear'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            logger=mock.ANY,
            workdir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            playbook='prepare-undercloud-backup.yaml',
            inventory=mock.ANY,
            tags='bar_setup_rear',
            output_callback='tripleo',
            skip_tags=None,
            verbosity=1,
            extra_vars=None
            )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_undercloud_backup_setup_rear_extra_vars_inline(self,
                                                            mock_playbook):
        arglist = [
            '--setup-rear',
            '--extra-vars',
            '{"tripleo_backup_and_restore_nfs_server": "192.168.24.1"}'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        extra_vars_dict = {
            'tripleo_backup_and_restore_nfs_server': '192.168.24.1'
        }

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            logger=mock.ANY,
            workdir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            playbook='prepare-undercloud-backup.yaml',
            inventory=mock.ANY,
            tags='bar_setup_rear',
            skip_tags=None,
            verbosity=1,
            output_callback='tripleo',
            extra_vars=extra_vars_dict
            )

    @mock.patch('tripleoclient.utils.run_ansible_playbook', autospec=True)
    def test_undercloud_backup_setup_nfs_rear_with_inventory(self,
                                                             mock_playbook):
        arglist = [
            '--setup-nfs',
            '--setup-rear',
            '--inventory',
            '/tmp/test_inventory.yaml'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        calls = [call(logger=mock.ANY,
                      workdir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                      playbook='prepare-nfs-backup.yaml',
                      inventory=mock.ANY,
                      tags='bar_setup_nfs_server',
                      skip_tags=None,
                      output_callback='tripleo',
                      verbosity=1,
                      extra_vars=None),
                 call(logger=mock.ANY,
                      workdir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                      playbook='prepare-undercloud-backup.yaml',
                      inventory=mock.ANY,
                      tags='bar_setup_rear',
                      skip_tags=None,
                      output_callback='tripleo',
                      verbosity=1,
                      extra_vars=None)]

        mock_playbook.assert_has_calls(calls)

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_undercloud_backup_setup_nfs_with_extra_vars(self, mock_playbook):
        arglist = [
            '--setup-nfs',
            '--extra-vars',
            '/tmp/test_vars.yaml'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            logger=mock.ANY,
            workdir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            playbook='prepare-nfs-backup.yaml',
            inventory=mock.ANY,
            tags='bar_setup_nfs_server',
            skip_tags=None,
            verbosity=1,
            output_callback='tripleo',
            extra_vars='/tmp/test_vars.yaml'
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_undercloud_backup_inventory(self, mock_playbook):
        arglist = [
            '--inventory',
            '/tmp/test_inventory.yaml'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            logger=mock.ANY,
            workdir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            playbook='cli-undercloud-backup.yaml',
            inventory=mock.ANY,
            tags='bar_create_recover_image',
            output_callback='tripleo',
            skip_tags=None,
            verbosity=1,
            extra_vars=None
        )
