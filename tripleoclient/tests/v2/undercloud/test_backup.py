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
from tripleoclient.v2 import undercloud_backup


class TestUndercloudBackup(utils.TestCommand):

    def setUp(self):
        super(TestUndercloudBackup, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.options = fakes.FakeOptions()
        self.cmd = undercloud_backup.BackupUndercloud(self.app, app_args)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_undercloud_backup_noargs(self, mock_playbook):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook='cli-undercloud-backup.yaml',
            inventory='localhost,',
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=3,
            extra_vars={
                'sources_path': '/home/stack/'
            }
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_undercloud_backup_withargs(self, mock_playbook):
        arglist = [
            '--add-path',
            '/tmp/foo.yaml',
            '--add-path',
            '/tmp/bar.yaml'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook=mock.ANY,
            inventory=mock.ANY,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=3,
            extra_vars={'sources_path':
                        '/home/stack/,/tmp/bar.yaml,/tmp/foo.yaml'})

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_undercloud_backup_withargs_remove(self, mock_playbook):
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
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook=mock.ANY,
            inventory=mock.ANY,
            verbosity=3,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={'sources_path':
                        '/tmp/foo.yaml'})

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_undercloud_backup_withargs_remove_double(self, mock_playbook):
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
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook=mock.ANY,
            inventory=mock.ANY,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=3,
            extra_vars={'sources_path':
                        '/home/stack/,/tmp/bar.yaml'})

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_undercloud_backup_withargs_remove_unex(self, mock_playbook):
        arglist = [
            '--add-path',
            '/tmp/foo.yaml',
            '--exclude-path',
            '/tmp/non-existing-path.yaml'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook=mock.ANY,
            inventory=mock.ANY,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=3,
            extra_vars={'sources_path':
                        '/home/stack/,/tmp/foo.yaml'})
