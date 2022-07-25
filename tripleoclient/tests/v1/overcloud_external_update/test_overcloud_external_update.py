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

import fixtures
import os
from unittest import mock

from tripleoclient.tests.v1.overcloud_external_update import fakes
from tripleoclient.v1 import overcloud_external_update


class TestOvercloudExternalUpdateRun(fakes.TestOvercloudExternalUpdateRun):

    def setUp(self):
        super(TestOvercloudExternalUpdateRun, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_external_update.ExternalUpdateRun(
            self.app, app_args)

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('builtins.open')
    def test_update_with_user_and_tags(self, mock_open, mock_execute,
                                       mock_expanduser):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--ssh-user', 'tripleo-admin',
                    '--tags', 'ceph']
        verifylist = [
            ('ssh_user', 'tripleo-admin'),
            ('tags', 'ceph'),
        ]

        self.check_parser(self.cmd, argslist, verifylist)

    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('builtins.open')
    def test_update_with_user_and_extra_vars(self, mock_open, mock_execute,
                                             mock_expanduser):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--ssh-user', 'tripleo-admin',
                    '--extra-vars', 'key1=val1',
                    '--extra-vars', 'key2=val2']
        verifylist = [
            ('ssh_user', 'tripleo-admin'),
            ('extra_vars', ['key1=val1', 'key2=val2'])
        ]

        self.check_parser(self.cmd, argslist, verifylist)

    @mock.patch('tripleoclient.utils.ensure_run_as_normal_user')
    @mock.patch('tripleoclient.workflows.deployment.config_download')
    @mock.patch('tripleoclient.utils.get_default_working_dir', autospec=True)
    @mock.patch('tripleoclient.workflows.deployment.snapshot_dir',
                autospec=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook', autospec=True)
    @mock.patch('tripleoclient.utils.get_key')
    def test_update_with_refresh(
            self, mock_get_key,
            mock_run_ansible_playbook,
            mock_snapshot_dir,
            mock_get_default_working_dir,
            mock_config_download,
            mock_usercheck):
        argslist = ['--yes', '--refresh']
        verifylist = [
            ('refresh', True)
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        argslist = ['--yes']
        verifylist = [
            ('refresh', False)
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        mock_get_key.return_value = '/test/key'
        work_dir = self.useFixture(fixtures.TempDir())
        mock_get_default_working_dir.return_value = work_dir.path
        ansible_dir = os.path.join(work_dir.path, 'config-download',
                                   'overcloud')
        self.cmd.take_action(parsed_args)
        mock_get_key.assert_called_once_with('overcloud')
        mock_snapshot_dir.assert_called_once_with(ansible_dir)
        mock_run_ansible_playbook.assert_called()
        mock_config_download.assert_not_called()
