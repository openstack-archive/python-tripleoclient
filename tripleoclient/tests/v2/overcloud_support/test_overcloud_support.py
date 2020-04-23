#   Copyright 2020 Red Hat, Inc.
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
import os

from osc_lib.tests import utils

from tripleoclient import constants
from tripleoclient.tests import fakes
from tripleoclient.v2 import overcloud_support


class TestOvercloudSupportReport(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudSupportReport, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.options = fakes.FakeOptions()
        self.cmd = overcloud_support.ReportExecute(self.app, app_args)

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_overcloud_support_noargs(self, mock_playbook):
        parsed_args = self.check_parser(self.cmd, ['all'], [])
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook='cli-support-collect-logs.yaml',
            inventory=mock.ANY,
            playbook_dir=mock.ANY,
            verbosity=3,
            extra_vars={
                'server_name': 'all',
                'sos_destination': '/var/lib/tripleo/support'
            }
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_overcloud_support_args(self, mock_playbook):
        arglist = ['server1', '--output', 'test']
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook='cli-support-collect-logs.yaml',
            inventory=mock.ANY,
            playbook_dir=mock.ANY,
            verbosity=3,
            extra_vars={
                'server_name': 'server1',
                'sos_destination': 'test'
            }
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_overcloud_support_args_stack(self, mock_playbook):
        arglist = ['server1', '--output', 'test', '--stack', 'notovercloud']
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)
        inv = os.path.join(
            constants.DEFAULT_WORK_DIR,
            'notovercloud/tripleo-ansible-inventory.yaml'
        )
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook='cli-support-collect-logs.yaml',
            inventory=inv,
            playbook_dir=mock.ANY,
            verbosity=3,
            extra_vars={
                'server_name': 'server1',
                'sos_destination': 'test'
            }
        )
