#   Copyright 2015 Red Hat, Inc.
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

from tripleoclient.tests.v1.overcloud_upgrade import fakes
from tripleoclient.v1 import overcloud_upgrade


class TestOvercloudUpgrade(fakes.TestOvercloudUpgrade):

    def setUp(self):
        super(TestOvercloudUpgrade, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_upgrade.UpgradeOvercloud(self.app, None)

    @mock.patch('tripleo_common.upgrade.StackUpgradeManager')
    def test_upgrade_out(self, mock_upgrade_manager):
        upgrade_manager = mock_upgrade_manager.return_value
        upgrade_manager.get_status.return_value = (
            'UPDATE_COMPLETE', {})
        argslist = ['start', '--stack', 'overcloud', '--templates']
        verifylist = [
            ('stage', 'start'),
            ('stack', 'overcloud'),
            ('templates', '/usr/share/openstack-tripleo-heat-templates/')
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        upgrade_manager.get_status.assert_called_once_with()
        upgrade_manager.upgrade.assert_called_once_with()
        upgrade_manager.upgrade_post.assert_not_called()
        upgrade_manager.upgrade_pre.assert_not_called()

    @mock.patch('tripleo_common.upgrade.StackUpgradeManager', autospec=True)
    def test_upgrade_answerfile(self, mock_upgrade_manager):
        answers = ("templates: {templates}\n"
                   "environments:\n"
                   "  - {environment}\n")

        mock_open = mock.mock_open(read_data=answers.format(
            templates='/tmp/tht', environment='/tmp/env'))

        upgrade_manager = mock_upgrade_manager.return_value

        with mock.patch('six.moves.builtins.open', mock_open):
            upgrade_manager.get_status.return_value = (
                'UPDATE_COMPLETE', {})
            arglist = [
                'start',
                '--stack', 'overcloud',
                '--answers-file', 'answerfile'
            ]
            verifylist = [
                ('stage', 'start'),
                ('stack', 'overcloud'),
                ('answers_file', 'answerfile')
            ]
            parsed_args = self.check_parser(self.cmd, arglist, verifylist)
            self.cmd.take_action(parsed_args)

        upgrade_manager.get_status.assert_called_once_with()
        upgrade_manager.upgrade.assert_called_once_with()
        upgrade_manager.upgrade_post.assert_not_called()
        upgrade_manager.upgrade_pre.assert_not_called()

        called_args = mock_upgrade_manager.call_args[1]
        self.assertEqual('/tmp/tht', called_args['tht_dir'])
        self.assertEqual(['/tmp/env'], called_args['environment_files'])

    @mock.patch('tripleo_common.upgrade.StackUpgradeManager')
    def test_upgrade_answerfile_just_environments(self, mock_upgrade_manager):
        mock_open = mock.mock_open(read_data="environments:\n  - /tmp/env\n")

        upgrade_manager = mock_upgrade_manager.return_value

        with mock.patch('six.moves.builtins.open', mock_open):
            upgrade_manager.get_status.return_value = (
                'UPDATE_COMPLETE', {})
            arglist = [
                'start',
                '--stack', 'overcloud',
                '--answers-file', 'answerfile'
            ]
            verifylist = [
                ('stage', 'start'),
                ('stack', 'overcloud'),
                ('answers_file', 'answerfile')
            ]
            parsed_args = self.check_parser(self.cmd, arglist, verifylist)
            self.cmd.take_action(parsed_args)

        upgrade_manager.get_status.assert_called_once_with()
        upgrade_manager.upgrade.assert_called_once_with()

        called_args = mock_upgrade_manager.call_args[1]
        self.assertEqual('/usr/share/openstack-tripleo-heat-templates/',
                         called_args['tht_dir'])
        self.assertEqual(['/tmp/env'], called_args['environment_files'])

    @mock.patch('tripleo_common.upgrade.StackUpgradeManager')
    def test_upgrade_perform_post(self, mock_upgrade_manager):
        upgrade_manager = mock_upgrade_manager.return_value
        upgrade_manager.get_status.return_value = (
            'UPDATE_COMPLETE', {})
        argslist = [
            'finish',
            '--stack', 'overcloud',
            '--templates',
        ]
        verifylist = [
            ('stage', 'finish'),
            ('stack', 'overcloud'),
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        upgrade_manager.get_status.assert_called_once_with()
        upgrade_manager.upgrade_post.assert_called_once_with()
        upgrade_manager.upgrade.assert_not_called()
        upgrade_manager.upgrade_pre.assert_not_called()

    @mock.patch('tripleo_common.upgrade.StackUpgradeManager')
    def test_upgrade_perform_pre(self, mock_upgrade_manager):
        upgrade_manager = mock_upgrade_manager.return_value
        upgrade_manager.get_status.return_value = (
            'UPDATE_COMPLETE', {})
        argslist = [
            'prepare',
            '--stack', 'overcloud',
            '--templates',
        ]
        verifylist = [
            ('stage', 'prepare'),
            ('stack', 'overcloud'),
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        upgrade_manager.get_status.assert_called_once_with()
        upgrade_manager.upgrade_pre.assert_called_once_with()
        upgrade_manager.upgrade.assert_not_called()
        upgrade_manager.upgrade_post.assert_not_called()
