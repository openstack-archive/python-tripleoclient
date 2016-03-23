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
    def test_upgrade_out(self, upgrade_manager):
        upgrade_manager.return_value.get_status.return_value = (
            'UPDATE_COMPLETE', {})
        argslist = ['start', '--stack', 'overcloud', '--templates']
        verifylist = [
            ('stage', 'start'),
            ('stack', 'overcloud'),
            ('templates', '/usr/share/openstack-tripleo-heat-templates/')
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        upgrade_manager.get_status.called_once()
        upgrade_manager.upgrade.called_once()

    @mock.patch('tripleo_common.upgrade.StackUpgradeManager')
    def test_upgrade_answerfile(self, upgrade_manager):
        answers = ("templates: {templates}\n"
                   "environments:\n"
                   "  - {environment}\n")

        mock_open = mock.mock_open(read_data=answers.format(
            templates='/tmp/tht', environment='/tmp/env'))

        with mock.patch('six.moves.builtins.open', mock_open):
            upgrade_manager.return_value.get_status.return_value = (
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

        upgrade_manager.get_status.called_once()
        upgrade_manager.upgrade.called_once()

        called_args = upgrade_manager.call_args[1]
        self.assertEqual('/tmp/tht', called_args['tht_dir'])
        self.assertEqual(['/tmp/env'], called_args['environment_files'])

    @mock.patch('tripleo_common.upgrade.StackUpgradeManager')
    def test_upgrade_answerfile_just_environments(self, upgrade_manager):
        mock_open = mock.mock_open(read_data="environments:\n  - /tmp/env\n")

        with mock.patch('six.moves.builtins.open', mock_open):
            upgrade_manager.return_value.get_status.return_value = (
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

        upgrade_manager.get_status.called_once()
        upgrade_manager.upgrade.called_once()

        called_args = upgrade_manager.call_args[1]
        self.assertEqual('/usr/share/openstack-tripleo-heat-templates/',
                         called_args['tht_dir'])
        self.assertEqual(['/tmp/env'], called_args['environment_files'])
