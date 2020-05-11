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

# Load the plugin init module for the plugin list and show commands
from tripleoclient import exceptions
from tripleoclient.v1 import tripleo_upgrade


class TestUpgrade(utils.TestCommand):

    def setUp(self):
        super(TestUpgrade, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_upgrade.Upgrade(self.app, None)
        self.cmd.ansible_dir = '/tmp'
        self.ansible_playbook_cmd = "ansible-playbook"

    @mock.patch('tripleoclient.utils.prompt_user_for_confirmation',
                return_value=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.take_action',
                autospec=True)
    def test_take_action(self, mock_deploy, mock_confirm):
        verifylist = [
            ('local_ip', '127.0.0.1'),
            ('templates', '/tmp/thtroot'),
            ('stack', 'undercloud'),
            ('output_dir', '/my'),
        ]

        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my',
                                         '-e', '/tmp/thtroot/puppet/foo.yaml',
                                         '-e', '/tmp/thtroot//docker/bar.yaml',
                                         '-e', '/tmp/thtroot42/notouch.yaml',
                                         '-e', '~/custom.yaml',
                                         '-e', 'something.yaml',
                                         '-e', '../../../outside.yaml'],
                                        verifylist)

        self.cmd.take_action(parsed_args)
        parsed_args.standalone = True
        parsed_args.upgrade = True
        mock_deploy.assert_called_with(self.cmd, parsed_args)

    @mock.patch('tripleoclient.utils.prompt_user_for_confirmation',
                return_value=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.take_action',
                autospec=True)
    def test_take_action_prompt(self, mock_deploy, mock_confirm):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my',
                                         '-e', '/tmp/thtroot/puppet/foo.yaml',
                                         '-e', '/tmp/thtroot//docker/bar.yaml',
                                         '-e', '/tmp/thtroot42/notouch.yaml',
                                         '-e', '~/custom.yaml',
                                         '-e', 'something.yaml',
                                         '-e', '../../../outside.yaml'], [])
        self.cmd.take_action(parsed_args)
        parsed_args.standlone = True
        parsed_args.upgrade = True
        mock_deploy.assert_called_with(self.cmd, parsed_args)

    @mock.patch('tripleoclient.utils.prompt_user_for_confirmation',
                return_value=False)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy',
                autospec=True)
    def test_take_action_prompt_no(self, mock_deploy, mock_confirm):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my',
                                         '-e', '/tmp/thtroot/puppet/foo.yaml',
                                         '-e', '/tmp/thtroot//docker/bar.yaml',
                                         '-e', '/tmp/thtroot42/notouch.yaml',
                                         '-e', '~/custom.yaml',
                                         '-e', 'something.yaml',
                                         '-e', '../../../outside.yaml'], [])
        parsed_args.standlone = True
        parsed_args.upgrade = True
        self.assertRaises(exceptions.UndercloudUpgradeNotConfirmed,
                          self.cmd.take_action, parsed_args)
        mock_deploy.assert_not_called()
