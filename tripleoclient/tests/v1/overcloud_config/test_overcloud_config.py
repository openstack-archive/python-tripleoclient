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

import mock

from osc_lib.tests import utils

from tripleoclient.tests import fakes
from tripleoclient.v1 import overcloud_config


class TestOvercloudConfig(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudConfig, self).setUp()
        self.cmd = overcloud_config.DownloadConfig(self.app, None)
        self.app.client_manager.orchestration = mock.Mock()
        self.app.options = fakes.FakeOptions()

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    def test_overcloud_download_config(self, mock_playbook):
        arglist = ['--name', 'overcloud', '--config-dir', '/tmp']
        verifylist = [
            ('name', 'overcloud'),
            ('config_dir', '/tmp'),
            ('preserve_config_dir', True)
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            extra_vars={'plan': 'overcloud', 'config_dir': '/tmp',
                        'preserve_config': True},
            inventory='localhost,', playbook='cli-config-download-export.yaml',
            playbook_dir='/usr/share/ansible/tripleo-playbooks',
            verbosity=3, workdir=mock.ANY)

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    def test_overcloud_download_config_no_preserve(self, mock_playbook):
        arglist = ['--name', 'overcloud', '--config-dir', '/tmp',
                   '--no-preserve-config']
        verifylist = [
            ('name', 'overcloud'),
            ('config_dir', '/tmp'),
            ('preserve_config_dir', False)
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            extra_vars={'plan': 'overcloud', 'config_dir': '/tmp',
                        'preserve_config': False},
            inventory='localhost,', playbook='cli-config-download-export.yaml',
            playbook_dir='/usr/share/ansible/tripleo-playbooks',
            verbosity=3, workdir=mock.ANY)
