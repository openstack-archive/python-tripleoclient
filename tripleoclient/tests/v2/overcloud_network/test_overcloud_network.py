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

from osc_lib import exceptions as osc_lib_exc

from tripleoclient.tests import fakes
from tripleoclient.v2 import overcloud_network


class TestOvercloudNetworkExtract(fakes.FakePlaybookExecution):

    def setUp(self):
        super(TestOvercloudNetworkExtract, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.options = fakes.FakeOptions()
        self.cmd = overcloud_network.OvercloudNetworkExtract(self.app,
                                                             app_args)

    @mock.patch('tripleoclient.utils.TempDirs', autospect=True)
    @mock.patch('os.path.abspath', autospect=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook', autospec=True)
    def test_overcloud_network_extract(self, mock_playbook, mock_abspath,
                                       mock_tempdirs):
        mock_abspath.return_value = '/test/test'
        arglist = ['--stack', 'overcloud', '--output', 'test', '--yes']
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook='cli-overcloud-network-extract.yaml',
            inventory=mock.ANY,
            playbook_dir=mock.ANY,
            verbosity=3,
            extra_vars={
                "stack_name": 'overcloud',
                "output": '/test/test',
                "overwrite": True
            }
        )

    @mock.patch('os.path.abspath', autospect=True)
    @mock.patch('os.path.exists', autospect=True)
    def test_overcloud_network_extract_no_overwrite(self, mock_abspath,
                                                    mock_path_exists):
        mock_abspath.return_value = '/test/test'
        mock_path_exists.return_value = True
        arglist = ['--stack', 'overcloud', '--output', 'test']
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.assertRaises(osc_lib_exc.CommandError,
                          self.cmd.take_action, parsed_args)


class TestOvercloudNetworkProvision(fakes.FakePlaybookExecution):

    def setUp(self):
        super(TestOvercloudNetworkProvision, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.options = fakes.FakeOptions()
        self.cmd = overcloud_network.OvercloudNetworkProvision(self.app, None)
        self.cmd.app_args = mock.Mock(verbose_level=1)

    @mock.patch('tripleoclient.utils.TempDirs', autospect=True)
    @mock.patch('os.path.abspath', autospect=True)
    @mock.patch('os.path.exists', autospect=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook', autospec=True)
    def test_overcloud_network_provision(self, mock_playbook, mock_path_exists,
                                         mock_abspath, mock_tempdirs):
        arglist = ['--output', 'deployed_networks.yaml', '--yes',
                   'network_data_v2.yaml']
        parsed_args = self.check_parser(self.cmd, arglist, [])

        mock_abspath.side_effect = ['/test/network_data_v2.yaml',
                                    '/test/deployed_networks.yaml']
        mock_path_exists.side_effect = [True, True]
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook='cli-overcloud-network-provision.yaml',
            inventory=mock.ANY,
            playbook_dir=mock.ANY,
            verbosity=3,
            extra_vars={
                "network_data_path": '/test/network_data_v2.yaml',
                "network_deployed_path": '/test/deployed_networks.yaml',
                "overwrite": True
            }
        )

    @mock.patch('os.path.abspath', autospect=True)
    @mock.patch('os.path.exists', autospect=True)
    def test_overcloud_network_extract_no_overwrite(self, mock_abspath,
                                                    mock_path_exists):
        arglist = ['--output', 'deployed_networks.yaml', 'network-data.yaml']
        parsed_args = self.check_parser(self.cmd, arglist, [])

        mock_abspath.side_effect = ['/test/network_data_v2.yaml',
                                    '/test/deployed_networks.yaml']
        mock_path_exists.side_effect = [True, True]

        self.assertRaises(osc_lib_exc.CommandError,
                          self.cmd.take_action, parsed_args)
