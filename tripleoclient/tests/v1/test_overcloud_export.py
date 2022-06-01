#   Copyright 2019 Red Hat, Inc.
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
import os

from unittest import mock

from osc_lib.tests import utils

from tripleoclient import utils as ooo_utils
from tripleoclient.v1 import overcloud_export


class TestOvercloudExport(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudExport, self).setUp()

        self.cmd = overcloud_export.ExportOvercloud(self.app, None)
        self.app.client_manager.orchestration = mock.Mock()
        self.tripleoclient = mock.Mock()
        self.app.client_manager.tripleoclient = self.tripleoclient
        self.mock_open = mock.mock_open()

    @mock.patch('os.path.exists')
    @mock.patch('yaml.safe_dump')
    @mock.patch('tripleoclient.export.export_stack')
    @mock.patch('tripleoclient.export.export_passwords')
    def test_export(self, mock_export_passwords,
                    mock_export_stack,
                    mock_safe_dump,
                    mock_exists):
        argslist = []
        verifylist = []
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        mock_exists.return_value = False
        mock_export_passwords.return_value = {'key': 'value'}
        mock_export_stack.return_value = {'key0': 'value0'}
        with mock.patch('builtins.open', self.mock_open):
            self.cmd.take_action(parsed_args)
        mock_export_passwords.assert_called_once_with(
            ooo_utils.get_default_working_dir('overcloud'),
            'overcloud', True)
        path = os.path.join(os.environ.get('HOME'),
                            'overcloud-deploy',
                            'overcloud',
                            'config-download')
        mock_export_stack.assert_called_once_with(
            ooo_utils.get_default_working_dir('overcloud'),
            'overcloud',
            False,
            path)
        self.assertEqual(
            {'parameter_defaults': {'AddVipsToEtcHosts': False,
                                    'key': 'value',
                                    'key0': 'value0'}},
            mock_safe_dump.call_args[0][0])

    @mock.patch('os.path.exists')
    @mock.patch('yaml.safe_dump')
    @mock.patch('tripleoclient.export.export_stack')
    @mock.patch('tripleoclient.export.export_passwords')
    def test_export_stack_name(self, mock_export_passwords,
                               mock_export_stack,
                               mock_safe_dump,
                               mock_exists):
        argslist = ['--stack', 'foo']
        verifylist = [('stack', 'foo')]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        mock_exists.return_value = False
        with mock.patch('builtins.open', self.mock_open):
            self.cmd.take_action(parsed_args)
        mock_export_passwords.assert_called_once_with(
            ooo_utils.get_default_working_dir('foo'),
            'foo', True)
        path = os.path.join(os.environ.get('HOME'),
                            'overcloud-deploy',
                            'foo',
                            'config-download')
        mock_export_stack.assert_called_once_with(
            ooo_utils.get_default_working_dir('foo'),
            'foo',
            False,
            path)

    @mock.patch('os.path.exists')
    @mock.patch('yaml.safe_dump')
    @mock.patch('tripleoclient.export.export_stack')
    @mock.patch('tripleoclient.export.export_passwords')
    def test_export_stack_name_and_dir(self, mock_export_passwords,
                                       mock_export_stack,
                                       mock_safe_dump, mock_exists):
        argslist = ['--stack', 'foo',
                    '--config-download-dir', '/tmp/bar']
        verifylist = [('stack', 'foo'),
                      ('config_download_dir', '/tmp/bar')]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        mock_exists.return_value = False
        with mock.patch('builtins.open', self.mock_open):
            self.cmd.take_action(parsed_args)
        mock_export_passwords.assert_called_once_with(
            ooo_utils.get_default_working_dir('foo'),
            'foo', True)
        mock_export_stack.assert_called_once_with(
            ooo_utils.get_default_working_dir('foo'),
            'foo',
            False,
            '/tmp/bar')

    @mock.patch('os.path.exists')
    @mock.patch('yaml.safe_dump')
    @mock.patch('tripleoclient.export.export_stack')
    @mock.patch('tripleoclient.export.export_passwords')
    def test_export_no_excludes(self, mock_export_passwords,
                                mock_export_stack,
                                mock_safe_dump, mock_exists):
        argslist = ['--stack', 'foo',
                    '--config-download-dir', '/tmp/bar',
                    '--no-password-excludes']
        verifylist = [('stack', 'foo'),
                      ('config_download_dir', '/tmp/bar'),
                      ('no_password_excludes', True)]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        mock_exists.return_value = False
        with mock.patch('builtins.open', self.mock_open):
            self.cmd.take_action(parsed_args)
        mock_export_passwords.assert_called_once_with(
            ooo_utils.get_default_working_dir('foo'),
            'foo', False)
        mock_export_stack.assert_called_once_with(
            ooo_utils.get_default_working_dir('foo'),
            'foo',
            False,
            '/tmp/bar')

    @mock.patch('tripleo_common.utils.plan.generate_passwords')
    @mock.patch('shutil.copy')
    @mock.patch('os.path.exists')
    @mock.patch('tripleoclient.utils.get_default_working_dir')
    def test_export_ephemeral_heat(self, mock_working_dir, mock_exists,
                                   mock_copy, mock_passwords):
        argslist = ['--force-overwrite']
        verifylist = [('force_overwrite', True)]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        mock_exists.return_value = True
        mock_working_dir.return_value = 'wd'
        mock_open = mock.mock_open(read_data='{}')
        mock_passwords.return_value = dict()
        with mock.patch('builtins.open', mock_open):
            self.cmd.take_action(parsed_args)
        mock_working_dir.assert_called()
        mock_passwords.assert_called()
