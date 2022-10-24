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

from tripleoclient.v1 import overcloud_cell
from tripleoclient.exceptions import CellExportError
from tripleoclient import utils as oooutils


class TestExportCell(utils.TestCommand):
    def setUp(self):
        super(TestExportCell, self).setUp()
        self.cmd = overcloud_cell.ExportCell(self.app, None)
        self.app.client_manager.orchestration = mock.Mock()

    @mock.patch('tripleoclient.v1.overcloud_cell.yaml.safe_dump')
    @mock.patch('tripleoclient.v1.overcloud_cell.print')
    @mock.patch('tripleoclient.v1.overcloud_cell.open')
    @mock.patch('tripleoclient.v1.overcloud_cell.export.export_stack')
    @mock.patch(
        'tripleoclient.v1.overcloud_cell.export.export_passwords',
        autospec=True)
    @mock.patch(
        'tripleoclient.v1.overcloud_cell.os.path.exists',
        autospec=True, return_value=False)
    def test_export_cell_defaults(self, mock_path_exists,
                                  mock_export_passwords, mock_export_stack,
                                  mock_open, mock_print, mock_yaml_dump):
        """Test class methods with all default parameters.
        The test approximates the behavior of the CLI under assumption that no
        alternative values are provided and no exceptions are raised.
        """
        argslist = []
        verifylist = []

        mock_export_passwords._return_value = {'foo': 'bar'}
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        mock_path_exists.assert_any_call('overcloud-cell-export.yaml')
        mock_export_passwords.assert_called_once_with(
            oooutils.get_default_working_dir('overcloud'),
            'overcloud')
        mock_export_stack.assert_called_once_with(
            oooutils.get_default_working_dir('overcloud'),
            'overcloud',
            True,
            os.path.join(
                os.environ.get('HOME'),
                'overcloud-deploy',
                'overcloud',
                'config-download'))
        mock_print.assert_called()
        mock_open.assert_called_once_with('overcloud-cell-export.yaml', 'w')
        mock_yaml_dump.assert_called_once()

    @mock.patch('tripleoclient.v1.overcloud_cell.yaml.safe_dump')
    @mock.patch('tripleoclient.v1.overcloud_cell.print')
    @mock.patch('tripleoclient.v1.overcloud_cell.open')
    @mock.patch('tripleoclient.v1.overcloud_cell.export.export_stack')
    @mock.patch(
        'tripleoclient.v1.overcloud_cell.export.export_passwords',
        autospec=True)
    @mock.patch(
        'tripleoclient.v1.overcloud_cell.os.path.exists',
        autospec=True, return_value=False)
    def test_export_cell_stack_config_dir(self, mock_path_exists,
                                          mock_export_passwords,
                                          mock_export_stack,
                                          mock_open,
                                          mock_print, mock_yaml_dump):
        """Test class methods with alternative 'cells_stack'
        and 'config_download_dir' argument values.

        The test approximates CLI behavior with no exceptions raised.
        """
        argslist = ['--cell-stack', 'fizz', '--config-download-dir', 'buzz']
        verifylist = [('cell_stack', 'fizz'), ('config_download_dir', 'buzz')]

        mock_export_passwords._return_value = {'foo': 'bar'}
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        mock_path_exists.assert_any_call('fizz-cell-export.yaml')
        mock_export_passwords.assert_called_once_with(
            oooutils.get_default_working_dir('fizz'),
            'fizz')
        mock_export_stack.assert_called_once_with(
            oooutils.get_default_working_dir('fizz'),
            'fizz',
            False,
            'buzz')
        mock_print.assert_called()
        mock_open.assert_called_once_with('fizz-cell-export.yaml', 'w')
        mock_yaml_dump.assert_called_once()

    @mock.patch(
        'tripleoclient.v1.overcloud_cell.os.path.exists',
        return_value=True)
    def test_cell_exception(self, mock_exists):
        """Test exception triggering behavior of the 'take_action' method.
        If the output file exists and the 'forced-overwrite' flag isn't set,
        the method must raise CellExportError to notify the operator.
        """
        argslist = []
        verifylist = []
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.assertRaises(CellExportError, self.cmd.take_action, parsed_args)
        mock_exists.assert_any_call('overcloud-cell-export.yaml')
