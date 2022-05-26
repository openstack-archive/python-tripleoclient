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

from unittest import mock

from tripleoclient.tests import base

from tripleoclient.v1 import tripleo_validator
from tripleoclient import constants
from tripleoclient.tests import fakes


class TestValidator(base.TestCase):

    def setUp(self):
        self.validator = tripleo_validator
        super(TestValidator, self).setUp()

    def test_module_init(self):
        expected_names = set([
            'LOG',
            'TripleOValidatorList',
            'TripleOValidatorShow',
            'TripleOValidatorGroupInfo',
            'TripleOValidatorShowParameter',
            'TripleOValidatorRun',
            'TripleOValidatorCommunityInit',
            'TripleOValidatorShowHistory',
            'TripleOValidatorShowRun'
        ])

        module_names = set(dir(self.validator))

        self.assertTrue(expected_names.issubset(module_names))


class TestValidatorGroupInfo(base.TestCommand):

    def setUp(self):
        super(TestValidatorGroupInfo, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorGroupInfo(self.app, None)

    @mock.patch('validations_libs.validation_actions.ValidationActions.'
                'group_information', autospec=True,
                return_value=fakes.GROUPS_LIST)
    def test_show_group_info(self, mock_validations):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)


class TestValidatorList(base.TestCommand):

    def setUp(self):
        super(TestValidatorList, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorList(self.app, None)

    @mock.patch('validations_libs.validation_actions.ValidationActions.'
                'list_validations',
                autospec=True,
                return_value=fakes.VALIDATIONS_LIST)
    def test_validation_list_noargs(self, mock_validations):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)


class TestValidatorShow(base.TestCommand):

    def setUp(self):
        super(TestValidatorShow, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorShow(self.app, None)

    @mock.patch('validations_libs.validation_actions.ValidationActions.'
                'show_validations',
                autospec=True,
                return_value=fakes.VALIDATIONS_LIST[0])
    def test_validation_show(self, mock_validations):
        arglist = ['my_val1']
        verifylist = [('validation_name', 'my_val1')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)


class TestValidatorShowParameter(base.TestCommand):

    def setUp(self):
        super(TestValidatorShowParameter, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorShowParameter(self.app,
                                                                   None)

    @mock.patch('validations_libs.validation_actions.ValidationActions.'
                'show_validations_parameters',
                autospec=True,
                return_value=fakes.VALIDATIONS_LIST[1])
    def test_validation_show_parameter(self, mock_validations):
        arglist = ['--validation', 'my_val2']
        verifylist = [('validation_name', ['my_val2'])]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)


class TestValidatorShowRun(base.TestCommand):

    def setUp(self):
        super(TestValidatorShowRun, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorShowRun(self.app,
                                                             None)

    @mock.patch('validations_libs.validation_actions.ValidationLogs.'
                'get_logfile_content_by_uuid',
                autospec=True,
                return_value=fakes.VALIDATIONS_LOGS_CONTENTS_LIST)
    def test_validation_show_run(self, mock_validations):
        arglist = ['008886df-d297-1eaa-2a74-000000000008']
        verifylist = [('uuid', '008886df-d297-1eaa-2a74-000000000008')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)


class TestValidatorShowHistory(base.TestCommand):

    def setUp(self):
        super(TestValidatorShowHistory, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorShowHistory(self.app,
                                                                 None)

    @mock.patch('validations_libs.validation_actions.ValidationActions.'
                'show_history',
                autospec=True,
                return_value=fakes.VALIDATIONS_LOGS_CONTENTS_LIST)
    def test_validation_show_history(self, mock_validations):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

    @mock.patch('validations_libs.validation_actions.ValidationActions.'
                'show_history',
                autospec=True,
                return_value=fakes.VALIDATIONS_LOGS_CONTENTS_LIST)
    def test_validation_show_history_for_a_validation(self, mock_validations):
        arglist = [
            '--validation',
            '512e'
        ]
        verifylist = [('validation', '512e')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)


class TestValidatorRun(base.TestCommand):

    def setUp(self):
        super().setUp()

        self.cmd = tripleo_validator.TripleOValidatorRun(self.app, None)

    @mock.patch('validations_libs.cli.run.common.print_dict', autospec=True)
    @mock.patch('validations_libs.cli.run.common.write_output', autospec=True)
    @mock.patch('validations_libs.validation_actions.ValidationActions.'
                'run_validations',
                return_value=fakes.FAKE_SUCCESS_RUN,
                autospec=True)
    def test_validation_run(self, mock_validations, mock_write_output,
                            mock_print_dict):
        arglist = ['--validation', 'mock_validation']
        verify_list = [
            ('validation_name', ['mock_validation']),
            ('validation_log_dir', constants.VALIDATIONS_LOG_BASEDIR)]

        parsed_args = self.check_parser(self.cmd, arglist, verify_list)
        self.cmd.take_action(parsed_args)

        # The 'output.log' argument value isn't derived from CLI arguments
        # but from the VF configuration file. Changes to it, or to the way
        # it is handled, should be reflected here.

        mock_write_output.assert_called_once_with(
            'output.log', fakes.FAKE_SUCCESS_RUN)

        mock_print_dict.assert_called_once_with(fakes.FAKE_SUCCESS_RUN)
