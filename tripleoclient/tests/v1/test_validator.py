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
from tripleoclient.v1 import tripleo_validator


class TestValidatorList(utils.TestCommand):

    def setUp(self):
        super(TestValidatorList, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorList(self.app, None)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine

    @mock.patch('tripleoclient.workflows.validations.list_validations',
                autospec=True)
    def test_validation_list_noargs(self, plan_mock):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        plan_mock.assert_called_once_with(
            mock.ANY, {'group_names': []})


class TestValidatorRun(utils.TestCommand):

    def setUp(self):
        super(TestValidatorRun, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorRun(self.app, None)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine

    @mock.patch('tripleoclient.workflows.validations.run_validations',
                autospec=True)
    def test_validation_run_withargs(self, plan_mock):
        arglist = [
            '--validation-name',
            'check-ftype'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        plan_mock.assert_called_once_with(
            mock.ANY,
            {'plan': 'overcloud',
             'validation_names': ['check-ftype']})
