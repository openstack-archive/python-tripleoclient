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

VALIDATIONS_LIST = [{
    'description': 'My Validation One Description',
    'groups': ['prep', 'pre-deployment'],
    'id': 'my_val1',
    'name': 'My Validition One Name',
    'parameters': {}
}, {
    'description': 'My Validation Two Description',
    'groups': ['prep', 'pre-introspection'],
    'id': 'my_val2',
    'name': 'My Validition Two Name',
    'parameters': {'min_value': 8}
}]

GROUPS_LIST = [
    ('group1', 'Group1 description'),
    ('group2', 'Group2 description'),
    ('group3', 'Group3 description'),
]


class TestValidatorGroupInfo(utils.TestCommand):

    def setUp(self):
        super(TestValidatorGroupInfo, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorGroupInfo(self.app, None)

    @mock.patch('tripleoclient.utils.parse_all_validation_groups_on_disk',
                return_value=GROUPS_LIST)
    def test_show_group_info(self, mock_validations):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)


class TestValidatorList(utils.TestCommand):

    def setUp(self):
        super(TestValidatorList, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorList(self.app, None)

    @mock.patch('tripleoclient.utils.parse_all_validations_on_disk',
                return_value=VALIDATIONS_LIST)
    def test_validation_list_noargs(self, mock_validations):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)


class TestValidatorShow(utils.TestCommand):

    def setUp(self):
        super(TestValidatorShow, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorShow(self.app, None)

    @mock.patch('tripleoclient.utils.parse_all_validations_on_disk',
                return_value=VALIDATIONS_LIST)
    def test_validation_show(self, mock_validations):
        arglist = ['my_val1']
        verifylist = [('validation_id', 'my_val1')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)


class TestValidatorShowParameter(utils.TestCommand):

    def setUp(self):
        super(TestValidatorShowParameter, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorShowParameter(self.app,
                                                                   None)

    @mock.patch('tripleoclient.utils.parse_all_validations_on_disk',
                return_value=VALIDATIONS_LIST)
    def test_validation_show_parameter(self, mock_validations):
        arglist = ['--validation', 'my_val2']
        verifylist = [('validation_name', ['my_val2'])]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
