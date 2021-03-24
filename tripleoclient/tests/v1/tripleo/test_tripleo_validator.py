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

VALIDATIONS_LOGS_CONTENTS_LIST = [{
    'plays': [{
        'play': {
            'duration': {
                'end': '2019-11-25T13:40:17.538611Z',
                'start': '2019-11-25T13:40:14.404623Z',
                'time_elapsed': '0:00:03.753'
            },
            'host': 'undercloud',
            'id': '008886df-d297-1eaa-2a74-000000000008',
            'validation_id': '512e',
            'validation_path':
            '/usr/share/ansible/validation-playbooks'
        },
        'tasks': [
            {
                'hosts': {
                    'undercloud': {
                        '_ansible_no_log': False,
                        'action': 'command',
                        'changed': False,
                        'cmd': [u'ls', '/sys/class/block/'],
                        'delta': '0:00:00.018913',
                        'end': '2019-11-25 13:40:17.120368',
                        'invocation': {
                            'module_args': {
                                '_raw_params': 'ls /sys/class/block/',
                                '_uses_shell': False,
                                'argv': None,
                                'chdir': None,
                                'creates': None,
                                'executable': None,
                                'removes': None,
                                'stdin': None,
                                'stdin_add_newline': True,
                                'strip_empty_ends': True,
                                'warn': True
                            }
                        },
                        'rc': 0,
                        'start': '2019-11-25 13:40:17.101455',
                        'stderr': '',
                        'stderr_lines': [],
                        'stdout': 'vda',
                        'stdout_lines': [u'vda']
                    }
                },
                'task': {
                    'duration': {
                        'end': '2019-11-25T13:40:17.336687Z',
                        'start': '2019-11-25T13:40:14.529880Z'
                    },
                    'id':
                    '008886df-d297-1eaa-2a74-00000000000d',
                    'name':
                    'advanced-format-512e-support : List the available drives'
                }
            },
            {
                'hosts': {
                    'undercloud': {
                        'action':
                        'advanced_format',
                        'changed': False,
                        'msg':
                        'All items completed',
                        'results': [{
                            '_ansible_item_label': 'vda',
                            '_ansible_no_log': False,
                            'ansible_loop_var': 'item',
                            'changed': False,
                            'item': 'vda',
                            'skip_reason': 'Conditional result was False',
                            'skipped': True
                        }],
                        'skipped': True
                    }
                },
                'task': {
                    'duration': {
                        'end': '2019-11-25T13:40:17.538611Z',
                        'start': '2019-11-25T13:40:17.341704Z'
                    },
                    'id': '008886df-d297-1eaa-2a74-00000000000e',
                    'name':
                    'advanced-format-512e-support: Detect the drive'
                }
            }
        ]
    }],
    'stats': {
        'undercloud': {
            'changed': 0,
            'failures': 0,
            'ignored': 0,
            'ok': 1,
            'rescued': 0,
            'skipped': 1,
            'unreachable': 0
        }
    },
    'validation_output': []
}]


class TestValidatorGroupInfo(utils.TestCommand):

    def setUp(self):
        super(TestValidatorGroupInfo, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorGroupInfo(self.app, None)

    @mock.patch('validations_libs.validation_actions.ValidationActions.'
                'group_information', return_value=GROUPS_LIST)
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

    @mock.patch('validations_libs.validation_actions.ValidationActions.'
                'list_validations',
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

    @mock.patch('validations_libs.validation_actions.ValidationActions.'
                'show_validations',
                return_value=VALIDATIONS_LIST[0])
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

    @mock.patch('validations_libs.validation_actions.ValidationActions.'
                'show_validations_parameters',
                return_value=VALIDATIONS_LIST[1])
    def test_validation_show_parameter(self, mock_validations):
        arglist = ['--validation', 'my_val2']
        verifylist = [('validation_name', ['my_val2'])]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)


class TestValidatorShowRun(utils.TestCommand):

    def setUp(self):
        super(TestValidatorShowRun, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorShowRun(self.app,
                                                             None)

    @mock.patch('validations_libs.validation_actions.ValidationLogs.'
                'get_logfile_content_by_uuid',
                return_value=VALIDATIONS_LOGS_CONTENTS_LIST)
    def test_validation_show_run(self, mock_validations):
        arglist = ['008886df-d297-1eaa-2a74-000000000008']
        verifylist = [('uuid', '008886df-d297-1eaa-2a74-000000000008')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)


class TestValidatorShowHistory(utils.TestCommand):

    def setUp(self):
        super(TestValidatorShowHistory, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_validator.TripleOValidatorShowHistory(self.app,
                                                                 None)

    @mock.patch('validations_libs.validation_actions.ValidationActions.'
                'show_history',
                return_value=VALIDATIONS_LOGS_CONTENTS_LIST)
    def test_validation_show_history(self, mock_validations):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

    @mock.patch('validations_libs.validation_actions.ValidationActions.'
                'show_history',
                return_value=VALIDATIONS_LOGS_CONTENTS_LIST)
    def test_validation_show_history_for_a_validation(self, mock_validations):
        arglist = [
            '--validation',
            '512e'
        ]
        verifylist = [('validation', '512e')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
