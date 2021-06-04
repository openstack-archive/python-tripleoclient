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

from tripleoclient.tests import fakes


FAKE_STACK = {
    'parameters': {
        'ControllerCount': 1,
        'ComputeCount': 1,
        'ObjectStorageCount': 0,
        'BlockStorageCount': 0,
        'CephStorageCount': 0,
        'DeployIdentifier': '',
    },
    'stack_name': 'overcloud',
    'stack_status': "CREATE_COMPLETE",
    'outputs': [{
        'output_key': 'KeystoneURL',
        'output_value': 'http://0.0.0.0:8000',
    }, {
        'output_key': 'EndpointMap',
        'output_value': {
            'KeystoneAdmin': {
                'host': '0.0.0.0',
                'uri': 'http://0.0.0.0:35357',
                'port': 35357,
            },
            'KeystoneInternal': {
                'host': '0.0.0.0',
                'uri': 'http://0.0.0.0:5000',
                'port': 5000,
            },
            'KeystonePublic': {
                'host': '0.0.0.0',
                'uri': 'http://0.0.0.0:5000',
                'port': 5000,
            },
            'NovaAdmin': {
                'host': '0.0.0.0',
                'uri': 'http://0.0.0.0:5000',
                'port': 8774,
            },
            'NovaInternal': {
                'host': '0.0.0.0',
                'uri': 'http://0.0.0.0:5000',
                'port': 8774,
            },
            'NovaPublic': {
                'host': '0.0.0.0',
                'uri': 'https://0.0.0.0:8774',
                'port': 8774,
            },
        }
    }]
}


def create_to_dict_mock(**kwargs):
    mock_with_to_dict = mock.Mock()
    mock_with_to_dict.configure_mock(**kwargs)
    mock_with_to_dict.to_dict.return_value = kwargs
    return mock_with_to_dict


def create_tht_stack(**kwargs):
    stack = FAKE_STACK.copy()
    stack.update(kwargs)
    return create_to_dict_mock(**stack)


def create_env_with_ntp(**kwargs):
    env = {
        'parameter_defaults': {
            'CinderEnableRbdBackend': True,
            'NtpServer': 'ntp.local',
        },
    }
    env.update(kwargs)
    return env


def create_env(**kwargs):
    env = {
        'parameter_defaults': {
            'CinderEnableRbdBackend': True,
        },
    }
    env.update(kwargs)
    return env


class TestDeployOvercloud(fakes.FakePlaybookExecution):

    def setUp(self):
        super(TestDeployOvercloud, self).setUp(ansible_mock=False)
