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
import os
import subprocess

from tripleoclient.tests.v1.test_plugin import TestPluginV1

# Load the plugin init module for the plugin list and show commands
from tripleoclient.v1 import undercloud_deploy


class FakePluginV1Client(object):
    def __init__(self, **kwargs):
        self.auth_token = kwargs['token']
        self.management_url = kwargs['endpoint']


class TestUndercloudDeploy(TestPluginV1):

    def setUp(self):
        super(TestUndercloudDeploy, self).setUp()

        # Get the command object to test
        self.cmd = undercloud_deploy.DeployUndercloud(self.app, None)
        # Substitute required packages
        self.cmd.prerequisites = iter(['foo', 'bar', 'baz'])

    @mock.patch('os.path.exists')
    @mock.patch('tripleo_common.utils.passwords.generate_passwords')
    @mock.patch('yaml.safe_dump')
    def test_update_passwords_env_init(self, mock_dump, mock_pw, mock_exists):
        pw_dict = {"GeneratedPassword": 123}
        pw_env_path = os.path.join(self.temp_homedir,
                                   'tripleo-undercloud-passwords.yaml')

        mock_pw.return_value = pw_dict
        mock_exists.return_value = False
        mock_open_context = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open_context):
            self.cmd._update_passwords_env()

        mock_exists.assert_called_once_with(pw_env_path)
        mock_open_context.assert_called_once_with(pw_env_path, 'w')
        mock_open_handle = mock_open_context()
        mock_dump.assert_called_once_with({'parameter_defaults': pw_dict},
                                          mock_open_handle,
                                          default_flow_style=False)

    @mock.patch('os.path.exists')
    @mock.patch('tripleo_common.utils.passwords.generate_passwords')
    @mock.patch('yaml.safe_dump')
    def test_update_passwords_env_update(self, mock_dump, mock_pw,
                                         mock_exists):
        pw_dict = {"GeneratedPassword": 123}
        pw_env_path = os.path.join(self.temp_homedir,
                                   'tripleo-undercloud-passwords.yaml')

        mock_pw.return_value = pw_dict
        mock_exists.return_value = True
        mock_open_context = mock.mock_open(
            read_data='parameter_defaults: {ExistingKey: xyz}\n')
        with mock.patch('six.moves.builtins.open', mock_open_context):
            self.cmd._update_passwords_env(
                passwords={'ADefault': 456, 'ExistingKey': 'dontupdate'})

        mock_exists.assert_called_once_with(pw_env_path)
        mock_open_context.assert_called_with(pw_env_path, 'w')
        mock_open_handle = mock_open_context()
        expected_dict = {'parameter_defaults': {'GeneratedPassword': 123,
                                                'ExistingKey': 'xyz',
                                                'ADefault': 456}}
        mock_dump.assert_called_once_with(expected_dict,
                                          mock_open_handle,
                                          default_flow_style=False)

    @mock.patch('subprocess.check_call', autospec=True)
    def test_install_prerequisites(self, mock_check_call):
        mock_check_call.side_effect = [
            True, True,
            subprocess.CalledProcessError(1, ''), True]
        arglist = []
        verifylist = []
        self.check_parser(self.cmd, arglist, verifylist)
        self.cmd._install_prerequisites(False)

        mock_check_call.assert_has_calls([
            mock.call(['rpm', '-q', 'foo']),
            mock.call(['rpm', '-q', 'bar']),
            mock.call(['rpm', '-q', 'baz']),
            mock.call(['yum', '-y', 'install', 'baz'])
        ])

    @mock.patch('subprocess.check_call', autospec=True)
    def test_fail_prerequisites(self, mock_check_call):
        mock_check_call.side_effect = [
            True, subprocess.CalledProcessError(127, ''), True, True]
        arglist = []
        verifylist = []
        self.check_parser(self.cmd, arglist, verifylist)
        try:
            self.cmd._install_prerequisites(False)
        except Exception as e:
            self.assertTrue('Failed to check for prerequisites: '
                            'bar, the exit status 127' in str(e))

        mock_check_call.assert_has_calls([
            mock.call(['rpm', '-q', 'foo']),
            mock.call(['rpm', '-q', 'bar'])])
