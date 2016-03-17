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

from tripleoclient.tests.v1.test_plugin import TestPluginV1

# Load the plugin init module for the plugin list and show commands
from tripleoclient.v1 import undercloud


class FakePluginV1Client(object):
    def __init__(self, **kwargs):
        self.auth_token = kwargs['token']
        self.management_url = kwargs['endpoint']


class TestUndercloudInstall(TestPluginV1):

    def setUp(self):
        super(TestUndercloudInstall, self).setUp()

        # Get the command object to test
        self.cmd = undercloud.InstallUndercloud(self.app, None)

    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_install(self, mock_subprocess):
        arglist = []
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        self.cmd.take_action(parsed_args)

        mock_subprocess.assert_called_with('instack-install-undercloud')


class TestUndercloudUpgrade(TestPluginV1):
    def setUp(self):
        super(TestUndercloudUpgrade, self).setUp()

        # Get the command object to test
        self.cmd = undercloud.UpgradeUndercloud(self.app, None)

    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_upgrade(self, mock_subprocess):
        arglist = []
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        self.cmd.take_action(parsed_args)

        mock_subprocess.assert_has_calls(
            [
                mock.call(['sudo', 'yum', 'update', '-y']),
                mock.call('instack-install-undercloud'),
                mock.call(['sudo', 'systemctl', 'restart',
                          'openstack-nova-api'])
            ]
        )
