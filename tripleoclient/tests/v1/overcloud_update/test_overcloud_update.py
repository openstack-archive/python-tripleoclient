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

from tripleoclient import exceptions
from tripleoclient.tests.v1.overcloud_update import fakes
from tripleoclient.v1 import overcloud_update


class TestOvercloudUpdate(fakes.TestOvercloudUpdate):

    def setUp(self):
        super(TestOvercloudUpdate, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_update.UpdateOvercloud(self.app, app_args)

    @mock.patch('tripleoclient.utils.get_stack',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_update.UpdateOvercloud.log',
                autospec=True)
    @mock.patch('tripleoclient.workflows.package_update.update_and_wait',
                autospec=True)
    def test_update_out(self, mock_update_wait, mock_logger, mock_get_stack):
        mock_update_wait.return_value = 'COMPLETE'
        mock_stack = mock.Mock()
        mock_stack.stack_name = 'mystack'
        mock_get_stack.return_value = mock_stack
        # mock_logger.return_value = mock.Mock()

        argslist = ['overcloud', '-i', '--templates']
        verifylist = [
            ('stack', 'overcloud'),
            ('interactive', True),
            ('templates', '/usr/share/openstack-tripleo-heat-templates/')
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        mock_update_wait.assert_called_once_with(
            mock_logger,
            self.app.client_manager,
            mock_stack, 'mystack', 1, 0)

    @mock.patch('tripleoclient.workflows.package_update.update_and_wait',
                autospec=True)
    def test_update_failed(self, mock_update_wait):
        mock_update_wait.return_value = 'FAILED'
        argslist = ['overcloud', '-i', '--templates']
        verifylist = [
            ('stack', 'overcloud'),
            ('interactive', True),
            ('templates', '/usr/share/openstack-tripleo-heat-templates/')
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.assertRaises(exceptions.DeploymentError,
                          self.cmd.take_action, parsed_args)
