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

import mock

from tripleoclient.tests.v1 import test_plugin
from tripleoclient import utils
from tripleoclient.v1 import overcloud_admin
from tripleoclient.workflows import deployment


@mock.patch.object(utils, 'get_stack', autospec=True)
@mock.patch.object(deployment, 'get_hosts_and_enable_ssh_admin', autospec=True)
class TestAdminAuthorize(test_plugin.TestPluginV1):
    def setUp(self):
        super(TestAdminAuthorize, self).setUp()
        self.cmd = overcloud_admin.Authorize(self.app, None)
        self.app.client_manager = mock.Mock()

    def test_ok(self, mock_get_host_and_enable_ssh_admin, mock_get_stack):
        arglist = []
        parsed_args = self.check_parser(self.cmd, arglist, [])
        mock_stack = mock.Mock()
        mock_get_stack.return_value = mock_stack

        self.cmd.take_action(parsed_args)
        mock_get_host_and_enable_ssh_admin.assert_called_once_with(
            mock_stack,
            parsed_args.overcloud_ssh_network,
            parsed_args.overcloud_ssh_user,
            mock.ANY,
            parsed_args.overcloud_ssh_port_timeout,
            mock.ANY
        )
