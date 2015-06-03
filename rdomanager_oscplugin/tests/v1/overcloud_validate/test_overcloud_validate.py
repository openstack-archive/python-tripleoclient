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

from rdomanager_oscplugin.tests.v1.overcloud_validate import fakes
from rdomanager_oscplugin.v1 import overcloud_validate


class TestOvercloudValidate(fakes.TestOvercloudValidate):

    def setUp(self):
        super(TestOvercloudValidate, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_validate.ValidateOvercloud(self.app, None)

    @mock.patch('os.chdir')
    @mock.patch('os.mkdir')
    @mock.patch('os.stat')
    @mock.patch('os.path.expanduser')
    @mock.patch('rdomanager_oscplugin.utils.run_shell')
    def test_validate_ok(self, mock_run_shell, mock_os_path_expanduser,
                         mock_os_stat, mock_os_mkdir, mock_os_chdir):
        mock_os_stat.return_value = True
        mock_os_path_expanduser.return_value = '/home/user'

        argslist = ['--overcloud-auth-url', 'http://foo',
                    '--overcloud-admin-password', 'password',
                    '--tempest-args', 'bar']
        verifylist = [
            ('overcloud_auth_url', 'http://foo'),
            ('overcloud_admin_password', 'password'),
            ('tempest_args', 'bar')
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_os_stat.assert_called_with('/home/user/tempest')
        self.assertEqual(0, mock_os_mkdir.call_count)
        mock_os_chdir.assert_called_with('/home/user/tempest')
        mock_run_shell.assert_has_calls([
            mock.call('/usr/share/openstack-tempest-kilo/tools/'
                      'configure-tempest-directory'),
            mock.call('./tools/config_tempest.py --out etc/tempest.conf '
                      '--debug --create '
                      'identity.uri http://foo '
                      'compute.allow_tenant_isolation true '
                      'object-storage.operator_role SwiftOperator '
                      'identity.admin_password password '
                      'compute.build_timeout 500 '
                      'compute.image_ssh_user cirros '
                      'compute.ssh_user cirros '
                      'network.build_timeout 500 '
                      'volume.build_timeout 500 '
                      'scenario.ssh_user cirros'),
            mock.call('./run_tempest.sh --no-virtual-env -- bar 2>&1 | '
                      'tee /home/user/tempest/tempest-run.log')
        ])
