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
        self.cmd.tempest_run_dir = '/home/user/tempest'

    @mock.patch('rdomanager_oscplugin.v1.overcloud_validate.ValidateOvercloud.'
                '_setup_dir')
    @mock.patch('os.chdir')
    @mock.patch('rdomanager_oscplugin.utils.run_shell')
    def test_validate_ok(self, mock_run_shell, mock_os_chdir, mock_setup_dir):

        argslist = ['--overcloud-auth-url', 'http://foo',
                    '--overcloud-admin-password', 'password',
                    '--network-id', '42',
                    '--deployer-input', 'partial_config_file',
                    '--tempest-args', 'bar',
                    '--skipfile', 'skip']
        verifylist = [
            ('overcloud_auth_url', 'http://foo'),
            ('overcloud_admin_password', 'password'),
            ('deployer_input', 'partial_config_file'),
            ('tempest_args', 'bar'),
            ('skipfile', 'skip')
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

        mock_setup_dir.assert_called_once_with()
        mock_os_chdir.assert_called_with('/home/user/tempest')
        mock_run_shell.assert_has_calls([
            mock.call('/usr/share/openstack-tempest-kilo/tools/'
                      'configure-tempest-directory'),
            mock.call('./tools/config_tempest.py --out etc/tempest.conf '
                      '--network-id 42 '
                      '--deployer-input partial_config_file '
                      '--debug --create '
                      'compute.allow_tenant_isolation true '
                      'compute.build_timeout 500 '
                      'compute.image_ssh_user cirros '
                      'compute.ssh_user cirros '
                      'identity.admin_password password '
                      'identity.uri http://foo '
                      'network.build_timeout 500 '
                      'network.tenant_network_cidr 192.168.0.0/24 '
                      'object-storage.operator_role swiftoperator '
                      'orchestration.stack_owner_role heat_stack_user '
                      'scenario.ssh_user cirros '
                      'volume.build_timeout 500'),
            mock.call('./tools/run-tests.sh bar --skip-file skip')
        ])
