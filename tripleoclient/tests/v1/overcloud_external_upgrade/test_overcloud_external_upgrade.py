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

from tripleoclient.tests.v1.overcloud_external_upgrade import fakes
from tripleoclient.v1 import overcloud_external_upgrade


class TestOvercloudExternalUpgradeRun(fakes.TestOvercloudExternalUpgradeRun):

    def setUp(self):
        super(TestOvercloudExternalUpgradeRun, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_external_upgrade.ExternalUpgradeRun(
            self.app, app_args)

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch('tripleoclient.utils.get_stack_output_item',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_tripleo_ansible_inventory',
                return_value='/home/fake/inventory.yaml')
    @mock.patch('tripleoclient.utils.prompt_user_for_confirmation',
                return_value=True)
    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    def test_upgrade_with_user_and_tags(self, mock_execute,
                                        mock_expanduser, update_ansible,
                                        mock_confirm, mock_inventory,
                                        mock_stack_output):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--ssh-user', 'tripleo-admin',
                    '--tags', 'ceph']
        verifylist = [
            ('ssh_user', 'tripleo-admin'),
            ('tags', 'ceph'),
        ]
        mock_stack_output.return_value = []
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.cmd.take_action(parsed_args)
            update_ansible.assert_called_once_with(
                self.app.client_manager,
                container='overcloud',
                nodes=None,
                inventory_file=mock_inventory.return_value,
                playbook='external_upgrade_steps_playbook.yaml',
                node_user='tripleo-admin',
                tags='ceph',
                skip_tags='',
                verbosity=1,
                extra_vars={}
            )

    @mock.patch('tripleoclient.utils.get_stack_output_item',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_tripleo_ansible_inventory',
                return_value='/home/fake/inventory.yaml')
    @mock.patch('tripleoclient.utils.prompt_user_for_confirmation',
                return_value=True)
    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    def test_upgrade_with_user_and_extra_vars(self, mock_execute,
                                              mock_expanduser, update_ansible,
                                              mock_confirm, mock_inventory,
                                              mock_stack_output):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--ssh-user', 'tripleo-admin',
                    '--extra-vars', 'key1=val1',
                    '--extra-vars', 'key2=val2']
        verifylist = [
            ('ssh_user', 'tripleo-admin'),
            ('extra_vars', ['key1=val1', 'key2=val2'])
        ]
        mock_stack_output.return_value = ['compute1', 'compute2']
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.cmd.take_action(parsed_args)
            update_ansible.assert_called_once_with(
                self.app.client_manager,
                container='overcloud',
                nodes='!compute1:!compute2',
                inventory_file=mock_inventory.return_value,
                playbook='external_upgrade_steps_playbook.yaml',
                node_user='tripleo-admin',
                tags='',
                skip_tags='',
                verbosity=1,
                extra_vars={'key1': 'val1', 'key2': 'val2'}
            )
