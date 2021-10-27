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

from unittest import mock

from tripleoclient.tests.v1 import test_plugin
from tripleoclient.v1 import overcloud_admin


class TestAdminAuthorize(test_plugin.TestPluginV1):
    def setUp(self):
        super(TestAdminAuthorize, self).setUp()
        self.cmd = overcloud_admin.Authorize(self.app, None)
        self.app.client_manager = mock.Mock()

    @mock.patch('tripleoclient.utils.parse_ansible_inventory',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_key')
    @mock.patch('tripleoclient.utils.get_default_working_dir')
    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_admin_authorize(self,
                             mock_playbook,
                             mock_dir,
                             mock_key,
                             mock_inventory):
        arglist = ['--limit', 'overcloud']
        verifylist = [('limit_hosts', 'overcloud')]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        mock_dir.return_value = "/home/stack/overcloud-deploy"
        ansible_dir = "{}/config-download/overcloud".format(
            mock_dir.return_value
        )
        inventory = "{}/tripleo-ansible-inventory.yaml".format(
            ansible_dir
        )

        mock_key.return_value = '/home/stack/.ssh/id_rsa_tripleo'
        mock_inventory.return_value = ['overcloud-novacompute-0',
                                       'overcloud-dellcompute-0',
                                       'overcloud-controller-0']

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            playbook='cli-enable-ssh-admin.yaml',
            inventory=inventory,
            workdir=ansible_dir,
            key=parsed_args.overcloud_ssh_key,
            playbook_dir='/usr/share/ansible/tripleo-playbooks',
            ssh_user=parsed_args.overcloud_ssh_user,
            extra_vars={
                "ANSIBLE_PRIVATE_KEY_FILE": '/home/stack/.ssh/id_rsa_tripleo',
                "ssh_servers": ['overcloud-novacompute-0',
                                'overcloud-dellcompute-0',
                                'overcloud-controller-0']
            },
            ansible_timeout=parsed_args.overcloud_ssh_port_timeout
        )
