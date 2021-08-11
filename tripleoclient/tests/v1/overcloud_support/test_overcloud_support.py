#   Copyright 2020 Red Hat, Inc.
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

from tripleoclient.tests import fakes
from tripleoclient.v1 import overcloud_support


class TestOvercloudSupportReport(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudSupportReport, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.client_manager.workflow_engine = mock.Mock()
        self.app.client_manager.tripleoclient = mock.Mock()
        self.app.client_manager.object_store = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine
        self.app.options = fakes.FakeOptions()
        self.cmd = overcloud_support.ReportExecute(self.app, app_args)

    @mock.patch('os.chmod')
    @mock.patch('tripleoclient.workflows.package_update.get_key')
    @mock.patch('tripleoclient.utils.get_tripleo_ansible_inventory')
    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_overcloud_support_noargs(self, mock_playbook, mock_inventory,
                                      mock_key, mock_chmod):
        parsed_args = self.check_parser(self.cmd, ['all'], [])
        self.key = mock_key
        mock_inventory.return_value = '/home/stack/tripleo-ansible-inventory'
        playbook = ('/usr/share/ansible/tripleo-playbooks'
                    '/cli-support-collect-logs.yaml')

        with mock.patch('builtins.open', mock.mock_open()):
            with open('/home/stack/.ssh/id_rsa_tripleo', 'w') as key_file:
                key_file.write(self.key)
            self.cmd.take_action(parsed_args)

        mock_playbook.assert_called_once_with(
            logger=mock.ANY,
            ansible_config='/etc/ansible/ansible.cfg',
            workdir=mock.ANY,
            python_interpreter='/usr/bin/python3',
            playbook=playbook,
            inventory=mock_inventory(),
            verbosity=1,
            timeout=None,
            forks=None,
            extra_vars={
                'server_name': 'all',
                'sos_destination': '/var/lib/tripleo/support'
            }
        )

    @mock.patch('os.chmod')
    @mock.patch('tripleoclient.workflows.package_update.get_key')
    @mock.patch('tripleoclient.utils.get_tripleo_ansible_inventory')
    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_overcloud_support_args(self, mock_playbook, mock_inventory,
                                    mock_key, mock_chmod):
        arglist = ['server1', '--output', 'test']
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.key = mock_key
        mock_inventory.return_value = '/home/stack/tripleo-ansible-inventory'
        playbook = ('/usr/share/ansible/tripleo-playbooks'
                    '/cli-support-collect-logs.yaml')

        with mock.patch('builtins.open', mock.mock_open()):
            with open('/home/stack/.ssh/id_rsa_tripleo', 'w') as key_file:
                key_file.write(self.key)
            self.cmd.take_action(parsed_args)

        mock_playbook.assert_called_once_with(
            logger=mock.ANY,
            ansible_config='/etc/ansible/ansible.cfg',
            workdir=mock.ANY,
            python_interpreter='/usr/bin/python3',
            playbook=playbook,
            inventory=mock_inventory(),
            verbosity=1,
            timeout=None,
            forks=None,
            extra_vars={
                'server_name': 'server1',
                'sos_destination': 'test'
            }
        )

    @mock.patch('os.chmod')
    @mock.patch('tripleoclient.workflows.package_update.get_key')
    @mock.patch('tripleoclient.utils.get_tripleo_ansible_inventory')
    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_overcloud_support_args_stack(self, mock_playbook, mock_inventory,
                                          mock_key, mock_chmod):
        arglist = ['server1', '--output', 'test', '--stack', 'notovercloud']
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.key = mock_key

        with mock.patch('builtins.open', mock.mock_open()):
            with open('/home/stack/.ssh/id_rsa_tripleo', 'w') as key_file:
                key_file.write(self.key)
            self.cmd.take_action(parsed_args)

        playbook = ('/usr/share/ansible/tripleo-playbooks'
                    '/cli-support-collect-logs.yaml')

        mock_inventory.assert_called_once_with(
                    inventory_file='/home/stack/'
                    'tripleo-ansible-inventory.yaml',
                    ssh_user='tripleo-admin',
                    stack='notovercloud',
                    return_inventory_file_path=True)

        mock_playbook.assert_called_once_with(
            logger=mock.ANY,
            ansible_config='/etc/ansible/ansible.cfg',
            workdir=mock.ANY,
            python_interpreter='/usr/bin/python3',
            playbook=playbook,
            inventory=mock_inventory(),
            verbosity=1,
            timeout=None,
            forks=None,
            extra_vars={
                'server_name': 'server1',
                'sos_destination': 'test'
            }
        )
