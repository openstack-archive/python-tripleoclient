#   Copyright 2021 Red Hat, Inc.
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

from unittest import mock

from osc_lib.tests import utils

from tripleoclient import constants
from tripleoclient.tests import fakes
from tripleoclient.v1 import overcloud_restore


class TestOvercloudRestore(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudRestore, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.options = fakes.FakeOptions()
        self.cmd = overcloud_restore.RestoreOvercloud(self.app, app_args)
        self.inventory = '/tmp/test_inventory.yaml'
        self.file = open(self.inventory, 'w').close()

    @mock.patch('os.path.isfile')
    @mock.patch('os.access')
    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_overcloud_restore_controller_(self,
                                           mock_playbook,
                                           mock_access,
                                           mock_isfile):
        arglist = [
            '--stack',
            'overcloud',
            '--node-name',
            'overcloud-controller-0'
        ]
        verifylist = []
        mock_isfile.return_value = True
        mock_access.return_value = True

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        parameter = 'tripleo_backup_and_restore_overcloud_restore_name'

        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook='cli-overcloud-restore-node.yaml',
            inventory=constants.ANSIBLE_INVENTORY.format('overcloud'),
            tags=None,
            skip_tags=None,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=3,
            extra_vars={
              parameter: arglist[3]
            },
            ssh_user='stack'
        )
