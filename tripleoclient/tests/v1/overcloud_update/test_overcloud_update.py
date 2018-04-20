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
import uuid

from tripleoclient import constants
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

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch('tripleoclient.utils.get_stack',
                autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_update.UpdateOvercloud.log',
                autospec=True)
    @mock.patch('tripleoclient.workflows.package_update.update',
                autospec=True)
    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.abspath')
    @mock.patch('yaml.load')
    def test_update_out(self, mock_yaml, mock_abspath, mock_open, mock_update,
                        mock_logger, mock_get_stack):
        mock_stack = mock.Mock()
        mock_stack.stack_name = 'mystack'
        mock_get_stack.return_value = mock_stack
        mock_abspath.return_value = '/home/fake/my-fake-registry.yaml'
        mock_yaml.return_value = {'fake_container': 'fake_value'}
        argslist = ['--stack', 'overcloud', '--init-minor-update',
                    '--container-registry-file', 'my-fake-registry.yaml']
        verifylist = [
            ('stack', 'overcloud'),
            ('init_minor_update', True),
            ('container_registry_file', 'my-fake-registry.yaml')
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        mock_update.assert_called_once_with(
            self.app.client_manager,
            container='overcloud',
            container_registry={'fake_container': 'fake_value'},
            ceph_ansible_playbook='/usr/share/ceph-ansible'
                                  '/site-docker.yml.sample',
            queue_name=str(uuid.uuid4()))

    @mock.patch('tripleoclient.workflows.package_update.update',
                autospec=True)
    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.abspath')
    @mock.patch('yaml.load')
    def test_update_failed(self, mock_yaml, mock_abspath, mock_open,
                           mock_update):
        mock_update.side_effect = exceptions.DeploymentError()
        mock_abspath.return_value = '/home/fake/my-fake-registry.yaml'
        mock_yaml.return_value = {'fake_container': 'fake_value'}
        argslist = ['--stack', 'overcloud', '--init-minor-update',
                    '--container-registry-file', 'my-fake-registry.yaml']
        verifylist = [
            ('stack', 'overcloud'),
            ('init_minor_update', True),
            ('container_registry_file', 'my-fake-registry.yaml')
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.assertRaises(exceptions.DeploymentError,
                          self.cmd.take_action, parsed_args)

    @mock.patch('tripleoclient.workflows.package_update.update_ansible',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_update_ansible(self, mock_open, mock_execute,
                            mock_expanduser, update_ansible):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--stack', 'overcloud', '--nodes', 'Compute', '--playbook',
                    'fake-playbook.yaml']
        verifylist = [
            ('stack', 'overcloud'),
            ('nodes', 'Compute'),
            ('static_inventory', None),
            ('playbook', 'fake-playbook.yaml')
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.cmd.take_action(parsed_args)
            update_ansible.assert_called_once_with(
                self.app.client_manager,
                nodes='Compute',
                inventory_file=mock_open().read(),
                playbook='fake-playbook.yaml',
                ansible_queue_name=constants.UPDATE_QUEUE
            )
