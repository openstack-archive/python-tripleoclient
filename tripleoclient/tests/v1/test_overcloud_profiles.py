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

import mock

from tripleoclient import exceptions
from tripleoclient.tests import test_utils
from tripleoclient.tests.v1 import test_plugin
from tripleoclient import utils
from tripleoclient.v1 import overcloud_profiles


@mock.patch.object(utils, 'assign_and_verify_profiles', autospec=True)
class TestMatchProfiles(test_plugin.TestPluginV1):
    def setUp(self):
        super(TestMatchProfiles, self).setUp()
        self.cmd = overcloud_profiles.MatchProfiles(self.app, None)
        self.app.client_manager.tripleoclient = mock.Mock()
        self.app.client_manager.baremetal = mock.Mock()
        self.app.client_manager.compute = mock.Mock()
        self.flavors = [
            test_utils.FakeFlavor('compute'),
            test_utils.FakeFlavor('control'),
        ]
        self.app.client_manager.compute.flavors.list.return_value = (
            self.flavors)

    def test_ok(self, mock_assign):
        mock_assign.return_value = (0, 0)

        arglist = [
            '--compute-flavor', 'compute',
            '--compute-scale', '3',
            '--control-flavor', 'control',
            '--control-scale', '1',
        ]
        parsed_args = self.check_parser(self.cmd, arglist, [])

        self.cmd.take_action(parsed_args)

        mock_assign.assert_called_once_with(
            self.app.client_manager.baremetal,
            {'compute': (self.flavors[0], 3),
             'control': (self.flavors[1], 1)},
            assign_profiles=True, dry_run=False)

    def test_failed(self, mock_assign):
        mock_assign.return_value = (2, 0)

        arglist = [
            '--compute-flavor', 'compute',
            '--compute-scale', '3',
            '--control-flavor', 'control',
            '--control-scale', '1',
        ]
        parsed_args = self.check_parser(self.cmd, arglist, [])

        self.assertRaises(exceptions.ProfileMatchingError,
                          self.cmd.take_action, parsed_args)

        mock_assign.assert_called_once_with(
            self.app.client_manager.baremetal,
            {'compute': (self.flavors[0], 3),
             'control': (self.flavors[1], 1)},
            assign_profiles=True, dry_run=False)

    def test_dry_run(self, mock_assign):
        mock_assign.return_value = (0, 0)

        arglist = [
            '--compute-flavor', 'compute',
            '--compute-scale', '3',
            '--control-flavor', 'control',
            '--control-scale', '1',
            '--dry-run'
        ]
        parsed_args = self.check_parser(self.cmd, arglist, [])

        self.cmd.take_action(parsed_args)

        mock_assign.assert_called_once_with(
            self.app.client_manager.baremetal,
            {'compute': (self.flavors[0], 3),
             'control': (self.flavors[1], 1)},
            assign_profiles=True, dry_run=True)


class TestListProfiles(test_plugin.TestPluginV1):
    def setUp(self):
        super(TestListProfiles, self).setUp()
        self.cmd = overcloud_profiles.ListProfiles(self.app, None)
        self.app.client_manager.tripleoclient = mock.Mock()
        self.app.client_manager.baremetal = mock.Mock()
        self.app.client_manager.compute = mock.Mock()
        self.nodes = [
            mock.Mock(uuid='uuid1', provision_state='active',
                      properties={}, maintenance=False),
            mock.Mock(uuid='uuid2', provision_state='enroll',
                      properties={'capabilities': 'profile:compute'},
                      maintenance=False),
            mock.Mock(uuid='uuid3', provision_state='available',
                      properties={'capabilities': 'profile:compute,'
                                  'compute_profile:1,control_profile:true'},
                      maintenance=False),
            mock.Mock(uuid='uuid4', provision_state='available',
                      properties={'capabilities': 'profile:compute,'
                                  'compute_profile:0'}, maintenance=False),
            mock.Mock(uuid='uuid5', provision_state='available',
                      properties={}, maintenance=False),
            mock.Mock(uuid='uuid6', provision_state='available',
                      properties={}, maintenance=False),
            mock.Mock(uuid='uuid7', provision_state='active',
                      properties={}, maintenance=True),
        ]
        self.hypervisors = [
            mock.Mock(hypervisor_type='ironic',
                      hypervisor_hostname='uuid%d' % i,
                      status='enabled', state='up')
            for i in range(1, 6)
        ]
        self.hypervisors[-1].status = 'disabled'
        self.bm_client = self.app.client_manager.baremetal
        self.bm_client.node.list.return_value = self.nodes
        self.compute_client = self.app.client_manager.compute
        self.compute_client.hypervisors.list.return_value = self.hypervisors

    def test_list(self):
        parsed_args = self.check_parser(self.cmd, [], [])
        result = self.cmd.take_action(parsed_args)
        self.assertEqual(5, len(result[0]))
        self.assertEqual(
            [('uuid1', self.nodes[0].name, 'active', None, ''),
             ('uuid3', self.nodes[2].name, 'available', 'compute',
              'compute, control'),
             ('uuid4', self.nodes[3].name, 'available', 'compute', '')],
            result[1])

    def test_all(self):
        parsed_args = self.check_parser(self.cmd, ['--all'], [('all', True)])
        result = self.cmd.take_action(parsed_args)
        self.assertEqual(6, len(result[0]))
        self.assertEqual(
            [('uuid1', self.nodes[0].name, 'active', None, '', ''),
             ('uuid2', self.nodes[1].name, 'enroll', 'compute', '',
              'Provision state enroll'),
             ('uuid3', self.nodes[2].name, 'available', 'compute',
              'compute, control', ''),
             ('uuid4', self.nodes[3].name, 'available', 'compute', '', ''),
             ('uuid5', self.nodes[4].name, 'available', None, '',
              'Compute service disabled'),
             ('uuid6', self.nodes[5].name, 'available', None, '',
              'No hypervisor record'),
             ('uuid7', self.nodes[6].name, 'active', None, '',
              'Maintenance')],
            result[1])
