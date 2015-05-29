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
from unittest import TestCase

from rdomanager_oscplugin import utils


class TestPasswordsUtil(TestCase):

    @mock.patch("os.path.isfile", return_value=False)
    @mock.patch("rdomanager_oscplugin.utils._generate_password",
                return_value="PASSWORD")
    def test_generate_passwords(self, generate_password_mock, isfile_mock):

        mock_open = mock.mock_open()

        with mock.patch('six.moves.builtins.open', mock_open):
            passwords = utils.generate_overcloud_passwords()

        self.assertEqual(sorted(mock_open().write.mock_calls), [
            mock.call('OVERCLOUD_ADMIN_PASSWORD=PASSWORD\n'),
            mock.call('OVERCLOUD_ADMIN_TOKEN=PASSWORD\n'),
            mock.call('OVERCLOUD_CEILOMETER_PASSWORD=PASSWORD\n'),
            mock.call('OVERCLOUD_CEILOMETER_SECRET=PASSWORD\n'),
            mock.call('OVERCLOUD_CINDER_PASSWORD=PASSWORD\n'),
            mock.call('OVERCLOUD_DEMO_PASSWORD=PASSWORD\n'),
            mock.call('OVERCLOUD_GLANCE_PASSWORD=PASSWORD\n'),
            mock.call('OVERCLOUD_HEAT_PASSWORD=PASSWORD\n'),
            mock.call('OVERCLOUD_HEAT_STACK_DOMAIN_PASSWORD=PASSWORD\n'),
            mock.call('OVERCLOUD_NEUTRON_PASSWORD=PASSWORD\n'),
            mock.call('OVERCLOUD_NOVA_PASSWORD=PASSWORD\n'),
            mock.call('OVERCLOUD_SWIFT_HASH=PASSWORD\n'),
            mock.call('OVERCLOUD_SWIFT_PASSWORD=PASSWORD\n'),
        ])
        self.assertEqual(generate_password_mock.call_count, 13)

        self.assertEqual(len(passwords), 13)

    @mock.patch("os.path.isfile", return_value=True)
    @mock.patch("rdomanager_oscplugin.utils._generate_password",
                return_value="PASSWORD")
    def test_load_passwords(self, generate_password_mock, isfile_mock):
        PASSWORDS = [
            'OVERCLOUD_ADMIN_PASSWORD=PASSWORD\n',
            'OVERCLOUD_ADMIN_TOKEN=PASSWORD\n',
            'OVERCLOUD_CEILOMETER_PASSWORD=PASSWORD\n',
            'OVERCLOUD_CEILOMETER_SECRET=PASSWORD\n',
            'OVERCLOUD_CINDER_PASSWORD=PASSWORD\n',
            'OVERCLOUD_DEMO_PASSWORD=PASSWORD\n',
            'OVERCLOUD_GLANCE_PASSWORD=PASSWORD\n',
            'OVERCLOUD_HEAT_PASSWORD=PASSWORD\n',
            'OVERCLOUD_HEAT_STACK_DOMAIN_PASSWORD=PASSWORD\n',
            'OVERCLOUD_NEUTRON_PASSWORD=PASSWORD\n',
            'OVERCLOUD_NOVA_PASSWORD=PASSWORD\n',
            'OVERCLOUD_SWIFT_HASH=PASSWORD\n',
            'OVERCLOUD_SWIFT_PASSWORD=PASSWORD\n',
        ]

        mock_open = mock.mock_open(read_data=''.join(PASSWORDS))
        mock_open.return_value.__iter__ = lambda self: self
        mock_open.return_value.__next__ = lambda self: self.readline()

        with mock.patch('six.moves.builtins.open', mock_open):
            passwords = utils.generate_overcloud_passwords()

        mock_open().write.assert_not_called()
        generate_password_mock.assert_not_called()

        self.assertEqual(len(passwords), 13)


class TestCheckHypervisorUtil(TestCase):
    def test_check_hypervisor_stats(self):

        mock_compute = mock.Mock()
        mock_stats = mock.Mock()

        return_values = [
            {'count': 0, 'memory_mb': 0, 'vcpus': 0},
            {'count': 1, 'memory_mb': 1, 'vcpus': 1},
        ]

        mock_stats.to_dict.side_effect = return_values
        mock_compute.hypervisors.statistics.return_value = mock_stats

        stats = utils.check_hypervisor_stats(
            mock_compute, nodes=1, memory=1, vcpu=1)

        self.assertEqual(stats, None)
        self.assertEqual(mock_stats.to_dict.call_count, 1)

        stats = utils.check_hypervisor_stats(
            mock_compute, nodes=1, memory=1, vcpu=1)
        self.assertEqual(stats, return_values[-1])
        self.assertEqual(mock_stats.to_dict.call_count, 2)


class TestWaitForStackUtil(TestCase):
    def setUp(self):
        self.mock_orchestration = mock.Mock()
        self.mock_stacks = mock.MagicMock()
        self.stack_status = mock.PropertyMock()
        type(self.mock_stacks).stack_status = self.stack_status
        self.mock_orchestration.stacks.get.return_value = self.mock_stacks

    def test_wait_for_stack_ready(self):
        self.mock_orchestration.reset_mock()
        self.mock_stacks.reset_mock()

        return_values = [
            'CREATE_COMPLETE'
        ]

        self.stack_status.side_effect = return_values

        complete = utils.wait_for_stack_ready(self.mock_orchestration, 'stack')

        self.assertEqual(complete, True)

    def test_wait_for_stack_ready_no_stack(self):
        self.mock_orchestration.reset_mock()

        self.mock_orchestration.stacks.get.return_value = None

        complete = utils.wait_for_stack_ready(self.mock_orchestration, 'stack')

        self.mock_orchestration.stacks.get.return_value = self.mock_stacks

        self.assertEqual(complete, False)

    def test_wait_for_stack_ready_failed(self):
        self.mock_orchestration.reset_mock()
        self.mock_stacks.reset_mock()

        return_values = [
            'CREATE_FAILED'
        ]

        self.stack_status.side_effect = return_values

        complete = utils.wait_for_stack_ready(self.mock_orchestration, 'stack')

        self.assertEqual(complete, False)

    def test_wait_for_stack_ready_timeout(self):
        self.mock_orchestration.reset_mock()
        self.mock_stacks.reset_mock()

        return_values = [
            mock.Mock(stack_status='CREATE_RUNNING'),
            mock.Mock(stack_status='CREATE_RUNNING'),
            mock.Mock(stack_status='CREATE_RUNNING'),
            mock.Mock(stack_status='CREATE_RUNNING'),
            mock.Mock(stack_status='CREATE_COMPLETE')
        ]

        # self.stack_status.side_effect = return_values
        self.mock_orchestration.stacks.get.side_effect = return_values

        complete = utils.wait_for_stack_ready(
            self.mock_orchestration, 'stack', loops=4, sleep=0.1)

        self.assertEqual(complete, False)


class TestWaitForDiscovery(TestCase):

    def test_wait_for_discovery_success(self):

        mock_discoverd = mock.Mock()
        self.node_uuids = [
            'NODE1',
            'NODE2',
        ]

        mock_discoverd.get_status.return_value = {
            'finished': True,
            'error': None
        }

        result = utils.wait_for_node_discovery(mock_discoverd, "TOKEN",
                                               "URL", self.node_uuids,
                                               loops=4, sleep=0.01)

        self.assertEqual(list(result), [
            ('NODE1', {'error': None, 'finished': True}),
            ('NODE2', {'error': None, 'finished': True})
        ])

    def test_wait_for_discovery_partial_success(self):

        mock_discoverd = mock.Mock()
        self.node_uuids = [
            'NODE1',
            'NODE2',
        ]

        mock_discoverd.get_status.side_effect = [{
            'finished': True,
            'error': None
        }, {
            'finished': True,
            'error': "Failed"
        }]

        result = utils.wait_for_node_discovery(mock_discoverd, "TOKEN",
                                               "URL", self.node_uuids,
                                               loops=4, sleep=0.01)

        self.assertEqual(list(result), [
            ('NODE1', {'error': None, 'finished': True}),
            ('NODE2', {'error': "Failed", 'finished': True})
        ])

    def test_wait_for_discovery_timeout(self):

        mock_discoverd = mock.Mock()
        self.node_uuids = [
            'NODE1',
            'NODE2',
        ]

        mock_discoverd.get_status.return_value = {
            'finished': False,
            'error': None
        }

        result = utils.wait_for_node_discovery(mock_discoverd, "TOKEN",
                                               "URL", self.node_uuids,
                                               loops=4, sleep=0.01)

        self.assertEqual(list(result), [])

    def test_create_environment_file(self):

        json_file_path = "env.json"

        mock_open = mock.mock_open()

        with mock.patch('six.moves.builtins.open', mock_open):
            with mock.patch('json.dumps', return_value="JSON"):
                utils.create_environment_file(path=json_file_path)

                mock_open.assert_called_with('env.json', 'w+')

        mock_open().write.assert_called_with('JSON')

    @mock.patch('rdomanager_oscplugin.utils.wait_for_provision_state')
    def test_set_nodes_state(self, wait_for_state_mock):

        wait_for_state_mock.return_value = True
        bm_client = mock.Mock()

        # One node already deployed, one in the manageable state after
        # introspection.
        nodes = [
            mock.Mock(uuid="ABCDEFGH", provision_state="active"),
            mock.Mock(uuid="IJKLMNOP", provision_state="manageable")
        ]

        skipped_states = ('active', 'available')
        utils.set_nodes_state(bm_client, nodes, 'provide', 'available',
                              skipped_states)

        bm_client.node.set_provision_state.assert_has_calls([
            mock.call('IJKLMNOP', 'provide'),
        ])

    @mock.patch("subprocess.Popen")
    def test_get_hiera_key(self, mock_popen):

        process_mock = mock.Mock()
        process_mock.communicate.return_value = ["pa$$word", ""]
        mock_popen.return_value = process_mock

        value = utils.get_hiera_key('password_name')

        self.assertEqual(value, "pa$$word")

    @mock.patch("six.moves.configparser")
    def test_get_config_value(self, mock_config_parser):

        mock_config_parser.ConfigParser().get.return_value = "pa$$word"

        value = utils.get_config_value('section', 'password_name')

        self.assertEqual(value, "pa$$word")

    def test_wait_for_provision_state(self):

        baremetal_client = mock.Mock()

        baremetal_client.node.get.return_value = mock.Mock(
            provision_state="available")

        result = utils.wait_for_provision_state(baremetal_client, 'UUID',
                                                "available")

        self.assertEqual(result, True)

    def test_wait_for_provision_state_not_found(self):

        baremetal_client = mock.Mock()

        baremetal_client.node.get.return_value = None

        result = utils.wait_for_provision_state(baremetal_client, 'UUID',
                                                "available")

        self.assertEqual(result, True)

    def test_wait_for_provision_state_fail(self):

        baremetal_client = mock.Mock()

        baremetal_client.node.get.return_value = mock.Mock(
            provision_state="not what we want")

        result = utils.wait_for_provision_state(baremetal_client, 'UUID',
                                                "available", loops=1,
                                                sleep=0.01)

        self.assertEqual(result, False)

    @mock.patch('subprocess.check_call')
    @mock.patch('os.path.exists')
    def test_remove_known_hosts(self, mock_exists, mock_check_call):

        mock_exists.return_value = True

        utils.remove_known_hosts('192.168.0.1')

        mock_check_call.assert_called_with(['ssh-keygen', '-R', '192.168.0.1'])

    @mock.patch('subprocess.check_call')
    @mock.patch('os.path.exists')
    def test_remove_known_hosts_no_file(self, mock_exists, mock_check_call):

        mock_exists.return_value = False

        utils.remove_known_hosts('192.168.0.1')

        mock_check_call.assert_not_called()
