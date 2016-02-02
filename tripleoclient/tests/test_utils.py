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
import os.path
import tempfile

from tripleoclient import exceptions
from tripleoclient import utils
from unittest import TestCase


class TestPasswordsUtil(TestCase):

    @mock.patch("os.path.isfile", return_value=False)
    @mock.patch("passlib.utils.generate_password",
                return_value="PASSWORD")
    def test_generate_passwords(self, generate_password_mock, isfile_mock):

        mock_open = mock.mock_open()

        with mock.patch('six.moves.builtins.open', mock_open):
            passwords = utils.generate_overcloud_passwords()

        self.assertEqual(sorted(mock_open().write.mock_calls), [
            mock.call('NEUTRON_METADATA_PROXY_SHARED_SECRET=PASSWORD\n'),
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
        self.assertEqual(generate_password_mock.call_count, 14)

        self.assertEqual(len(passwords), 14)

    @mock.patch("os.path.isfile", return_value=True)
    @mock.patch("passlib.utils.generate_password",
                return_value="PASSWORD")
    def test_load_passwords(self, generate_password_mock, isfile_mock):
        PASSWORDS = [
            'NEUTRON_METADATA_PROXY_SHARED_SECRET=PASSWORD\n',
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

        generate_password_mock.assert_not_called()
        self.assertEqual(len(passwords), 14)
        for name in utils._PASSWORD_NAMES:
            self.assertEqual('PASSWORD', passwords[name])


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

    def mock_event(self, resource_name, id, resource_status_reason,
                   resource_status, event_time):
        e = mock.Mock()
        e.resource_name = resource_name
        e.id = id
        e.resource_status_reason = resource_status_reason
        e.resource_status = resource_status
        e.event_time = event_time
        return e

    @mock.patch("heatclient.common.event_utils.get_events")
    @mock.patch('time.sleep', return_value=None)
    def test_wait_for_stack_ready(self, sleep_mock, mock_el):
        stack = mock.Mock()
        stack.stack_name = 'stack'
        stack.stack_status = "CREATE_COMPLETE"
        self.mock_orchestration.stacks.get.return_value = stack

        complete = utils.wait_for_stack_ready(self.mock_orchestration, 'stack')
        self.assertTrue(complete)
        sleep_mock.assert_not_called()

    def test_wait_for_stack_ready_no_stack(self):
        self.mock_orchestration.stacks.get.return_value = None

        complete = utils.wait_for_stack_ready(self.mock_orchestration, 'stack')

        self.assertFalse(complete)

    @mock.patch("heatclient.common.event_utils.get_events")
    @mock.patch('time.sleep', return_value=None)
    def test_wait_for_stack_ready_failed(self, sleep_mock, mock_el):
        stack = mock.Mock()
        stack.stack_name = 'stack'
        stack.stack_status = "CREATE_FAILED"
        self.mock_orchestration.stacks.get.return_value = stack

        complete = utils.wait_for_stack_ready(self.mock_orchestration, 'stack')

        self.assertFalse(complete)

        sleep_mock.assert_not_called()

    @mock.patch("heatclient.common.event_utils.get_events")
    @mock.patch('time.sleep', return_value=None)
    def test_wait_for_stack_in_progress(self, sleep_mock, mock_el):

        mock_el.side_effect = [[
            self.mock_event('stack', 'aaa', 'Stack CREATE started',
                            'CREATE_IN_PROGRESS', '2015-10-14T02:25:21Z'),
            self.mock_event('thing', 'bbb', 'state changed',
                            'CREATE_IN_PROGRESS', '2015-10-14T02:25:21Z'),
        ], [
            self.mock_event('thing', 'ccc', 'state changed',
                            'CREATE_COMPLETE', '2015-10-14T02:25:43Z'),
            self.mock_event('stack', 'ddd',
                            'Stack CREATE completed successfully',
                            'CREATE_COMPLETE', '2015-10-14T02:25:43Z'),
        ], [], []]

        stack = mock.Mock()
        stack.stack_name = 'stack'
        stack.stack_status = 'CREATE_IN_PROGRESS'
        complete_stack = mock.Mock()
        complete_stack.stack_name = 'stack'
        complete_stack.stack_status = 'CREATE_COMPLETE'
        self.mock_orchestration.stacks.get.side_effect = [
            stack, stack, stack, complete_stack]

        utils.wait_for_stack_ready(self.mock_orchestration, 'stack')

        self.assertEqual(2, sleep_mock.call_count)


class TestWaitForIntrospection(TestCase):

    def test_wait_for_introspection_success(self):

        mock_inspector = mock.Mock()
        self.node_uuids = [
            'NODE1',
            'NODE2',
        ]

        mock_inspector.get_status.return_value = {
            'finished': True,
            'error': None
        }

        result = utils.wait_for_node_introspection(mock_inspector, "TOKEN",
                                                   "URL", self.node_uuids,
                                                   loops=4, sleep=0.01)

        self.assertEqual(list(result), [
            ('NODE1', {'error': None, 'finished': True}),
            ('NODE2', {'error': None, 'finished': True})
        ])

    def test_wait_for_introspection_partial_success(self):

        mock_inspector = mock.Mock()
        self.node_uuids = [
            'NODE1',
            'NODE2',
        ]

        mock_inspector.get_status.side_effect = [{
            'finished': True,
            'error': None
        }, {
            'finished': True,
            'error': "Failed"
        }]

        result = utils.wait_for_node_introspection(mock_inspector, "TOKEN",
                                                   "URL", self.node_uuids,
                                                   loops=4, sleep=0.01)

        self.assertEqual(list(result), [
            ('NODE1', {'error': None, 'finished': True}),
            ('NODE2', {'error': "Failed", 'finished': True})
        ])

    def test_wait_for_introspection_timeout(self):

        mock_inspector = mock.Mock()
        self.node_uuids = [
            'NODE1',
            'NODE2',
        ]

        mock_inspector.get_status.return_value = {
            'finished': False,
            'error': None
        }

        result = utils.wait_for_node_introspection(mock_inspector, "TOKEN",
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

    @mock.patch('tripleoclient.utils.wait_for_provision_state')
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
        uuids = list(utils.set_nodes_state(bm_client, nodes, 'provide',
                                           'available', skipped_states))

        bm_client.node.set_provision_state.assert_has_calls([
            mock.call('IJKLMNOP', 'provide'),
        ])

        self.assertEqual(uuids, ['IJKLMNOP', ])

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
            provision_state="available", last_error=None)

        utils.wait_for_provision_state(baremetal_client, 'UUID', "available")

    def test_wait_for_provision_state_not_found(self):

        baremetal_client = mock.Mock()

        baremetal_client.node.get.return_value = None

        utils.wait_for_provision_state(baremetal_client, 'UUID', "available")

    def test_wait_for_provision_state_timeout(self):

        baremetal_client = mock.Mock()

        baremetal_client.node.get.return_value = mock.Mock(
            provision_state="not what we want", last_error=None)

        with self.assertRaises(exceptions.Timeout):
            utils.wait_for_provision_state(baremetal_client, 'UUID',
                                           "available", loops=1, sleep=0.01)

    def test_wait_for_provision_state_fail(self):

        baremetal_client = mock.Mock()

        baremetal_client.node.get.return_value = mock.Mock(
            provision_state="enroll",
            last_error="node on fire; returning to previous state.")

        with self.assertRaises(exceptions.StateTransitionFailed):
            utils.wait_for_provision_state(baremetal_client, 'UUID',
                                           "available", loops=1, sleep=0.01)

    @mock.patch('subprocess.check_call')
    @mock.patch('os.path.exists')
    def test_remove_known_hosts(self, mock_exists, mock_check_call):

        mock_exists.return_value = True

        utils.remove_known_hosts('192.168.0.1')
        known_hosts = os.path.expanduser("~/.ssh/known_hosts")

        mock_check_call.assert_called_with(
            ['ssh-keygen', '-R', '192.168.0.1', '-f', known_hosts])

    @mock.patch('subprocess.check_call')
    @mock.patch('os.path.exists')
    def test_remove_known_hosts_no_file(self, mock_exists, mock_check_call):

        mock_exists.return_value = False

        utils.remove_known_hosts('192.168.0.1')

        mock_check_call.assert_not_called()

    def test_empty_file_checksum(self):
        # Used a NamedTemporaryFile since it's deleted when the file is closed.
        with tempfile.NamedTemporaryFile() as empty_temp_file:
            self.assertEqual(utils.file_checksum(empty_temp_file.name),
                             'd41d8cd98f00b204e9800998ecf8427e')

    def test_non_empty_file_checksum(self):
        # Used a NamedTemporaryFile since it's deleted when the file is closed.
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(b'foo')
            temp_file.flush()

            self.assertEqual(utils.file_checksum(temp_file.name),
                             'acbd18db4cc2f85cedef654fccc4a4d8')

    def test_shouldnt_checksum_open_special_files(self):
        self.assertRaises(ValueError, utils.file_checksum, '/dev/random')
        self.assertRaises(ValueError, utils.file_checksum, '/dev/zero')


class TestCheckNodesCount(TestCase):

    def setUp(self):
        self.baremetal = mock.Mock()
        self.defaults = {
            'ControllerCount': 1,
            'ComputeCount': 1,
            'ObjectStorageCount': 0,
            'BlockStorageCount': 0,
            'CephStorageCount': 0,
        }
        self.stack = mock.Mock(parameters=self.defaults)

        def ironic_node_list(*args, **kwargs):
            if kwargs.get('associated') is True:
                nodes = range(2)
            elif kwargs.get('maintenance') is False:
                nodes = range(1)
            return nodes
        self.baremetal.node.list.side_effect = ironic_node_list

    def test_check_nodes_count_deploy_enough_nodes(self):
        user_params = {'ControllerCount': 2}
        self.assertEqual(True,
                         utils.check_nodes_count(self.baremetal, None,
                                                 user_params, self.defaults))

    def test_check_nodes_count_deploy_too_much(self):
        user_params = {'ControllerCount': 3}
        self.assertRaises(exceptions.DeploymentError, utils.check_nodes_count,
                          self.baremetal, None, user_params, self.defaults)

    def test_check_nodes_count_scale_enough_nodes(self):
        user_params = {'ControllerCount': 2}
        self.assertEqual(True,
                         utils.check_nodes_count(self.baremetal, None,
                                                 user_params, self.defaults))

    def test_check_nodes_count_scale_too_much(self):
        user_params = {'ControllerCount': 3}
        self.assertRaises(exceptions.DeploymentError, utils.check_nodes_count,
                          self.baremetal, self.stack, user_params,
                          self.defaults)

    def test_check_default_param_not_in_stack(self):
        missing_param = 'CephStorageCount'
        self.stack.parameters = self.defaults.copy()
        del self.stack.parameters[missing_param]

        self.assertRaises(ValueError, utils.check_nodes_count,
                          self.baremetal, self.stack, dict(), self.defaults)


class TestEnsureRunAsNormalUser(TestCase):

    @mock.patch('os.geteuid')
    def test_ensure_run_as_normal_user(self, os_geteuid_mock):
        os_geteuid_mock.return_value = 1000
        self.assertEqual(utils.ensure_run_as_normal_user(), None)

    @mock.patch('os.geteuid')
    def test_ensure_run_as_normal_user_root(self, os_geteuid_mock):
        os_geteuid_mock.return_value = 0
        self.assertRaises(exceptions.RootUserExecution,
                          utils.ensure_run_as_normal_user)
