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

from unittest import TestCase

import mock

from rdomanager_oscplugin import utils


class TestPasswordsUtil(TestCase):
    def test_generate_passwords(self):

        passwords = utils.generate_overcloud_passwords()
        passwords2 = utils.generate_overcloud_passwords()

        self.assertEqual(len(passwords), 13)
        self.assertNotEqual(passwords, passwords2)


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
