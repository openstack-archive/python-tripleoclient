# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import netaddr
from unittest import mock

import ironic_inspector_client
from oslo_concurrency import processutils
from oslo_utils import units

from tripleoclient import exceptions
from tripleoclient.tests import fakes
from tripleoclient.workflows import baremetal


class TestBaremetalWorkflows(fakes.FakePlaybookExecution):

    def setUp(self):
        super(TestBaremetalWorkflows, self).setUp()
        self.glance = self.app.client_manager.image = mock.Mock()
        self.tripleoclient = mock.Mock()
        self.app.client_manager.tripleoclient = self.tripleoclient
        self.mock_playbook = mock.patch(
            'tripleoclient.utils.run_ansible_playbook',
            autospec=True
        )
        self.mock_playbook.start()
        self.addCleanup(self.mock_playbook.stop)

        self.node_update = [{'op': 'add',
                             'path': '/properties/capabilities',
                             'value': 'boot_option:local'},
                            {'op': 'add',
                             'path': '/driver_info/deploy_ramdisk',
                             'value': None},
                            {'op': 'add',
                             'path': '/driver_info/deploy_kernel',
                             'value': None},
                            {'op': 'add',
                             'path': '/driver_info/rescue_ramdisk',
                             'value': None},
                            {'op': 'add',
                             'path': '/driver_info/rescue_kernel',
                             'value': None}]
        # Mock data
        self.disks = [
            {'name': '/dev/sda', 'size': 11 * units.Gi},
            {'name': '/dev/sdb', 'size': 2 * units.Gi},
            {'name': '/dev/sdc', 'size': 5 * units.Gi},
            {'name': '/dev/sdd', 'size': 21 * units.Gi},
            {'name': '/dev/sde', 'size': 13 * units.Gi},
        ]
        for i, disk in enumerate(self.disks):
            disk['wwn'] = 'wwn%d' % i
            disk['serial'] = 'serial%d' % i
        self.baremetal.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH"),
        ]

        self.node = mock.Mock(uuid="ABCDEFGH", properties={})
        self.baremetal.node.get.return_value = self.node
        self.inspector.get_data.return_value = {
            'inventory': {'disks': self.disks}
        }
        self.existing_nodes = [
            {'uuid': '1', 'driver': 'ipmi',
             'driver_info': {'ipmi_address': '10.0.0.1'}},
            {'uuid': '2', 'driver': 'pxe_ipmitool',
             'driver_info': {'ipmi_address': '10.0.0.1', 'ipmi_port': 6235}},
            {'uuid': '3', 'driver': 'foobar', 'driver_info': {}},
            {'uuid': '4', 'driver': 'fake',
             'driver_info': {'fake_address': 42}},
            {'uuid': '5', 'driver': 'ipmi', 'driver_info': {}},
            {'uuid': '6', 'driver': 'pxe_drac',
             'driver_info': {'drac_address': '10.0.0.2'}},
            {'uuid': '7', 'driver': 'pxe_drac',
             'driver_info': {'drac_address': '10.0.0.3', 'drac_port': 6230}},
        ]

    def test_register_or_update_success(self):
        self.assertEqual(baremetal.register_or_update(
            self.app.client_manager,
            nodes_json=[],
            instance_boot_option='local'
        ), [mock.ANY])

    def test_introspect_success(self):
        baremetal.introspect(self.app.client_manager, node_uuids=[],
                             run_validations=True, concurrency=20,
                             node_timeout=1200, max_retries=1,
                             retry_timeout=120)

    def test_introspect_manageable_nodes_success(self):
        baremetal.introspect_manageable_nodes(
            self.app.client_manager, run_validations=False, concurrency=20,
            node_timeout=1200, max_retries=1, retry_timeout=120,
        )

    def test_run_instance_boot_option(self):
        result = baremetal._configure_boot(
            self.app.client_manager,
            node_uuid='MOCK_UUID',
            instance_boot_option='netboot')
        self.assertIsNone(result)
        self.node_update[0].update({'value': 'boot_option:netboot'})
        self.baremetal.node.update.assert_called_once_with(
            mock.ANY, self.node_update)

    def test_run_instance_boot_option_not_set(self):
        result = baremetal._configure_boot(
            self.app.client_manager,
            node_uuid='MOCK_UUID')
        self.assertIsNone(result)
        self.node_update[0].update({'value': ''})
        self.baremetal.node.update.assert_called_once_with(
            mock.ANY, self.node_update)

    def test_run_instance_boot_option_already_set_no_overwrite(self):
        node_mock = mock.MagicMock()
        node_mock.properties.get.return_value = ({'boot_option': 'netboot'})
        self.app.client_manager.baremetal.node.get.return_value = node_mock

        result = baremetal._configure_boot(
            self.app.client_manager,
            node_uuid='MOCK_UUID')
        self.assertIsNone(result)
        self.node_update[0].update({'value': 'boot_option:netboot'})
        self.baremetal.node.update.assert_called_once_with(
            mock.ANY, self.node_update)

    def test_run_instance_boot_option_already_set_do_overwrite(self):
        node_mock = mock.MagicMock()
        node_mock.properties.get.return_value = ({'boot_option': 'netboot'})
        self.app.client_manager.baremetal.node.get.return_value = node_mock
        result = baremetal._configure_boot(
            self.app.client_manager,
            node_uuid='MOCK_UUID',
            instance_boot_option='local')
        self.assertIsNone(result)
        self.node_update[0].update({'value': 'boot_option:local'})
        self.baremetal.node.update.assert_called_once_with(
            mock.ANY, self.node_update)

    def test_run_exception_on_node_update(self):
        self.baremetal.node.update.side_effect = Exception("Update error")
        self.assertRaises(
            Exception,
            baremetal._configure_boot,
            self.app.client_manager,
            node_uuid='MOCK_UUID')

        self.inspector.get_data.return_value = {
            'inventory': {'disks': self.disks}
        }

    def test_smallest(self):
        baremetal._apply_root_device_strategy(
            self.app.client_manager,
            node_uuid='MOCK_UUID',
            strategy='smallest')
        self.assertEqual(self.baremetal.node.update.call_count, 1)
        root_device_args = self.baremetal.node.update.call_args_list[0]
        expected_patch = [{'op': 'add', 'path': '/properties/root_device',
                           'value': {'wwn': 'wwn2'}},
                          {'op': 'add', 'path': '/properties/local_gb',
                           'value': 4}]
        self.assertEqual(mock.call('ABCDEFGH', expected_patch),
                         root_device_args)

    def test_smallest_with_ext(self):
        self.disks[2]['wwn_with_extension'] = 'wwnext'
        baremetal._apply_root_device_strategy(
            self.app.client_manager,
            node_uuid='MOCK_UUID',
            strategy='smallest')
        self.assertEqual(self.baremetal.node.update.call_count, 1)
        root_device_args = self.baremetal.node.update.call_args_list[0]
        expected_patch = [{'op': 'add', 'path': '/properties/root_device',
                           'value': {'wwn_with_extension': 'wwnext'}},
                          {'op': 'add', 'path': '/properties/local_gb',
                           'value': 4}]
        self.assertEqual(mock.call('ABCDEFGH', expected_patch),
                         root_device_args)

    def test_largest(self):
        baremetal._apply_root_device_strategy(
            self.app.client_manager,
            node_uuid='MOCK_UUID',
            strategy='largest')
        self.assertEqual(self.baremetal.node.update.call_count, 1)
        root_device_args = self.baremetal.node.update.call_args_list[0]
        expected_patch = [{'op': 'add', 'path': '/properties/root_device',
                           'value': {'wwn': 'wwn3'}},
                          {'op': 'add', 'path': '/properties/local_gb',
                           'value': 20}]
        self.assertEqual(mock.call('ABCDEFGH', expected_patch),
                         root_device_args)

    def test_largest_with_ext(self):
        self.disks[3]['wwn_with_extension'] = 'wwnext'
        baremetal._apply_root_device_strategy(
            self.app.client_manager,
            node_uuid='MOCK_UUID',
            strategy='largest')
        self.assertEqual(self.baremetal.node.update.call_count, 1)
        root_device_args = self.baremetal.node.update.call_args_list[0]
        expected_patch = [{'op': 'add', 'path': '/properties/root_device',
                           'value': {'wwn_with_extension': 'wwnext'}},
                          {'op': 'add', 'path': '/properties/local_gb',
                           'value': 20}]
        self.assertEqual(mock.call('ABCDEFGH', expected_patch),
                         root_device_args)

    def test_no_overwrite(self):
        self.node.properties['root_device'] = {'foo': 'bar'}
        baremetal._apply_root_device_strategy(
            self.app.client_manager,
            node_uuid='MOCK_UUID',
            strategy='smallest')
        self.assertEqual(self.baremetal.node.update.call_count, 0)

    def test_with_overwrite(self):
        self.node.properties['root_device'] = {'foo': 'bar'}
        baremetal._apply_root_device_strategy(
            self.app.client_manager,
            node_uuid='MOCK_UUID',
            strategy='smallest',
            overwrite=True)
        self.assertEqual(self.baremetal.node.update.call_count, 1)
        root_device_args = self.baremetal.node.update.call_args_list[0]
        expected_patch = [{'op': 'add', 'path': '/properties/root_device',
                           'value': {'wwn': 'wwn2'}},
                          {'op': 'add', 'path': '/properties/local_gb',
                           'value': 4}]
        self.assertEqual(mock.call('ABCDEFGH', expected_patch),
                         root_device_args)

    def test_minimum_size(self):
        baremetal._apply_root_device_strategy(
            self.app.client_manager,
            node_uuid='MOCK_UUID',
            strategy='smallest',
            minimum_size=10)
        self.assertEqual(self.baremetal.node.update.call_count, 1)
        root_device_args = self.baremetal.node.update.call_args_list[0]
        expected_patch = [{'op': 'add', 'path': '/properties/root_device',
                           'value': {'wwn': 'wwn0'}},
                          {'op': 'add', 'path': '/properties/local_gb',
                           'value': 10}]
        self.assertEqual(mock.call('ABCDEFGH', expected_patch),
                         root_device_args)

    def test_bad_inventory(self):
        self.inspector.get_data.return_value = {}
        self.assertRaisesRegex(exceptions.RootDeviceDetectionError,
                               "Malformed introspection data",
                               baremetal._apply_root_device_strategy,
                               self.app.client_manager,
                               node_uuid='MOCK_UUID',
                               strategy='smallest')
        self.assertEqual(self.baremetal.node.update.call_count, 0)

    def test_no_disks(self):
        self.inspector.get_data.return_value = {
            'inventory': {
                'disks': [{'name': '/dev/sda', 'size': 1 * units.Gi}]
            }
        }

        self.assertRaisesRegex(exceptions.RootDeviceDetectionError,
                               "No suitable disks",
                               baremetal._apply_root_device_strategy,
                               self.app.client_manager,
                               node_uuid='MOCK_UUID',
                               strategy='smallest')
        self.assertEqual(self.baremetal.node.update.call_count, 0)

    def test_md_device_found(self):
        self.inspector.get_data.return_value = {
            'inventory': {
                'disks': [{'name': '/dev/md0', 'size': 99 * units.Gi},
                          {'name': '/dev/sda', 'size': 100 * units.Gi}]
            }
        }

        baremetal._apply_root_device_strategy(
            self.app.client_manager,
            node_uuid='MOCK_UUID',
            strategy=None)
        self.assertEqual(self.baremetal.node.update.call_count, 0)

    def test_no_data(self):
        self.inspector.get_data.side_effect = (
            ironic_inspector_client.ClientError(mock.Mock()))

        self.assertRaisesRegex(exceptions.RootDeviceDetectionError,
                               "No introspection data",
                               baremetal._apply_root_device_strategy,
                               self.app.client_manager,
                               node_uuid='MOCK_UUID',
                               strategy='smallest')
        self.assertEqual(self.baremetal.node.update.call_count, 0)

    def test_no_wwn_and_serial(self):
        self.inspector.get_data.return_value = {
            'inventory': {
                'disks': [{'name': '/dev/sda', 'size': 10 * units.Gi}]
                }
        }

        self.assertRaisesRegex(exceptions.RootDeviceDetectionError,
                               "Neither WWN nor serial number are known",
                               baremetal._apply_root_device_strategy,
                               self.app.client_manager,
                               node_uuid='MOCK_UUID',
                               strategy='smallest')
        self.assertEqual(self.baremetal.node.update.call_count, 0)

    def test_device_list(self):
        baremetal._apply_root_device_strategy(
            self.app.client_manager,
            node_uuid='MOCK_UUID',
            strategy='hda,sda,sdb,sdc')
        self.assertEqual(self.baremetal.node.update.call_count, 1)
        root_device_args = self.baremetal.node.update.call_args_list[0]
        expected_patch = [{'op': 'add', 'path': '/properties/root_device',
                           'value': {'wwn': 'wwn0'}},
                          {'op': 'add', 'path': '/properties/local_gb',
                           'value': 10}]
        self.assertEqual(mock.call('ABCDEFGH', expected_patch),
                         root_device_args)

    def test_device_list_not_found(self):
        self.assertRaisesRegex(exceptions.RootDeviceDetectionError,
                               "Cannot find a disk",
                               baremetal._apply_root_device_strategy,
                               self.app.client_manager,
                               node_uuid='MOCK_UUID',
                               strategy='hda')
        self.assertEqual(self.baremetal.node.update.call_count, 0)

    def test_existing_ips(self):
        result = baremetal._existing_ips(self.existing_nodes)
        self.assertEqual({('10.0.0.1', 623), ('10.0.0.1', 6235),
                          ('10.0.0.2', None), ('10.0.0.3', 6230)},
                         set(result))

    def test_with_list(self):
        result = baremetal._get_candidate_nodes(
            ['10.0.0.1', '10.0.0.2', '10.0.0.3'],
            [623, 6230, 6235],
            [['admin', 'password'], ['admin', 'admin']],
            self.existing_nodes)
        self.assertEqual([
            {'ip': '10.0.0.3', 'port': 623,
             'username': 'admin', 'password': 'password'},
            {'ip': '10.0.0.1', 'port': 6230,
             'username': 'admin', 'password': 'password'},
            {'ip': '10.0.0.3', 'port': 6235,
             'username': 'admin', 'password': 'password'},
            {'ip': '10.0.0.3', 'port': 623,
             'username': 'admin', 'password': 'admin'},
            {'ip': '10.0.0.1', 'port': 6230,
             'username': 'admin', 'password': 'admin'},
            {'ip': '10.0.0.3', 'port': 6235,
             'username': 'admin', 'password': 'admin'},
        ], result)

    def test_with_subnet(self):
        result = baremetal._get_candidate_nodes(
            '10.0.0.0/30',
            [623, 6230, 6235],
            [['admin', 'password'], ['admin', 'admin']],
            self.existing_nodes)
        self.assertEqual([
            {'ip': '10.0.0.1', 'port': 6230,
             'username': 'admin', 'password': 'password'},
            {'ip': '10.0.0.1', 'port': 6230,
             'username': 'admin', 'password': 'admin'},
        ], result)

    def test_invalid_subnet(self):
        self.assertRaises(
            netaddr.core.AddrFormatError,
            baremetal._get_candidate_nodes,
            'meow',
            [623, 6230, 6235],
            [['admin', 'password'], ['admin', 'admin']],
            self.existing_nodes)

    @mock.patch.object(processutils, 'execute', autospec=True)
    def test_success(self, mock_execute):
        result = baremetal._probe_node('10.0.0.42', 623,
                                       'admin', 'password')
        self.assertEqual({'pm_type': 'ipmi',
                          'pm_addr': '10.0.0.42',
                          'pm_user': 'admin',
                          'pm_password': 'password',
                          'pm_port': 623},
                         result)
        mock_execute.assert_called_once_with('ipmitool', '-I', 'lanplus',
                                             '-H', '10.0.0.42',
                                             '-L', 'ADMINISTRATOR',
                                             '-p', '623', '-U', 'admin',
                                             '-f', mock.ANY, 'power', 'status',
                                             attempts=2)

    @mock.patch.object(processutils, 'execute', autospec=True)
    def test_failure(self, mock_execute):
        mock_execute.side_effect = processutils.ProcessExecutionError()
        self.assertIsNone(baremetal._probe_node('10.0.0.42', 623,
                                                'admin', 'password'))
        mock_execute.assert_called_once_with('ipmitool', '-I', 'lanplus',
                                             '-H', '10.0.0.42',
                                             '-L', 'ADMINISTRATOR',
                                             '-p', '623', '-U', 'admin',
                                             '-f', mock.ANY, 'power', 'status',
                                             attempts=2)
