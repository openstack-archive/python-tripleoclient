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

import tempfile

import json
import mock
import os

from ironic_discoverd import client as discoverd_client

from rdomanager_oscplugin import exceptions
from rdomanager_oscplugin.tests.v1.baremetal import fakes
from rdomanager_oscplugin.v1 import baremetal


class TestImportBaremetal(fakes.TestBaremetal):

    def setUp(self):
        super(TestImportBaremetal, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.ImportBaremetal(self.app, None)

        self.csv_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.json_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.instack_json = tempfile.NamedTemporaryFile(mode='w', delete=False)

        self.csv_file.write("""\
pxe_ssh,192.168.122.1,root,"KEY1",00:d0:28:4c:e8:e8
pxe_ssh,192.168.122.1,root,"KEY2",00:7c:ef:3d:eb:60""")

        json.dump([{
            "pm_user": "stack",
            "pm_addr": "192.168.122.1",
            "pm_password": "KEY1",
            "pm_type": "pxe_ssh",
            "mac": [
                "00:0b:d0:69:7e:59"
            ],
        }, {
            "arch": "x86_64",
            "pm_user": "stack",
            "pm_addr": "192.168.122.2",
            "pm_password": "KEY2",
            "pm_type": "pxe_ssh",
            "mac": [
                "00:0b:d0:69:7e:58"
            ]
        }], self.json_file)

        json.dump({
            "nodes": [{
                "pm_user": "stack",
                "pm_addr": "192.168.122.1",
                "pm_password": "KEY1",
                "pm_type": "pxe_ssh",
                "mac": [
                    "00:0b:d0:69:7e:59"
                ],
            }, {
                "arch": "x86_64",
                "pm_user": "stack",
                "pm_addr": "192.168.122.2",
                "pm_password": "KEY2",
                "pm_type": "pxe_ssh",
                "mac": [
                    "00:0b:d0:69:7e:58"
                ]
            }]
        }, self.instack_json)

        self.csv_file.close()
        self.json_file.close()
        self.instack_json.close()

    def tearDown(self):

        super(TestImportBaremetal, self).tearDown()
        os.unlink(self.csv_file.name)
        os.unlink(self.json_file.name)
        os.unlink(self.instack_json.name)

    @mock.patch('os_cloud_config.nodes.register_all_nodes', autospec=True)
    def test_json_import(self, mock_register_nodes):

        arglist = [self.json_file.name, '--json', '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', True),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_register_nodes.assert_called_with(
            'http://localhost',
            [
                {
                    'pm_password': 'KEY1',
                    'pm_type': 'pxe_ssh',
                    'pm_user': 'stack',
                    'pm_addr': '192.168.122.1',
                    'mac': ['00:0b:d0:69:7e:59']
                }, {
                    'pm_user': 'stack',
                    'pm_password': 'KEY2',
                    'pm_addr': '192.168.122.2',
                    'arch': 'x86_64',
                    'pm_type': 'pxe_ssh',
                    'mac': ['00:0b:d0:69:7e:58']
                }
            ],
            client=self.app.client_manager.rdomanager_oscplugin.baremetal(),
            keystone_client=None)

    @mock.patch('os_cloud_config.nodes.register_all_nodes', autospec=True)
    def test_instack_json_import(self, mock_register_nodes):

        arglist = [self.instack_json.name, '--json', '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', True),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_register_nodes.assert_called_with(
            'http://localhost',
            [
                {
                    'pm_password': 'KEY1',
                    'pm_type': 'pxe_ssh',
                    'pm_user': 'stack',
                    'pm_addr': '192.168.122.1',
                    'mac': ['00:0b:d0:69:7e:59']
                }, {
                    'pm_user': 'stack',
                    'pm_password': 'KEY2',
                    'pm_addr': '192.168.122.2',
                    'arch': 'x86_64',
                    'pm_type': 'pxe_ssh',
                    'mac': ['00:0b:d0:69:7e:58']
                }
            ],
            client=self.app.client_manager.rdomanager_oscplugin.baremetal(),
            keystone_client=None)

    @mock.patch('os_cloud_config.nodes.register_all_nodes', autospec=True)
    def test_csv_import(self, mock_register_nodes):

        arglist = [self.csv_file.name, '--csv', '-s', 'http://localhost']

        verifylist = [
            ('csv', True),
            ('json', False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_register_nodes.assert_called_with(
            'http://localhost',
            [
                {
                    'pm_password': 'KEY1',
                    'pm_user': 'root',
                    'pm_type': 'pxe_ssh',
                    'pm_addr': '192.168.122.1',
                    'mac': ['00:d0:28:4c:e8:e8']
                }, {
                    'pm_password': 'KEY2',
                    'pm_user': 'root',
                    'pm_type': 'pxe_ssh',
                    'pm_addr': '192.168.122.1',
                    'mac': ['00:7c:ef:3d:eb:60']
                }
            ],
            client=self.app.client_manager.rdomanager_oscplugin.baremetal(),
            keystone_client=None)


class TestStartBaremetalIntrospectionBulk(fakes.TestBaremetal):

    def setUp(self):
        super(TestStartBaremetalIntrospectionBulk, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.StartBaremetalIntrospectionBulk(self.app, None)

    @mock.patch('ironic_discoverd.client.get_status', autospec=True)
    @mock.patch('ironic_discoverd.client.introspect', autospec=True)
    def test_introspect_bulk_one(self, introspect_mock, get_status_mock,):

        client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH")
        ]

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        introspect_mock.assert_called_once_with(
            'ABCDEFGH', base_url=None, auth_token='TOKEN')

    @mock.patch('rdomanager_oscplugin.utils.wait_for_node_discovery',
                autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.wait_for_provision_state',
                autospec=True)
    @mock.patch('ironic_discoverd.client.get_status', autospec=True)
    @mock.patch('ironic_discoverd.client.introspect', autospec=True)
    def test_introspect_bulk(self, introspect_mock, get_status_mock,
                             wait_for_state_mock, wait_for_discover_mock):

        wait_for_discover_mock.return_value = []
        wait_for_state_mock.return_value = True

        get_status_mock.return_value = {'finished': True, 'error': None}

        client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH", provision_state="available"),
            mock.Mock(uuid="IJKLMNOP", provision_state="manageable"),
            mock.Mock(uuid="QRSTUVWX", provision_state="available"),
        ]

        arglist = []
        verifylist = [
            ('poll', True)
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        client.node.set_provision_state.assert_has_calls([
            mock.call('ABCDEFGH', 'manage'),
            mock.call('QRSTUVWX', 'manage'),
        ])

        introspect_mock.assert_has_calls([
            mock.call('ABCDEFGH', base_url=None, auth_token='TOKEN'),
            mock.call('IJKLMNOP', base_url=None, auth_token='TOKEN'),
            mock.call('QRSTUVWX', base_url=None, auth_token='TOKEN'),
        ])

        wait_for_discover_mock.assert_called_once_with(
            discoverd_client, 'TOKEN', None,
            ['ABCDEFGH', 'IJKLMNOP', 'QRSTUVWX'])

    @mock.patch('rdomanager_oscplugin.utils.wait_for_node_discovery',
                autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.wait_for_provision_state',
                autospec=True)
    @mock.patch('ironic_discoverd.client.get_status', autospec=True)
    @mock.patch('ironic_discoverd.client.introspect', autospec=True)
    def test_introspect_bulk_no_poll(self, introspect_mock, get_status_mock,
                                     wait_for_state_mock,
                                     wait_for_discover_mock):

        wait_for_discover_mock.return_value = []
        wait_for_state_mock.return_value = True

        get_status_mock.return_value = {'finished': True, 'error': None}

        client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH", provision_state="available"),
            mock.Mock(uuid="IJKLMNOP", provision_state="manageable"),
            mock.Mock(uuid="QRSTUVWX", provision_state="available"),
        ]

        arglist = ['--no-poll', ]
        verifylist = [
            ('poll', False)
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        client.node.set_provision_state.assert_has_calls([
            mock.call('ABCDEFGH', 'manage'),
            mock.call('QRSTUVWX', 'manage'),
        ])

        introspect_mock.assert_has_calls([
            mock.call('ABCDEFGH', base_url=None, auth_token='TOKEN'),
            mock.call('IJKLMNOP', base_url=None, auth_token='TOKEN'),
            mock.call('QRSTUVWX', base_url=None, auth_token='TOKEN'),
        ])

        self.assertFalse(wait_for_discover_mock.called)


class TestStatusBaremetalIntrospectionBulk(fakes.TestBaremetal):

    def setUp(self):
        super(TestStatusBaremetalIntrospectionBulk, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.StatusBaremetalIntrospectionBulk(self.app, None)

    @mock.patch('ironic_discoverd.client.get_status', autospec=True)
    def test_status_bulk_one(self, discoverd_mock):

        client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH")
        ]

        discoverd_mock.return_value = {
            'finished': False, 'error': None
        }

        parsed_args = self.check_parser(self.cmd, [], [])
        result = self.cmd.take_action(parsed_args)

        discoverd_mock.assert_called_once_with(
            'ABCDEFGH', base_url=None, auth_token='TOKEN')

        self.assertEqual(result, (
            ('Node UUID', 'Finished', 'Error'),
            [('ABCDEFGH', False, None)]))

    @mock.patch('ironic_discoverd.client.get_status', autospec=True)
    def test_status_bulk(self, discoverd_mock):

        client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH"),
            mock.Mock(uuid="IJKLMNOP"),
            mock.Mock(uuid="QRSTUVWX"),
        ]

        discoverd_mock.return_value = {
            'finished': False, 'error': None
        }

        parsed_args = self.check_parser(self.cmd, [], [])
        result = self.cmd.take_action(parsed_args)

        discoverd_mock.assert_has_calls([
            mock.call('ABCDEFGH', base_url=None, auth_token='TOKEN'),
            mock.call('IJKLMNOP', base_url=None, auth_token='TOKEN'),
            mock.call('QRSTUVWX', base_url=None, auth_token='TOKEN'),
        ])

        self.assertEqual(result, (
            ('Node UUID', 'Finished', 'Error'),
            [
                ('ABCDEFGH', False, None),
                ('IJKLMNOP', False, None),
                ('QRSTUVWX', False, None)
            ]
        ))


class TestConfigureBaremetalBoot(fakes.TestBaremetal):

    def setUp(self):
        super(TestConfigureBaremetalBoot, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.ConfigureBaremetalBoot(self.app, None)

    @mock.patch('openstackclient.common.utils.find_resource', autospec=True)
    def test_configure_boot(self, find_resource_mock):

        find_resource_mock.return_value = mock.Mock(id="IDIDID")
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        bm_client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH"),
            mock.Mock(uuid="IJKLMNOP"),
        ]

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(find_resource_mock.call_count, 2)

        self.assertEqual(bm_client.node.update.call_count, 2)
        self.assertEqual(bm_client.node.update.mock_calls, [
            mock.call('ABCDEFGH', [{
                'op': 'add', 'value': 'boot_option:local',
                'path': '/properties/capabilities'
            }, {
                'op': 'add', 'value': 'IDIDID',
                'path': '/driver_info/deploy_ramdisk'
            }, {
                'op': 'add', 'value': 'IDIDID',
                'path': '/driver_info/deploy_kernel'
            }]),
            mock.call('IJKLMNOP', [{
                'op': 'add', 'value': 'boot_option:local',
                'path': '/properties/capabilities'
            }, {
                'op': 'add', 'value': 'IDIDID',
                'path': '/driver_info/deploy_ramdisk'
            }, {
                'op': 'add', 'value': 'IDIDID',
                'path': '/driver_info/deploy_kernel'
            }])
        ])

    @mock.patch('openstackclient.common.utils.find_resource', autospec=True)
    @mock.patch.object(baremetal.ConfigureBaremetalBoot, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test_configure_boot_in_transition(self, _, find_resource_mock):
        find_resource_mock.return_value = mock.Mock(id="IDIDID")

        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        bm_client.node.list.return_value = [mock.Mock(uuid="ABCDEFGH",
                                                      power_state=None),
                                            ]
        bm_client.node.get.side_effect = [mock.Mock(uuid="ABCDEFGH",
                                                    power_state=None),
                                          mock.Mock(uuid="ABCDEFGH",
                                                    power_state='available'),
                                          ]
        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(1, bm_client.node.list.call_count)
        self.assertEqual(2, bm_client.node.get.call_count)
        self.assertEqual(1, bm_client.node.update.call_count)

    @mock.patch('openstackclient.common.utils.find_resource', autospec=True)
    @mock.patch.object(baremetal.ConfigureBaremetalBoot, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test_configure_boot_timeout(self, _, find_resource_mock):
        find_resource_mock.return_value = mock.Mock(id="IDIDID")

        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        bm_client.node.list.return_value = [mock.Mock(uuid="ABCDEFGH",
                                                      power_state=None),
                                            ]
        bm_client.node.get.return_value = mock.Mock(uuid="ABCDEFGH",
                                                    power_state=None)
        parsed_args = self.check_parser(self.cmd, [], [])
        self.assertRaises(exceptions.Timeout,
                          self.cmd.take_action,
                          parsed_args)
