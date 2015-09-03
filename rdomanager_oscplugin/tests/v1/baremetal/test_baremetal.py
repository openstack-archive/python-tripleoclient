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


class TestValidateInstackEnv(fakes.TestBaremetal):

    def setUp(self):
        super(TestValidateInstackEnv, self).setUp()

        self.instack_json = tempfile.NamedTemporaryFile(mode='w', delete=False)

        # Get the command object to test
        self.cmd = baremetal.ValidateInstackEnv(self.app, None)

    def mock_instackenv_json(self, instackenv_data):
        json.dump(instackenv_data, self.instack_json)
        self.instack_json.close()

    def tearDown(self):
        super(TestValidateInstackEnv, self).tearDown()
        os.unlink(self.instack_json.name)

    def test_success(self):
        self.mock_instackenv_json({
            "nodes": [{
                "pm_user": "stack",
                "pm_addr": "192.168.122.1",
                "pm_password": "SOME SSH KEY",
                "pm_type": "pxe_ssh",
                "mac": [
                    "00:0b:d0:69:7e:59"
                ],
            }]
        })

        arglist = ['-f', self.instack_json.name]
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(0, self.cmd.error_count)

    def test_empty_password(self):
        self.mock_instackenv_json({
            "nodes": [{
                "pm_user": "stack",
                "pm_addr": "192.168.122.1",
                "pm_password": "",
                "pm_type": "pxe_ssh",
                "mac": [
                    "00:0b:d0:69:7e:59"
                ],
            }]
        })

        arglist = ['-f', self.instack_json.name]
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(1, self.cmd.error_count)

    def test_no_password(self):
        self.mock_instackenv_json({
            "nodes": [{
                "pm_user": "stack",
                "pm_addr": "192.168.122.1",
                "pm_type": "pxe_ssh",
                "mac": [
                    "00:0b:d0:69:7e:59"
                ],
            }]
        })

        arglist = ['-f', self.instack_json.name]
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(1, self.cmd.error_count)

    def test_empty_user(self):
        self.mock_instackenv_json({
            "nodes": [{
                "pm_user": "",
                "pm_addr": "192.168.122.1",
                "pm_password": "SOME SSH KEY",
                "pm_type": "pxe_ssh",
                "mac": [
                    "00:0b:d0:69:7e:59"
                ],
            }]
        })

        arglist = ['-f', self.instack_json.name]
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(1, self.cmd.error_count)

    def test_no_user(self):
        self.mock_instackenv_json({
            "nodes": [{
                "pm_addr": "192.168.122.1",
                "pm_password": "SOME SSH KEY",
                "pm_type": "pxe_ssh",
                "mac": [
                    "00:0b:d0:69:7e:59"
                ],
            }]
        })

        arglist = ['-f', self.instack_json.name]
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(1, self.cmd.error_count)

    def test_empty_mac(self):
        self.mock_instackenv_json({
            "nodes": [{
                "pm_user": "stack",
                "pm_addr": "192.168.122.1",
                "pm_password": "SOME SSH KEY",
                "pm_type": "pxe_ssh",
                "mac": [],
            }]
        })

        arglist = ['-f', self.instack_json.name]
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(1, self.cmd.error_count)

    def test_no_mac(self):
        self.mock_instackenv_json({
            "nodes": [{
                "pm_user": "stack",
                "pm_addr": "192.168.122.1",
                "pm_password": "SOME SSH KEY",
                "pm_type": "pxe_ssh",
            }]
        })

        arglist = ['-f', self.instack_json.name]
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(1, self.cmd.error_count)

    def test_duplicated_mac(self):
        self.mock_instackenv_json({
            "nodes": [{
                "pm_user": "stack",
                "pm_addr": "192.168.122.1",
                "pm_password": "KEY1",
                "pm_type": "pxe_ssh",
                "mac": [
                    "00:0b:d0:69:7e:58"
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
        })

        arglist = ['-f', self.instack_json.name]
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(1, self.cmd.error_count)

    @mock.patch('rdomanager_oscplugin.utils.run_shell')
    def test_ipmitool_success(self, mock_run_shell):
        mock_run_shell.return_value = 0
        self.mock_instackenv_json({
            "nodes": [{
                "pm_user": "stack",
                "pm_addr": "192.168.122.1",
                "pm_password": "KEY1",
                "pm_type": "pxe_ipmitool",
                "mac": [
                    "00:0b:d0:69:7e:59"
                ],
            }]
        })

        arglist = ['-f', self.instack_json.name]
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(0, self.cmd.error_count)

    @mock.patch('rdomanager_oscplugin.utils.run_shell')
    def test_ipmitool_failure(self, mock_run_shell):
        mock_run_shell.return_value = 1
        self.mock_instackenv_json({
            "nodes": [{
                "pm_user": "stack",
                "pm_addr": "192.168.122.1",
                "pm_password": "KEY1",
                "pm_type": "pxe_ipmitool",
                "mac": [
                    "00:0b:d0:69:7e:59"
                ],
            }]
        })

        arglist = ['-f', self.instack_json.name]
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(1, self.cmd.error_count)

    @mock.patch('rdomanager_oscplugin.utils.run_shell')
    def test_duplicated_baremetal_ip(self, mock_run_shell):
        mock_run_shell.return_value = 0
        self.mock_instackenv_json({
            "nodes": [{
                "pm_user": "stack",
                "pm_addr": "192.168.122.1",
                "pm_password": "KEY1",
                "pm_type": "pxe_ipmitool",
                "mac": [
                    "00:0b:d0:69:7e:59"
                ],
            }, {
                "arch": "x86_64",
                "pm_user": "stack",
                "pm_addr": "192.168.122.1",
                "pm_password": "KEY2",
                "pm_type": "pxe_ipmitool",
                "mac": [
                    "00:0b:d0:69:7e:58"
                ]
            }]
        })

        arglist = ['-f', self.instack_json.name]
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(1, self.cmd.error_count)


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


@mock.patch('time.sleep', lambda sec: None)
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
            mock.Mock(uuid="ABCDEFGH", provision_state="manageable")
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
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        # The nodes that are available are set to "manageable" state.
        client.node.set_provision_state.assert_has_calls([
            mock.call('ABCDEFGH', 'manage'),
            mock.call('QRSTUVWX', 'manage'),
        ])

        # Since everything is mocked, the node states doesn't change.
        # Therefore only the node originally in manageable state is
        # introspected:
        introspect_mock.assert_has_calls([
            mock.call('IJKLMNOP', base_url=None, auth_token='TOKEN'),
        ])

        wait_for_discover_mock.assert_called_once_with(
            discoverd_client, 'TOKEN', None,
            ['IJKLMNOP'])

        # And lastly it  will be set to available:
        client.node.set_provision_state.assert_has_calls([
            mock.call('IJKLMNOP', 'provide'),
        ])


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


class TestConfigureReadyState(fakes.TestBaremetal):

    def setUp(self):
        super(TestConfigureReadyState, self).setUp()
        self.cmd = baremetal.ConfigureReadyState(self.app, None)

    @mock.patch('rdomanager_oscplugin.v1.baremetal.ConfigureReadyState.'
                '_configure_bios')
    @mock.patch('rdomanager_oscplugin.v1.baremetal.ConfigureReadyState.'
                '_configure_root_raid_volumes')
    @mock.patch('rdomanager_oscplugin.v1.baremetal.ConfigureReadyState.'
                '_configure_nonroot_raid_volumes')
    @mock.patch('rdomanager_oscplugin.v1.baremetal.ConfigureReadyState.'
                '_wait_for_drac_config_jobs')
    @mock.patch('rdomanager_oscplugin.v1.baremetal.ConfigureReadyState.'
                '_delete_raid_volumes')
    @mock.patch('rdomanager_oscplugin.v1.baremetal.ConfigureReadyState.'
                '_change_power_state')
    @mock.patch('rdomanager_oscplugin.v1.baremetal.ConfigureReadyState.'
                '_run_introspection')
    def test_configure_ready_state(self, mock_run_introspection,
                                   mock_change_power_state,
                                   mock_delete_raid_volumes,
                                   mock_wait_for_drac_config_jobs,
                                   mock_configure_nonroot_raid_volumes,
                                   mock_configure_root_raid_volumes,
                                   mock_configure_bios):

        nodes = [mock.Mock(uuid='foo', driver='drac'),
                 mock.Mock(uuid='bar', driver='ilo'),
                 mock.Mock(uuid='baz', driver='drac')]
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        bm_client.node.list.return_value = nodes

        argslist = ['--delete-existing-raid-volumes']
        verifylist = [('delete_raid_volumes', True)]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

        drac_nodes = [node for node in nodes if 'drac' in node.driver]
        mock_configure_bios.assert_called_once_with(drac_nodes)
        mock_configure_root_raid_volumes.assert_called_once_with(drac_nodes)
        mock_configure_nonroot_raid_volumes.assert_called_once_with(drac_nodes)
        mock_wait_for_drac_config_jobs.assert_called_with(drac_nodes)
        mock_delete_raid_volumes.assert_called_with(drac_nodes)
        mock_change_power_state.assert_has_calls(([
            mock.call(drac_nodes, 'reboot'),
            mock.call(drac_nodes, 'reboot'),
            mock.call(drac_nodes, 'off'),
        ]))
        mock_run_introspection.assert_called_once_with(drac_nodes)

    @mock.patch('rdomanager_oscplugin.v1.baremetal.ConfigureReadyState.'
                '_configure_bios')
    @mock.patch('rdomanager_oscplugin.v1.baremetal.ConfigureReadyState.'
                '_configure_root_raid_volumes')
    @mock.patch('rdomanager_oscplugin.v1.baremetal.ConfigureReadyState.'
                '_configure_nonroot_raid_volumes')
    @mock.patch('rdomanager_oscplugin.v1.baremetal.ConfigureReadyState.'
                '_wait_for_drac_config_jobs')
    @mock.patch('rdomanager_oscplugin.v1.baremetal.ConfigureReadyState.'
                '_change_power_state')
    @mock.patch('rdomanager_oscplugin.v1.baremetal.ConfigureReadyState.'
                '_run_introspection')
    def test_configure_ready_state_with_delete_existing_raid_volumes(
            self, mock_run_introspection, mock_change_power_state,
            mock_wait_for_drac_config_jobs,
            mock_configure_nonroot_raid_volumes,
            mock_configure_root_raid_volumes, mock_configure_bios):

        nodes = [mock.Mock(uuid='foo', driver='drac'),
                 mock.Mock(uuid='bar', driver='ilo'),
                 mock.Mock(uuid='baz', driver='drac')]
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        bm_client.node.list.return_value = nodes

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        drac_nodes = [node for node in nodes if 'drac' in node.driver]
        mock_configure_bios.assert_called_once_with(drac_nodes)
        mock_configure_root_raid_volumes.assert_called_once_with(drac_nodes)
        mock_configure_nonroot_raid_volumes.assert_called_once_with(drac_nodes)
        mock_wait_for_drac_config_jobs.assert_called_with(drac_nodes)
        mock_change_power_state.assert_has_calls(([
            mock.call(drac_nodes, 'reboot'),
            mock.call(drac_nodes, 'reboot'),
            mock.call(drac_nodes, 'off'),
        ]))
        mock_run_introspection.assert_called_once_with(drac_nodes)

    @mock.patch.object(baremetal.ConfigureReadyState, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test__configure_bios(self, mock_sleep_time):
        nodes = [mock.Mock(uuid='foo')]
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        self.cmd.bm_client = bm_client

        self.cmd._configure_bios(nodes)

        bm_client.node.vendor_passthru.assert_called_once_with(
            'foo', 'configure_bios_settings', http_method='POST')

    @mock.patch.object(baremetal.ConfigureReadyState, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test__configure_root_raid_volumes(self, mock_sleep_time):
        nodes = [mock.Mock(uuid='foo')]
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        self.cmd.bm_client = bm_client

        self.cmd._configure_root_raid_volumes(nodes)

        bm_client.node.vendor_passthru.assert_called_once_with(
            'foo', 'create_raid_configuration',
            {'create_nonroot_volumes': False,
             'create_root_volume': True},
            'POST')

    @mock.patch.object(baremetal.ConfigureReadyState, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test__configure_nonroot_raid_volumes(self, mock_sleep_time):
        nodes = [mock.Mock(uuid='foo')]
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        self.cmd.bm_client = bm_client

        self.cmd._configure_nonroot_raid_volumes(nodes)

        bm_client.node.vendor_passthru.assert_called_once_with(
            'foo', 'create_raid_configuration',
            {'create_nonroot_volumes': True,
             'create_root_volume': False},
            'POST')

    @mock.patch.object(baremetal.ConfigureReadyState, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test__wait_for_drac_config_jobs(self, mock_sleep_time):
        nodes = [mock.Mock(uuid='foo')]
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        bm_client.node.vendor_passthru.side_effect = [
            mock.Mock(unfinished_jobs={'percent_complete': '34',
                                       'id': 'JID_343938731947',
                                       'name': 'ConfigBIOS:BIOS.Setup.1-1'}),
            mock.Mock(unfinished_jobs={}),
        ]
        self.cmd.bm_client = bm_client

        self.cmd._wait_for_drac_config_jobs(nodes)

        self.assertEqual(2, bm_client.node.vendor_passthru.call_count)
        bm_client.node.vendor_passthru.assert_has_calls(
            mock.call('foo', 'list_unfinished_jobs', http_method='GET'),
        )

    @mock.patch.object(baremetal.ConfigureReadyState, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test__wait_for_drac_config_jobs_times_out(self, mock_sleep_time):
        nodes = [mock.Mock(uuid='foo')]
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        bm_client.node.vendor_passthru.return_value = mock.Mock(
            unfinished_jobs={'percent_complete': '34',
                             'id': 'JID_343938731947',
                             'name': 'ConfigBIOS:BIOS.Setup.1-1'})
        self.cmd.bm_client = bm_client

        self.assertRaises(exceptions.Timeout,
                          self.cmd._wait_for_drac_config_jobs,
                          nodes)

    @mock.patch.object(baremetal.ConfigureReadyState, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test__delete_raid_volumes(self, mock_sleep_time):
        node_with_raid_volume = mock.Mock(uuid='foo')
        nodes = [node_with_raid_volume, mock.Mock(uuid='bar')]
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        bm_client.node.vendor_passthru.side_effect = [
            mock.Mock(virtual_disks=[
                {'controller': 'RAID.Integrated.1-1',
                 'id': 'Disk.Virtual.0:RAID.Integrated.1-1'},
                {'controller': 'RAID.Integrated.1-1',
                 'id': 'Disk.Virtual.0:RAID.Integrated.1-2'}]),
            True, True, True,
            mock.Mock(virtual_disks=[])
        ]
        self.cmd.bm_client = bm_client

        nodes_to_restart = self.cmd._delete_raid_volumes(nodes)

        bm_client.node.vendor_passthru.assert_has_calls([
            mock.call('foo', 'list_virtual_disks', http_method='GET'),
            mock.call('foo', 'delete_virtual_disk',
                      {'virtual_disk': 'Disk.Virtual.0:RAID.Integrated.1-1'},
                      'POST'),
            mock.call('foo', 'delete_virtual_disk',
                      {'virtual_disk': 'Disk.Virtual.0:RAID.Integrated.1-2'},
                      'POST'),
            mock.call('foo', 'apply_pending_raid_config',
                      {'raid_controller': 'RAID.Integrated.1-1'}, 'POST'),
        ])
        self.assertEqual(set([node_with_raid_volume]), nodes_to_restart)

    def test__change_power_state(self):
        nodes = [mock.Mock(uuid='foo')]
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        self.cmd.bm_client = bm_client

        self.cmd._change_power_state(nodes, 'reboot')

        bm_client.node.set_power_state.assert_called_once_with('foo', 'reboot')

    @mock.patch('ironic_discoverd.client.introspect', autospec=True)
    @mock.patch('rdomanager_oscplugin.utils.wait_for_node_discovery',
                autospec=True)
    def test__run_introspection(self, mock_wait_for_node_discovery,
                                mock_introspect):
        nodes = [mock.Mock(uuid='foo')]
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        self.cmd.bm_client = bm_client
        self.cmd.discoverd_url = None

        self.cmd._run_introspection(nodes)

        mock_introspect.assert_called_once_with('foo', base_url=None,
                                                auth_token='TOKEN')
        mock_wait_for_node_discovery.assert_called_once_with(mock.ANY, 'TOKEN',
                                                             None, ['foo'])


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

        bm_client.node.get.side_effect = [
            mock.Mock(uuid="ABCDEFGH", properties={}),
            mock.Mock(uuid="IJKLMNOP", properties={}),
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
                                                    power_state=None,
                                                    properties={}),
                                          mock.Mock(uuid="ABCDEFGH",
                                                    power_state='available',
                                                    properties={}),
                                          mock.Mock(uuid="ABCDEFGH",
                                                    power_state='available',
                                                    properties={}),
                                          ]
        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(1, bm_client.node.list.call_count)
        self.assertEqual(3, bm_client.node.get.call_count)
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

    @mock.patch('openstackclient.common.utils.find_resource', autospec=True)
    def test_configure_boot_skip_maintenance(self, find_resource_mock):

        find_resource_mock.return_value = mock.Mock(id="IDIDID")
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        bm_client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH", maintenance=False),
        ]

        bm_client.node.get.return_value = mock.Mock(uuid="ABCDEFGH",
                                                    maintenance=False,
                                                    properties={})

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(bm_client.node.list.mock_calls, [mock.call(
            maintenance=False)])

    @mock.patch('openstackclient.common.utils.find_resource', autospec=True)
    def test_configure_boot_existing_properties(self, find_resource_mock):

        find_resource_mock.return_value = mock.Mock(id="IDIDID")
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        bm_client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH"),
            mock.Mock(uuid="IJKLMNOP"),
            mock.Mock(uuid="QRSTUVWX"),
            mock.Mock(uuid="YZABCDEF"),
        ]

        bm_client.node.get.side_effect = [
            mock.Mock(uuid="ABCDEFGH", properties={
                'capabilities': 'existing:cap'
            }),
            mock.Mock(uuid="IJKLMNOP", properties={
                'capabilities': 'boot_option:local'
            }),
            mock.Mock(uuid="QRSTUVWX", properties={
                'capabilities': 'boot_option:remote'
            }),
            mock.Mock(uuid="YZABCDEF", properties={}),
        ]

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(find_resource_mock.call_count, 2)

        self.assertEqual(bm_client.node.update.call_count, 4)
        self.assertEqual(bm_client.node.update.mock_calls, [
            mock.call('ABCDEFGH', [{
                'op': 'add', 'value': 'boot_option:local,existing:cap',
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
            }]),
            mock.call('QRSTUVWX', [{
                'op': 'add', 'value': 'boot_option:remote',
                'path': '/properties/capabilities'
            }, {
                'op': 'add', 'value': 'IDIDID',
                'path': '/driver_info/deploy_ramdisk'
            }, {
                'op': 'add', 'value': 'IDIDID',
                'path': '/driver_info/deploy_kernel'
            }]),
            mock.call('YZABCDEF', [{
                'op': 'add', 'value': 'boot_option:local',
                'path': '/properties/capabilities'
            }, {
                'op': 'add', 'value': 'IDIDID',
                'path': '/driver_info/deploy_ramdisk'
            }, {
                'op': 'add', 'value': 'IDIDID',
                'path': '/driver_info/deploy_kernel'
            }]),
        ])


class TestShowNodeCapabilities(fakes.TestBaremetal):

    def setUp(self):
        super(TestShowNodeCapabilities, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.ShowNodeCapabilities(self.app, None)

    def test_success(self):

        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()

        bm_client.node.list.return_value = [
            mock.Mock(uuid='UUID1'),
            mock.Mock(uuid='UUID2'),
        ]

        bm_client.node.get.return_value = mock.Mock(
            properties={'capabilities': 'boot_option:local'})

        arglist = []
        parsed_args = self.check_parser(self.cmd, arglist, [])
        result = self.cmd.take_action(parsed_args)

        self.assertEqual((
            ('Node UUID', 'Node Capabilities'),
            [('UUID1', 'boot_option:local'), ('UUID2', 'boot_option:local')]
        ), result)
