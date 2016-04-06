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
import yaml

import fixtures
from oslo_utils import units

from tripleoclient import exceptions
from tripleoclient.tests.v1.baremetal import fakes
from tripleoclient.v1 import baremetal


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

    @mock.patch('tripleoclient.utils.run_shell')
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

    @mock.patch('tripleoclient.utils.run_shell')
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

    @mock.patch('tripleoclient.utils.run_shell')
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

        self.csv_file = tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.csv')
        self.json_file = tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.json')
        self.instack_json = tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.json')
        self.yaml_file = tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.yaml')
        self.instack_yaml = tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.yaml')
        self.unsupported_txt = tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.txt')

        self.csv_file.write("""\
pxe_ssh,192.168.122.1,stack,"KEY1",00:0b:d0:69:7e:59
pxe_ssh,192.168.122.2,stack,"KEY2",00:0b:d0:69:7e:58""")

        self.nodes_list = [{
            "pm_user": "stack",
            "pm_addr": "192.168.122.1",
            "pm_password": "KEY1",
            "pm_type": "pxe_ssh",
            "mac": [
                "00:0b:d0:69:7e:59"
            ],
        }, {
            "pm_user": "stack",
            "pm_addr": "192.168.122.2",
            "pm_password": "KEY2",
            "pm_type": "pxe_ssh",
            "mac": [
                "00:0b:d0:69:7e:58"
            ]
        }]

        json.dump(self.nodes_list, self.json_file)
        json.dump({"nodes": self.nodes_list}, self.instack_json)
        self.yaml_file.write(yaml.safe_dump(self.nodes_list, indent=2))
        self.instack_yaml.write(
            yaml.safe_dump({"nodes": self.nodes_list}, indent=2))

        self.csv_file.close()
        self.json_file.close()
        self.instack_json.close()
        self.yaml_file.close()
        self.instack_yaml.close()

    def tearDown(self):

        super(TestImportBaremetal, self).tearDown()
        os.unlink(self.csv_file.name)
        os.unlink(self.json_file.name)
        os.unlink(self.instack_json.name)
        os.unlink(self.yaml_file.name)
        os.unlink(self.instack_yaml.name)

    @mock.patch('tripleo_common.utils.nodes.register_all_nodes', autospec=True)
    def test_json_import(self, mock_register_nodes):

        arglist = [self.json_file.name, '--json', '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', True),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_register_nodes.assert_called_with(
            'http://localhost', self.nodes_list,
            client=self.app.client_manager.baremetal,
            keystone_client=None)

    @mock.patch('tripleo_common.utils.nodes.register_all_nodes', autospec=True)
    def test_json_import_detect_suffix(self, mock_register_nodes):

        arglist = [self.json_file.name, '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_register_nodes.assert_called_with(
            'http://localhost', self.nodes_list,
            client=self.app.client_manager.baremetal,
            keystone_client=None)

    @mock.patch('tripleo_common.utils.nodes.register_all_nodes', autospec=True)
    def test_instack_json_import(self, mock_register_nodes):

        arglist = [self.instack_json.name, '--json', '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', True),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_register_nodes.assert_called_with(
            'http://localhost', self.nodes_list,
            client=self.app.client_manager.baremetal,
            keystone_client=None)

    @mock.patch('tripleo_common.utils.nodes.register_all_nodes', autospec=True)
    def test_csv_import(self, mock_register_nodes):

        arglist = [self.csv_file.name, '--csv', '-s', 'http://localhost']

        verifylist = [
            ('csv', True),
            ('json', False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_register_nodes.assert_called_with(
            'http://localhost', self.nodes_list,
            client=self.app.client_manager.baremetal,
            keystone_client=None)

    @mock.patch('tripleo_common.utils.nodes.register_all_nodes', autospec=True)
    def test_csv_import_detect_suffix(self, mock_register_nodes):

        arglist = [self.csv_file.name, '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_register_nodes.assert_called_with(
            'http://localhost', self.nodes_list,
            client=self.app.client_manager.baremetal,
            keystone_client=None)

    @mock.patch('tripleo_common.utils.nodes.register_all_nodes', autospec=True)
    def test_yaml_import(self, mock_register_nodes):

        arglist = [self.yaml_file.name, '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_register_nodes.assert_called_with(
            'http://localhost', self.nodes_list,
            client=self.app.client_manager.baremetal,
            keystone_client=None)

    def test_invalid_import_filetype(self):

        arglist = [self.unsupported_txt.name, '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegexp(exceptions.InvalidConfiguration,
                                'Invalid file extension',
                                self.cmd.take_action, parsed_args)

    @mock.patch('tripleo_common.utils.nodes.register_all_nodes', autospec=True)
    def test_instack_yaml_import(self, mock_register_nodes):

        arglist = [self.instack_yaml.name, '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_register_nodes.assert_called_with(
            'http://localhost', self.nodes_list,
            client=self.app.client_manager.baremetal,
            keystone_client=None)


@mock.patch('time.sleep', lambda sec: None)
class TestStartBaremetalIntrospectionBulk(fakes.TestBaremetal):

    def setUp(self):
        super(TestStartBaremetalIntrospectionBulk, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.StartBaremetalIntrospectionBulk(self.app, None)

    def test_introspect_bulk_one(self):
        client = self.app.client_manager.baremetal
        client.node = fakes.FakeBaremetalNodeClient(
            states={"ABCDEFGH": "available"},
            transitions={
                ("ABCDEFGH", "manage"): "manageable",
                ("ABCDEFGH", "provide"): "available",
            }
        )
        inspector_client = self.app.client_manager.baremetal_introspection
        inspector_client.states['ABCDEFGH'] = {'finished': True, 'error': None}

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(client.node.updates, [
            ('ABCDEFGH', 'manage'),
            ('ABCDEFGH', 'provide')
        ])
        self.assertEqual(['ABCDEFGH'], inspector_client.on_introspection)

    def test_introspect_bulk_failed(self):
        client = self.app.client_manager.baremetal
        client.node = fakes.FakeBaremetalNodeClient(
            states={"ABCDEFGH": "available", "IJKLMNOP": "available"},
            transitions={
                ("ABCDEFGH", "manage"): "manageable",
                ("IJKLMNOP", "manage"): "manageable",
                ("ABCDEFGH", "provide"): "available",
            }
        )
        inspector_client = self.app.client_manager.baremetal_introspection
        inspector_client.states['ABCDEFGH'] = {'finished': True,
                                               'error': None}
        inspector_client.states['IJKLMNOP'] = {'finished': True,
                                               'error': 'fake error'}

        parsed_args = self.check_parser(self.cmd, [], [])
        self.assertRaisesRegexp(exceptions.IntrospectionError,
                                'IJKLMNOP: fake error',
                                self.cmd.take_action, parsed_args)

        self.assertEqual({'ABCDEFGH': 'available', 'IJKLMNOP': 'manageable'},
                         client.node.states)
        self.assertEqual(['ABCDEFGH', 'IJKLMNOP'],
                         inspector_client.on_introspection)

    def test_introspect_bulk(self):
        client = self.app.client_manager.baremetal
        client.node = fakes.FakeBaremetalNodeClient(
            states={
                "ABC": "available",
                "DEF": "enroll",
                "GHI": "manageable",
                "JKL": "clean_wait"
            },
            transitions={
                ("ABC", "manage"): "manageable",
                ("DEF", "manage"): "manageable",
                ("ABC", "provide"): "available",
                ("DEF", "provide"): "available",
                ("GHI", "provide"): "available"
            }
        )
        inspector_client = self.app.client_manager.baremetal_introspection
        for uuid in ('ABC', 'DEF', 'GHI'):
            inspector_client.states[uuid] = {'finished': True, 'error': None}

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        # The nodes that are available are set to "manageable" state.
        # Then all manageable nodes are set to "available".
        self.assertEqual(client.node.updates, [
            ('ABC', 'manage'),
            ('DEF', 'manage'),
            ('ABC', 'provide'),
            ('DEF', 'provide'),
            ('GHI', 'provide')
        ])

        # Nodes which start in "enroll", "available" or "manageable" states are
        # introspected:
        self.assertEqual(['ABC', 'DEF', 'GHI'],
                         sorted(inspector_client.on_introspection))

    def test_introspect_bulk_timeout(self):
        client = self.app.client_manager.baremetal
        client.node = fakes.FakeBaremetalNodeClient(
            states={
                "ABC": "available",
                "DEF": "enroll",
            },
            transitions={
                ("ABC", "manage"): "available",   # transition times out
                ("DEF", "manage"): "manageable",
                ("DEF", "provide"): "available"
            }
        )
        inspector_client = self.app.client_manager.baremetal_introspection
        inspector_client.states['ABC'] = {'finished': False, 'error': None}
        inspector_client.states['DEF'] = {'finished': True, 'error': None}
        log_fixture = self.useFixture(fixtures.FakeLogger())

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        self.assertIn("FAIL: Timeout waiting for Node ABC", log_fixture.output)
        # Nodes that were successfully introspected are made available
        self.assertEqual(
            [("ABC", "manage"), ("DEF", "manage"), ("DEF", "provide")],
            client.node.updates)

    def test_introspect_bulk_transition_fails(self):
        client = self.app.client_manager.baremetal
        client.node = fakes.FakeBaremetalNodeClient(
            states={
                "ABC": "available",
                "DEF": "enroll",
            },
            transitions={
                ("ABC", "manage"): "manageable",
                ("DEF", "manage"): "enroll",      # state transition fails
                ("ABC", "provide"): "available"
            },
            transition_errors={
                ("DEF", "manage"): "power credential verification failed"
            }
        )
        inspector_client = self.app.client_manager.baremetal_introspection
        for uuid in ('ABC', 'DEF'):
            inspector_client.states[uuid] = {'finished': True, 'error': None}
        log_fixture = self.useFixture(fixtures.FakeLogger())

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        self.assertIn("FAIL: State transition failed for Node DEF",
                      log_fixture.output)
        # Nodes that were successfully introspected are made available
        self.assertEqual(
            [("ABC", "manage"), ("DEF", "manage"), ("ABC", "provide")],
            client.node.updates)


class TestStatusBaremetalIntrospectionBulk(fakes.TestBaremetal):

    def setUp(self):
        super(TestStatusBaremetalIntrospectionBulk, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.StatusBaremetalIntrospectionBulk(self.app, None)

    def test_status_bulk_one(self):
        client = self.app.client_manager.baremetal
        client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH")
        ]
        inspector_client = self.app.client_manager.baremetal_introspection
        inspector_client.states['ABCDEFGH'] = {'finished': False,
                                               'error': None}

        parsed_args = self.check_parser(self.cmd, [], [])
        result = self.cmd.take_action(parsed_args)

        self.assertEqual(result, (
            ('Node UUID', 'Finished', 'Error'),
            [('ABCDEFGH', False, None)]))

    def test_status_bulk(self):
        client = self.app.client_manager.baremetal
        client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH"),
            mock.Mock(uuid="IJKLMNOP"),
            mock.Mock(uuid="QRSTUVWX"),
        ]
        inspector_client = self.app.client_manager.baremetal_introspection
        for node in client.node.list.return_value:
            inspector_client.states[node.uuid] = {'finished': False,
                                                  'error': None}

        parsed_args = self.check_parser(self.cmd, [], [])
        result = self.cmd.take_action(parsed_args)

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

    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_configure_bios')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_configure_root_raid_volumes')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_configure_nonroot_raid_volumes')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_wait_for_drac_config_jobs')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_delete_raid_volumes')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_change_power_state')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
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
        bm_client = self.app.client_manager.baremetal
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

    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_configure_bios')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_configure_root_raid_volumes')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_configure_nonroot_raid_volumes')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_wait_for_drac_config_jobs')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_change_power_state')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_run_introspection')
    def test_configure_ready_state_with_delete_existing_raid_volumes(
            self, mock_run_introspection, mock_change_power_state,
            mock_wait_for_drac_config_jobs,
            mock_configure_nonroot_raid_volumes,
            mock_configure_root_raid_volumes, mock_configure_bios):

        nodes = [mock.Mock(uuid='foo', driver='drac'),
                 mock.Mock(uuid='bar', driver='ilo'),
                 mock.Mock(uuid='baz', driver='drac')]
        bm_client = self.app.client_manager.baremetal
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
        bm_client = self.app.client_manager.baremetal
        self.cmd.bm_client = bm_client

        self.cmd._configure_bios(nodes)

        bm_client.node.vendor_passthru.assert_called_once_with(
            'foo', 'configure_bios_settings', http_method='POST')

    @mock.patch.object(baremetal.ConfigureReadyState, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test__configure_root_raid_volumes(self, mock_sleep_time):
        nodes = [mock.Mock(uuid='foo')]
        bm_client = self.app.client_manager.baremetal
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
        bm_client = self.app.client_manager.baremetal
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
        bm_client = self.app.client_manager.baremetal
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
            [mock.call('foo', 'list_unfinished_jobs', http_method='GET')]
        )

    @mock.patch.object(baremetal.ConfigureReadyState, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test__wait_for_drac_config_jobs_times_out(self, mock_sleep_time):
        nodes = [mock.Mock(uuid='foo')]
        bm_client = self.app.client_manager.baremetal
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
        bm_client = self.app.client_manager.baremetal
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
        bm_client = self.app.client_manager.baremetal
        self.cmd.bm_client = bm_client

        self.cmd._change_power_state(nodes, 'reboot')

        bm_client.node.set_power_state.assert_called_once_with('foo', 'reboot')

    @mock.patch('tripleoclient.utils.wait_for_node_introspection',
                autospec=True)
    def test__run_introspection(self, mock_wait_for_node_introspection):
        nodes = [mock.Mock(uuid='foo')]
        bm_client = self.app.client_manager.baremetal
        inspector_client = self.app.client_manager.baremetal_introspection
        self.cmd.bm_client = bm_client

        self.cmd._run_introspection(nodes)

        self.assertEqual(['foo'], inspector_client.on_introspection)
        mock_wait_for_node_introspection.assert_called_once_with(
            mock.ANY, ['foo'])


class TestConfigureBaremetalBoot(fakes.TestBaremetal):

    def setUp(self):
        super(TestConfigureBaremetalBoot, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.ConfigureBaremetalBoot(self.app, None)

    @mock.patch('openstackclient.common.utils.find_resource', autospec=True)
    def test_configure_boot(self, find_resource_mock):

        find_resource_mock.return_value = mock.Mock(id="IDIDID")
        bm_client = self.app.client_manager.baremetal
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
        self.assertEqual(find_resource_mock.mock_calls, [
            mock.call(mock.ANY, 'bm-deploy-kernel'),
            mock.call(mock.ANY, 'bm-deploy-ramdisk')
        ])

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
    def test_configure_boot_with_suffix(self, find_resource_mock):

        find_resource_mock.return_value = mock.Mock(id="IDIDID")
        bm_client = self.app.client_manager.baremetal
        bm_client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH"),
            mock.Mock(uuid="IJKLMNOP"),
        ]

        bm_client.node.get.side_effect = [
            mock.Mock(uuid="ABCDEFGH", properties={}),
            mock.Mock(uuid="IJKLMNOP", properties={}),
        ]

        arglist = ['--deploy-kernel', 'bm-deploy-kernel_20150101T100620',
                   '--deploy-ramdisk', 'bm-deploy-ramdisk_20150101T100620']
        verifylist = [('deploy_kernel', 'bm-deploy-kernel_20150101T100620'),
                      ('deploy_ramdisk', 'bm-deploy-ramdisk_20150101T100620')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        self.assertEqual(find_resource_mock.call_count, 2)
        self.assertEqual(find_resource_mock.mock_calls, [
            mock.call(mock.ANY, 'bm-deploy-kernel_20150101T100620'),
            mock.call(mock.ANY, 'bm-deploy-ramdisk_20150101T100620')
        ])

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

        bm_client = self.app.client_manager.baremetal
        bm_client.node.list.return_value = [mock.Mock(uuid="ABCDEFGH",
                                                      power_state=None),
                                            ]
        bm_client.node.get.side_effect = [mock.Mock(uuid="ABCDEFGH",
                                                    power_state=None,
                                                    properties={}),
                                          mock.Mock(uuid="ABCDEFGH",
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

        bm_client = self.app.client_manager.baremetal
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
        bm_client = self.app.client_manager.baremetal
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
        bm_client = self.app.client_manager.baremetal
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


@mock.patch('openstackclient.common.utils.find_resource', autospec=True)
class TestConfigureBaremetalBootRootDeviceDetection(fakes.TestBaremetal):

    def setUp(self):
        super(TestConfigureBaremetalBootRootDeviceDetection, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.ConfigureBaremetalBoot(self.app, None)

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

        self.inspector_client = self.app.client_manager.baremetal_introspection
        self.inspector_client.data['ABCDEFGH'] = {
            'inventory': {'disks': self.disks}
        }

        self.bm_client = self.app.client_manager.baremetal
        self.bm_client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH"),
        ]

        self.node = mock.Mock(uuid="ABCDEFGH", properties={})
        self.bm_client.node.get.return_value = self.node

    def test_smallest(self, find_resource_mock):
        find_resource_mock.return_value = mock.Mock(id="IDIDID")

        arglist = ['--root-device', 'smallest']
        verifylist = [('root_device', 'smallest')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        self.assertEqual(self.bm_client.node.update.call_count, 2)
        root_device_args = self.bm_client.node.update.call_args_list[1]
        expected_patch = [{'op': 'add', 'path': '/properties/root_device',
                           'value': {'wwn': 'wwn2'}},
                          {'op': 'add', 'path': '/properties/local_gb',
                           'value': 4}]
        self.assertEqual(mock.call('ABCDEFGH', expected_patch),
                         root_device_args)

    def test_largest(self, find_resource_mock):
        find_resource_mock.return_value = mock.Mock(id="IDIDID")

        arglist = ['--root-device', 'largest']
        verifylist = [('root_device', 'largest')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        self.assertEqual(self.bm_client.node.update.call_count, 2)
        root_device_args = self.bm_client.node.update.call_args_list[1]
        expected_patch = [{'op': 'add', 'path': '/properties/root_device',
                           'value': {'wwn': 'wwn3'}},
                          {'op': 'add', 'path': '/properties/local_gb',
                           'value': 20}]
        self.assertEqual(mock.call('ABCDEFGH', expected_patch),
                         root_device_args)

    def test_no_overwrite(self, find_resource_mock):
        find_resource_mock.return_value = mock.Mock(id="IDIDID")
        self.node.properties['root_device'] = {'foo': 'bar'}

        arglist = ['--root-device', 'smallest']
        verifylist = [('root_device', 'smallest')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        self.assertEqual(self.bm_client.node.update.call_count, 1)

    def test_with_overwrite(self, find_resource_mock):
        find_resource_mock.return_value = mock.Mock(id="IDIDID")
        self.node.properties['root_device'] = {'foo': 'bar'}

        arglist = ['--root-device', 'smallest',
                   '--overwrite-root-device-hints']
        verifylist = [('root_device', 'smallest'),
                      ('overwrite_root_device_hints', True)]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        self.assertEqual(self.bm_client.node.update.call_count, 2)
        root_device_args = self.bm_client.node.update.call_args_list[1]
        expected_patch = [{'op': 'add', 'path': '/properties/root_device',
                           'value': {'wwn': 'wwn2'}},
                          {'op': 'add', 'path': '/properties/local_gb',
                           'value': 4}]
        self.assertEqual(mock.call('ABCDEFGH', expected_patch),
                         root_device_args)

    def test_minimum_size(self, find_resource_mock):
        find_resource_mock.return_value = mock.Mock(id="IDIDID")

        arglist = ['--root-device', 'smallest',
                   '--root-device-minimum-size', '10']
        verifylist = [('root_device', 'smallest')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        self.assertEqual(self.bm_client.node.update.call_count, 2)
        root_device_args = self.bm_client.node.update.call_args_list[1]
        expected_patch = [{'op': 'add', 'path': '/properties/root_device',
                           'value': {'wwn': 'wwn0'}},
                          {'op': 'add', 'path': '/properties/local_gb',
                           'value': 10}]
        self.assertEqual(mock.call('ABCDEFGH', expected_patch),
                         root_device_args)

    def test_bad_inventory(self, find_resource_mock):
        find_resource_mock.return_value = mock.Mock(id="IDIDID")
        del self.inspector_client.data['ABCDEFGH']['inventory']

        arglist = ['--root-device', 'smallest']
        verifylist = [('root_device', 'smallest')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.assertRaisesRegexp(exceptions.RootDeviceDetectionError,
                                "Malformed introspection data",
                                self.cmd.take_action, parsed_args)

        self.assertEqual(self.bm_client.node.update.call_count, 1)

    def test_no_disks(self, find_resource_mock):
        find_resource_mock.return_value = mock.Mock(id="IDIDID")
        self.inspector_client.data['ABCDEFGH']['inventory']['disks'] = [
            {'name': '/dev/sda', 'size': 1 * units.Gi}
        ]

        arglist = ['--root-device', 'smallest']
        verifylist = [('root_device', 'smallest')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.assertRaisesRegexp(exceptions.RootDeviceDetectionError,
                                "No suitable disks",
                                self.cmd.take_action, parsed_args)

        self.assertEqual(self.bm_client.node.update.call_count, 1)

    def test_no_data(self, find_resource_mock):
        find_resource_mock.return_value = mock.Mock(id="IDIDID")
        del self.inspector_client.data['ABCDEFGH']

        arglist = ['--root-device', 'smallest']
        verifylist = [('root_device', 'smallest')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.assertRaisesRegexp(exceptions.RootDeviceDetectionError,
                                "No introspection data",
                                self.cmd.take_action, parsed_args)

        self.assertEqual(self.bm_client.node.update.call_count, 1)

    def test_no_wwn_and_serial(self, find_resource_mock):
        find_resource_mock.return_value = mock.Mock(id="IDIDID")
        self.inspector_client.data['ABCDEFGH']['inventory']['disks'] = [
            {'name': '/dev/sda', 'size': 10 * units.Gi}
        ]

        arglist = ['--root-device', 'smallest']
        verifylist = [('root_device', 'smallest')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.assertRaisesRegexp(exceptions.RootDeviceDetectionError,
                                "Neither WWN nor serial number are known",
                                self.cmd.take_action, parsed_args)

        self.assertEqual(self.bm_client.node.update.call_count, 1)

    def test_device_list(self, find_resource_mock):
        find_resource_mock.return_value = mock.Mock(id="IDIDID")

        arglist = ['--root-device', 'hda,sda,sdb,sdc']
        verifylist = [('root_device', 'hda,sda,sdb,sdc')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        self.assertEqual(self.bm_client.node.update.call_count, 2)
        root_device_args = self.bm_client.node.update.call_args_list[1]
        expected_patch = [{'op': 'add', 'path': '/properties/root_device',
                           'value': {'wwn': 'wwn0'}},
                          {'op': 'add', 'path': '/properties/local_gb',
                           'value': 10}]
        self.assertEqual(mock.call('ABCDEFGH', expected_patch),
                         root_device_args)

    def test_device_list_not_found(self, find_resource_mock):
        find_resource_mock.return_value = mock.Mock(id="IDIDID")

        arglist = ['--root-device', 'hda']
        verifylist = [('root_device', 'hda')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.assertRaisesRegexp(exceptions.RootDeviceDetectionError,
                                "Cannot find a disk",
                                self.cmd.take_action, parsed_args)

        self.assertEqual(self.bm_client.node.update.call_count, 1)


class TestShowNodeCapabilities(fakes.TestBaremetal):

    def setUp(self):
        super(TestShowNodeCapabilities, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.ShowNodeCapabilities(self.app, None)

    def test_success(self):

        bm_client = self.app.client_manager.baremetal

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
