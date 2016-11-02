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
import copy
import json
import os
import tempfile

import mock
import yaml

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
        self.baremetal = self.app.client_manager.baremetal
        self.baremetal.http_client.os_ironic_api_version = '1.11'
        self.baremetal.node = fakes.FakeBaremetalNodeClient(
            states={"ABCDEFGH": "enroll", "IJKLMNOP": "enroll"},
            transitions={
                ("ABCDEFGH", "manage"): "manageable",
                ("IJKLMNOP", "manage"): "manageable",
                ("ABCDEFGH", "provide"): "available",
                ("IJKLMNOP", "provide"): "available",

            }
        )
        self.mock_websocket_success = [{
            "status": "SUCCESS",
            "registered_nodes": [
                {"uuid": "MOCK_NODE_UUID", "provision_state": "manageable"},
                {"uuid": "MOCK_NODE_UUID2", "provision_state": "available"},
            ],
        }, {
            "status": "SUCCESS"
        }]

        self.workflow = self.app.client_manager.workflow_engine
        tripleoclient = self.app.client_manager.tripleoclient
        websocket = tripleoclient.messaging_websocket()
        websocket.wait_for_message.side_effect = self.mock_websocket_success
        self.websocket = websocket

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    def tearDown(self):

        super(TestImportBaremetal, self).tearDown()
        os.unlink(self.csv_file.name)
        os.unlink(self.json_file.name)
        os.unlink(self.instack_json.name)
        os.unlink(self.yaml_file.name)
        os.unlink(self.instack_yaml.name)

    def _check_workflow_call(self, local=True, provide=True,
                             kernel_name='bm-deploy-kernel',
                             ramdisk_name='bm-deploy-ramdisk'):

        call_list = [mock.call(
            'tripleo.baremetal.v1.register_or_update', workflow_input={
                'kernel_name': kernel_name,
                'nodes_json': self.nodes_list,
                'queue_name': 'UUID4',
                'ramdisk_name': ramdisk_name,
                'instance_boot_option': 'local' if local else 'netboot'
            }
        )]

        if provide:
            call_list.append(mock.call(
                'tripleo.baremetal.v1.provide', workflow_input={
                    'node_uuids': ['MOCK_NODE_UUID', ],
                    'queue_name': 'UUID4'
                }
            ))

        self.workflow.executions.create.assert_has_calls(call_list)

        self.assertEqual(self.workflow.executions.create.call_count,
                         2 if provide else 1)

    def test_json_import(self):

        arglist = [self.json_file.name, '--json', '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', True),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self._check_workflow_call()

    def test_json_import_initial_state_enroll(self):

        arglist = [
            self.json_file.name,
            '--json',
            '-s', 'http://localhost',
            '--initial-state', 'enroll'
        ]

        verifylist = [
            ('csv', False),
            ('json', True),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        self._check_workflow_call(provide=False)
        self.assertEqual([], self.baremetal.node.updates)

    def test_available_does_not_require_api_1_11(self):
        arglist = [self.json_file.name, '--json', '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', True),
        ]
        self.baremetal.http_client.os_ironic_api_version = '1.6'
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        self._check_workflow_call()

    def test_enroll_requires_api_1_11(self):
        arglist = [
            self.json_file.name,
            '--json',
            '-s', 'http://localhost',
            '--initial-state', 'enroll'
        ]

        verifylist = [
            ('csv', False),
            ('json', True),
        ]
        self.baremetal.http_client.os_ironic_api_version = '1.6'
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.assertRaisesRegexp(exceptions.InvalidConfiguration,
                                'OS_BAREMETAL_API_VERSION',
                                self.cmd.take_action, parsed_args)
        self.workflow.executions.create.assert_not_called()

    def test_json_import_detect_suffix(self):

        arglist = [self.json_file.name, '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self._check_workflow_call()

    def test_instack_json_import(self):

        arglist = [self.instack_json.name, '--json', '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', True),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self._check_workflow_call()

    def test_csv_import(self):

        arglist = [self.csv_file.name, '--csv', '-s', 'http://localhost']

        verifylist = [
            ('csv', True),
            ('json', False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self._check_workflow_call()

    def test_csv_import_detect_suffix(self):

        arglist = [self.csv_file.name, '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self._check_workflow_call()

    def test_yaml_import(self):

        arglist = [self.yaml_file.name, '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self._check_workflow_call()

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

    def test_instack_yaml_import(self):

        arglist = [self.instack_yaml.name, '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self._check_workflow_call()

    def test_netboot(self):

        arglist = [self.json_file.name, '-s', 'http://localhost',
                   '--instance-boot-option', 'netboot']

        verifylist = [
            ('instance_boot_option', 'netboot')
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self._check_workflow_call(local=False)

    def test_custom_image(self):

        arglist = [self.json_file.name, '-s', 'http://localhost',
                   '--deploy-kernel', 'k', '--deploy-ramdisk', 'r']

        verifylist = [
            ('deploy_kernel', 'k'),
            ('deploy_ramdisk', 'r')
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self._check_workflow_call(kernel_name='k', ramdisk_name='r')

    def test_no_image(self):

        arglist = [self.json_file.name, '-s', 'http://localhost',
                   '--no-deploy-image']

        verifylist = [
            ('no_deploy_image', True)
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self._check_workflow_call(kernel_name=None, ramdisk_name=None)


class TestStartBaremetalIntrospectionBulk(fakes.TestBaremetal):

    def setUp(self):
        super(TestStartBaremetalIntrospectionBulk, self).setUp()

        self.workflow = self.app.client_manager.workflow_engine
        tripleoclients = self.app.client_manager.tripleoclient
        websocket = tripleoclients.messaging_websocket()
        self.websocket = websocket

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

        # Get the command object to test
        self.cmd = baremetal.StartBaremetalIntrospectionBulk(self.app, None)

    def _check_workflow_call(self, provide=True):

        call_list = [mock.call(
            'tripleo.baremetal.v1.introspect_manageable_nodes',
            workflow_input={'queue_name': 'UUID4'}
        )]

        if provide:
            call_list.append(mock.call(
                'tripleo.baremetal.v1.provide_manageable_nodes',
                workflow_input={'queue_name': 'UUID4'}
            ))

        self.workflow.executions.create.assert_has_calls(call_list)

        self.assertEqual(self.workflow.executions.create.call_count,
                         2 if provide else 1)

    def test_introspect_bulk(self):
        client = self.app.client_manager.baremetal
        client.node = fakes.FakeBaremetalNodeClient(
            states={"ABCDEFGH": "available"},
            transitions={
                ("ABCDEFGH", "manage"): "manageable",
                ("ABCDEFGH", "provide"): "available",
            }
        )

        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
            "message": "Success",
            "introspected_nodes": {},
        }

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        self._check_workflow_call()

    def test_introspect_bulk_failed(self):
        client = self.app.client_manager.baremetal
        client.node = fakes.FakeBaremetalNodeClient(
            states={"ABCDEFGH": "available"},
            transitions={
                ("ABCDEFGH", "manage"): "manageable",
                ("ABCDEFGH", "provide"): "available",
            }
        )

        self.websocket.wait_for_message.return_value = {
            "status": "ERROR",
            "message": "Failed",
        }

        parsed_args = self.check_parser(self.cmd, [], [])

        self.assertRaises(
            exceptions.IntrospectionError,
            self.cmd.take_action, parsed_args)

        self._check_workflow_call(provide=False)


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
        self.node = mock.Mock(uuid='foo')
        self.ready_state_data = """{
    "compute" :{
        "bios_settings": {"ProcVirtualization": "Enabled"}
    },
    "storage" :{
        "bios_settings": {"ProcVirtualization": "Disabled"}
    }
}
"""
        self.ready_state_config = {
            "compute": {
                "bios_settings": {"ProcVirtualization": "Enabled"}
            },
            "storage": {
                "bios_settings": {"ProcVirtualization": "Disabled"},
            }
        }

    @mock.patch('tripleoclient.utils.node_get_capabilities')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_apply_changes')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_configure_bios')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_change_power_state')
    def test_configure_ready_state(
            self, mock_change_power_state, mock_configure_bios,
            mock_apply_changes, mock_node_get_capabilities):

        nodes = [mock.Mock(uuid='foo', driver='drac'),
                 mock.Mock(uuid='bar', driver='ilo'),
                 mock.Mock(uuid='baz', driver='drac')]
        drac_nodes = [node for node in nodes if 'drac' in node.driver]
        drac_nodes_with_profiles = [(drac_nodes[0], 'compute'),
                                    (drac_nodes[1], 'storage')]

        bm_client = self.app.client_manager.baremetal
        bm_client.node.list.return_value = nodes

        mock_node_get_capabilities.side_effect = [
            {'profile': 'compute'}, {'profile': 'storage'}]
        mock_configure_bios.return_value = set([nodes[0]])

        arglist = ['ready-state.json']
        verifylist = [('file', 'ready-state.json')]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        with mock.patch('six.moves.builtins.open',
                        mock.mock_open(read_data=self.ready_state_data)):
            self.cmd.take_action(parsed_args)

        mock_node_get_capabilities.assert_has_calls(
            [mock.call(nodes[0]), mock.call(nodes[2])])
        mock_configure_bios.assert_called_once_with(drac_nodes_with_profiles)
        mock_apply_changes.assert_has_calls([
            # configure BIOS
            mock.call(set([nodes[0]]))])
        mock_change_power_state.assert_called_once_with(drac_nodes, 'off')

    @mock.patch.object(baremetal.ConfigureReadyState, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test__configure_bios(self, mock_sleep_time):
        nodes = [(self.node, 'compute')]
        bm_client = self.app.client_manager.baremetal
        self.cmd.bm_client = bm_client
        self.cmd.ready_state_config = self.ready_state_config

        self.cmd._configure_bios(nodes)

        bm_client.node.vendor_passthru.assert_has_calls([
            mock.call('foo', 'set_bios_config',
                      args={'ProcVirtualization': 'Enabled'},
                      http_method='POST'),
            mock.call('foo', 'commit_bios_config', http_method='POST')])

    @mock.patch.object(baremetal.ConfigureReadyState, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test__wait_for_drac_config_jobs(self, mock_sleep_time):
        nodes = [self.node]
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
        nodes = [self.node]
        bm_client = self.app.client_manager.baremetal
        bm_client.node.vendor_passthru.return_value = mock.Mock(
            unfinished_jobs={'percent_complete': '34',
                             'id': 'JID_343938731947',
                             'name': 'ConfigBIOS:BIOS.Setup.1-1'})
        self.cmd.bm_client = bm_client

        self.assertRaises(exceptions.Timeout,
                          self.cmd._wait_for_drac_config_jobs,
                          nodes)

    def test__change_power_state(self):
        nodes = [self.node]
        bm_client = self.app.client_manager.baremetal
        self.cmd.bm_client = bm_client

        self.cmd._change_power_state(nodes, 'reboot')

        bm_client.node.set_power_state.assert_called_once_with('foo', 'reboot')

    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_change_power_state')
    @mock.patch('tripleoclient.v1.baremetal.ConfigureReadyState.'
                '_wait_for_drac_config_jobs')
    def test__apply_changes(self, mock_wait_for_drac_config_jobs,
                            mock_change_power_state):
        nodes = [self.node]
        bm_client = self.app.client_manager.baremetal
        self.cmd.bm_client = bm_client

        self.cmd._apply_changes(nodes)

        mock_change_power_state.assert_called_once_with(nodes, 'reboot')
        mock_wait_for_drac_config_jobs.assert_called_once_with(nodes)


class TestConfigureBaremetalBoot(fakes.TestBaremetal):

    def setUp(self):
        super(TestConfigureBaremetalBoot, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.ConfigureBaremetalBoot(self.app, None)

        # Mistral-related mocks
        self.workflow = self.app.client_manager.workflow_engine
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()
        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
            "message": ""
        }

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

        self.workflow_input = {'queue_name': 'UUID4',
                               'node_uuids': ['ABCDEFGH'],
                               'kernel_name': 'bm-deploy-kernel',
                               'ramdisk_name': 'bm-deploy-ramdisk',
                               'root_device': None,
                               'root_device_minimum_size': 4,
                               'overwrite_root_device_hints': False}
        # Ironic mocks
        self.bm_client = self.app.client_manager.baremetal
        self.bm_client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH"),
        ]

        self.node = mock.Mock(uuid="ABCDEFGH", properties={})
        self.bm_client.node.get.return_value = self.node

    def test_configure_boot(self):
        self.bm_client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH"),
            mock.Mock(uuid="IJKLMNOP"),
        ]

        self.bm_client.node.get.side_effect = [
            mock.Mock(uuid="ABCDEFGH", properties={}),
            mock.Mock(uuid="IJKLMNOP", properties={}),
        ]

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        call_list = [mock.call('tripleo.baremetal.v1.configure',
                               workflow_input=self.workflow_input)]

        workflow_input = copy.copy(self.workflow_input)
        workflow_input['node_uuids'] = ["IJKLMNOP"]
        call_list.append(mock.call('tripleo.baremetal.v1.configure',
                                   workflow_input=workflow_input))

        self.workflow.executions.create.assert_has_calls(call_list)

    def test_configure_boot_with_suffix(self):
        self.bm_client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH"),
            mock.Mock(uuid="IJKLMNOP"),
        ]

        self.bm_client.node.get.side_effect = [
            mock.Mock(uuid="ABCDEFGH", properties={}),
            mock.Mock(uuid="IJKLMNOP", properties={}),
        ]

        arglist = ['--deploy-kernel', 'bm-deploy-kernel_20150101T100620',
                   '--deploy-ramdisk', 'bm-deploy-ramdisk_20150101T100620']
        verifylist = [('deploy_kernel', 'bm-deploy-kernel_20150101T100620'),
                      ('deploy_ramdisk', 'bm-deploy-ramdisk_20150101T100620')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        self.workflow_input['kernel_name'] = 'bm-deploy-kernel_20150101T100620'
        self.workflow_input['ramdisk_name'] = (
            'bm-deploy-ramdisk_20150101T100620')

        call_list = [mock.call('tripleo.baremetal.v1.configure',
                               workflow_input=self.workflow_input)]

        workflow_input = copy.copy(self.workflow_input)
        workflow_input['node_uuids'] = ["IJKLMNOP"]
        call_list.append(mock.call('tripleo.baremetal.v1.configure',
                                   workflow_input=workflow_input))

        self.workflow.executions.create.assert_has_calls(call_list)

    @mock.patch.object(baremetal.ConfigureBaremetalBoot, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test_configure_boot_in_transition(self, _):
        self.bm_client.node.list.return_value = [mock.Mock(uuid="ABCDEFGH",
                                                           power_state=None)]

        self.bm_client.node.get.side_effect = [
            mock.Mock(uuid="ABCDEFGH", power_state=None, properties={}),
            mock.Mock(uuid="ABCDEFGH", power_state=None, properties={}),
            mock.Mock(uuid="ABCDEFGH", power_state='available', properties={}),
            mock.Mock(uuid="ABCDEFGH", power_state='available', properties={}),
        ]

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(1, self.bm_client.node.list.call_count)
        self.assertEqual(3, self.bm_client.node.get.call_count)
        self.assertEqual(1, self.workflow.executions.create.call_count)

    @mock.patch.object(baremetal.ConfigureBaremetalBoot, 'sleep_time',
                       new_callable=mock.PropertyMock,
                       return_value=0)
    def test_configure_boot_timeout(self, _):
        self.bm_client.node.list.return_value = [mock.Mock(uuid="ABCDEFGH",
                                                           power_state=None)]
        self.bm_client.node.get.return_value = mock.Mock(uuid="ABCDEFGH",
                                                         power_state=None)
        parsed_args = self.check_parser(self.cmd, [], [])
        self.assertRaises(exceptions.Timeout,
                          self.cmd.take_action,
                          parsed_args)

    def test_configure_boot_skip_maintenance(self):
        self.bm_client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH", maintenance=False),
        ]

        self.bm_client.node.get.return_value = mock.Mock(uuid="ABCDEFGH",
                                                         maintenance=False,
                                                         properties={})

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(self.bm_client.node.list.mock_calls, [mock.call(
            maintenance=False)])

    def test_root_device_options(self):
        argslist = ['--root-device', 'smallest',
                    '--root-device-minimum-size', '2',
                    '--overwrite-root-device-hints']
        verifylist = [('root_device', 'smallest'),
                      ('root_device_minimum_size', 2),
                      ('overwrite_root_device_hints', True)]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

        self.workflow_input['root_device'] = 'smallest'
        self.workflow_input['root_device_minimum_size'] = 2
        self.workflow_input['overwrite_root_device_hints'] = True
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.configure',
            workflow_input=self.workflow_input
        )


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
