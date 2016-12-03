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
import mock
import os
import tempfile

from osc_lib.tests import utils as test_utils

from tripleoclient import exceptions
from tripleoclient.tests.v1.overcloud_node import fakes
from tripleoclient.v1 import overcloud_node


class TestDeleteNode(fakes.TestDeleteNode):

    def setUp(self):
        super(TestDeleteNode, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_node.DeleteNode(self.app, None)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.tripleoclient = mock.Mock()

        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient = mock.Mock()
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient

        self.workflow = self.app.client_manager.workflow_engine
        self.stack_name = self.app.client_manager.orchestration.stacks.get
        self.stack_name.return_value = mock.Mock(stack_name="overcloud")

        # Mock UUID4 generation for every test
        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    # TODO(someone): This test does not pass with autospec=True, it should
    # probably be fixed so that it can pass with that.
    def test_node_delete(self):
        argslist = ['instance1', 'instance2', '--templates',
                    '--stack', 'overcast']
        verifylist = [
            ('stack', 'overcast'),
            ('nodes', ['instance1', 'instance2'])
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS"
        }

        self.stack_name.return_value = mock.Mock(stack_name="overcast")

        self.cmd.take_action(parsed_args)

        # Verify
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.scale.v1.delete_node',
            workflow_input={
                'container': 'overcast',
                'queue_name': 'UUID4',
                'nodes': ['instance1', 'instance2']
            })

    def test_node_wrong_stack(self):
        argslist = ['instance1', '--templates',
                    '--stack', 'overcast']
        verifylist = [
            ('stack', 'overcast'),
            ('nodes', ['instance1', ])
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS"
        }

        self.stack_name.return_value = None

        self.assertRaises(exceptions.InvalidConfiguration,
                          self.cmd.take_action,
                          parsed_args)

        # Verify
        self.workflow.executions.create.assert_not_called()

    def test_node_delete_without_stack(self):

        arglist = ['instance1', ]

        verifylist = [
            ('stack', 'overcloud'),
            ('nodes', ['instance1']),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS"
        }

        self.cmd.take_action(parsed_args)

        # Verify
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.scale.v1.delete_node',
            workflow_input={
                'container': 'overcloud',
                'queue_name': 'UUID4',
                'nodes': ['instance1', ]
            })

    def test_node_delete_wrong_instance(self):

        argslist = ['wrong_instance', '--templates',
                    '--stack', 'overcloud']
        verifylist = [
            ('stack', 'overcloud'),
            ('nodes', ['wrong_instance']),
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.websocket.wait_for_message.return_value = {
            "status": "FAILED",
            "message": """Failed to run action ERROR: Couldn't find \
                following instances in stack overcloud: wrong_instance"""
        }

        self.assertRaises(exceptions.InvalidConfiguration,
                          self.cmd.take_action, parsed_args)

        # Verify
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.scale.v1.delete_node',
            workflow_input={
                'container': 'overcloud',
                'queue_name': 'UUID4',
                'nodes': ['wrong_instance', ]
            })


class TestProvideNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestProvideNode, self).setUp()

        self.workflow = self.app.client_manager.workflow_engine
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()

        # Get the command object to test
        self.cmd = overcloud_node.ProvideNode(self.app, None)

    def test_provide_all_manageable_nodes(self):
        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
            "message": ""
        }

        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable'],
                                        [('all_manageable', True)])
        self.cmd.take_action(parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide_manageable_nodes',
            workflow_input={'queue_name': 'UUID4'}
        )

    def test_provide_one_node(self):
        node_id = 'node_uuid1'

        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
            "message": "Success"
        }

        parsed_args = self.check_parser(self.cmd,
                                        [node_id],
                                        [('node_uuids', [node_id])])
        self.cmd.take_action(parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide', workflow_input={
                'node_uuids': [node_id],
                'queue_name': 'UUID4'}
        )

    def test_provide_multiple_nodes(self):
        node_id1 = 'node_uuid1'
        node_id2 = 'node_uuid2'

        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
            "message": "Success"
        }

        argslist = [node_id1, node_id2]
        verifylist = [('node_uuids', [node_id1, node_id2])]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide', workflow_input={
                'node_uuids': [node_id1, node_id2],
                'queue_name': 'UUID4'
            }
        )

    def test_provide_no_node_or_flag_specified(self):
        self.assertRaises(test_utils.ParserException,
                          self.check_parser,
                          self.cmd, [], [])

    def test_provide_uuids_and_all_both_specified(self):
        argslist = ['node_id1', 'node_id2', '--all-manageable']
        verifylist = [('node_uuids', ['node_id1', 'node_id2']),
                      ('all_manageable', True)]
        self.assertRaises(test_utils.ParserException,
                          self.check_parser,
                          self.cmd, argslist, verifylist)


class TestIntrospectNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestIntrospectNode, self).setUp()

        self.workflow = self.app.client_manager.workflow_engine
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()

        # Get the command object to test
        self.cmd = overcloud_node.IntrospectNode(self.app, None)

    def _check_introspect_all_manageable(self, parsed_args, provide=False):
        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
            "message": "Success",
            "introspected_nodes": {}
        }

        self.cmd.take_action(parsed_args)

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

    def _check_introspect_nodes(self, parsed_args, nodes, provide=False):
        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
            "message": "Success",
            "introspected_nodes": {}
        }

        self.cmd.take_action(parsed_args)

        call_list = [mock.call(
            'tripleo.baremetal.v1.introspect', workflow_input={
                'node_uuids': nodes,
                'queue_name': 'UUID4'}
        )]

        if provide:
            call_list.append(mock.call(
                'tripleo.baremetal.v1.provide', workflow_input={
                    'node_uuids': nodes,
                    'queue_name': 'UUID4'}
            ))

        self.workflow.executions.create.assert_has_calls(call_list)
        self.assertEqual(self.workflow.executions.create.call_count,
                         2 if provide else 1)

    def test_introspect_all_manageable_nodes_without_provide(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable'],
                                        [('all_manageable', True)])
        self._check_introspect_all_manageable(parsed_args, provide=False)

    def test_introspect_all_manageable_nodes_with_provide(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable', '--provide'],
                                        [('all_manageable', True),
                                         ('provide', True)])
        self._check_introspect_all_manageable(parsed_args, provide=True)

    def test_introspect_nodes_without_provide(self):
        nodes = ['node_uuid1', 'node_uuid2']
        parsed_args = self.check_parser(self.cmd,
                                        nodes,
                                        [('node_uuids', nodes)])
        self._check_introspect_nodes(parsed_args, nodes, provide=False)

    def test_introspect_nodes_with_provide(self):
        nodes = ['node_uuid1', 'node_uuid2']
        argslist = nodes + ['--provide']

        parsed_args = self.check_parser(self.cmd,
                                        argslist,
                                        [('node_uuids', nodes),
                                         ('provide', True)])
        self._check_introspect_nodes(parsed_args, nodes, provide=True)

    def test_introspect_no_node_or_flag_specified(self):
        self.assertRaises(test_utils.ParserException,
                          self.check_parser,
                          self.cmd, [], [])

    def test_introspect_uuids_and_all_both_specified(self):
        argslist = ['node_id1', 'node_id2', '--all-manageable']
        verifylist = [('node_uuids', ['node_id1', 'node_id2']),
                      ('all_manageable', True)]
        self.assertRaises(test_utils.ParserException,
                          self.check_parser,
                          self.cmd, argslist, verifylist)


class TestImportNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestImportNode, self).setUp()

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

        self.json_file = tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.json')
        json.dump(self.nodes_list, self.json_file)
        self.json_file.close()
        self.addCleanup(os.unlink, self.json_file.name)

        self.workflow = self.app.client_manager.workflow_engine
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()

        # Get the command object to test
        self.cmd = overcloud_node.ImportNode(self.app, None)

    def _check_workflow_call(self, parsed_args, introspect=False,
                             provide=False, local=True, no_deploy_image=False):
        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
            "message": "Success",
            "registered_nodes": [{
                "uuid": "MOCK_NODE_UUID"
            }]
        }

        self.cmd.take_action(parsed_args)

        nodes_list = copy.deepcopy(self.nodes_list)

        call_count = 1
        call_list = [mock.call(
            'tripleo.baremetal.v1.register_or_update', workflow_input={
                'nodes_json': nodes_list,
                'queue_name': 'UUID4',
                'kernel_name': None if no_deploy_image else 'bm-deploy-kernel',
                'ramdisk_name': (None
                                 if no_deploy_image else 'bm-deploy-ramdisk'),
                'instance_boot_option': 'local' if local else 'netboot'
            }
        )]

        if introspect:
            call_count += 1
            call_list.append(mock.call(
                'tripleo.baremetal.v1.introspect', workflow_input={
                    'node_uuids': ['MOCK_NODE_UUID'],
                    'queue_name': 'UUID4'}
            ))

        if provide:
            call_count += 1
            call_list.append(mock.call(
                'tripleo.baremetal.v1.provide', workflow_input={
                    'node_uuids': ['MOCK_NODE_UUID'],
                    'queue_name': 'UUID4'
                }
            ))

        self.workflow.executions.create.assert_has_calls(call_list)
        self.assertEqual(self.workflow.executions.create.call_count,
                         call_count)

    def test_import_only(self):
        argslist = [self.json_file.name]
        verifylist = [('introspect', False),
                      ('provide', False)]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self._check_workflow_call(parsed_args)

    def test_import_and_introspect(self):
        argslist = [self.json_file.name, '--introspect']
        verifylist = [('introspect', True),
                      ('provide', False)]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self._check_workflow_call(parsed_args, introspect=True)

    def test_import_and_provide(self):
        argslist = [self.json_file.name, '--provide']
        verifylist = [('introspect', False),
                      ('provide', True)]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self._check_workflow_call(parsed_args, provide=True)

    def test_import_and_introspect_and_provide(self):
        argslist = [self.json_file.name, '--introspect', '--provide']
        verifylist = [('introspect', True),
                      ('provide', True)]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self._check_workflow_call(parsed_args, introspect=True, provide=True)

    def test_import_with_netboot(self):
        arglist = [self.json_file.name, '--instance-boot-option', 'netboot']
        verifylist = [('instance_boot_option', 'netboot')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self._check_workflow_call(parsed_args, local=False)

    def test_import_with_no_deployed_image(self):
        arglist = [self.json_file.name, '--no-deploy-image']
        verifylist = [('no_deploy_image', True)]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self._check_workflow_call(parsed_args, no_deploy_image=True)


class TestConfigureNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestConfigureNode, self).setUp()

        self.workflow = self.app.client_manager.workflow_engine
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()
        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
            "message": ""
        }

        # Get the command object to test
        self.cmd = overcloud_node.ConfigureNode(self.app, None)

        self.workflow_input = {'queue_name': 'UUID4',
                               'kernel_name': 'bm-deploy-kernel',
                               'ramdisk_name': 'bm-deploy-ramdisk',
                               'instance_boot_option': None,
                               'root_device': None,
                               'root_device_minimum_size': 4,
                               'overwrite_root_device_hints': False}

    def test_configure_all_manageable_nodes(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable'],
                                        [('all_manageable', True)])
        self.cmd.take_action(parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.configure_manageable_nodes',
            workflow_input=self.workflow_input
        )

    def test_failed_to_configure_all_manageable_nodes(self):
        self.websocket.wait_for_message.return_value = {
            "status": "FAILED",
            "message": "Test failure."
        }

        parsed_args = self.check_parser(self.cmd, ['--all-manageable'], [])
        self.assertRaises(exceptions.NodeConfigurationError,
                          self.cmd.take_action, parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.configure_manageable_nodes',
            workflow_input=self.workflow_input
        )

    def test_configure_specified_nodes(self):
        argslist = ['node_uuid1', 'node_uuid2']
        verifylist = [('node_uuids', ['node_uuid1', 'node_uuid2'])]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

        self.workflow_input['node_uuids'] = ['node_uuid1', 'node_uuid2']
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.configure',
            workflow_input=self.workflow_input
        )

    def test_failed_to_configure_specified_nodes(self):
        self.websocket.wait_for_message.return_value = {
            "status": "FAILED",
            "message": "Test failure."
        }

        parsed_args = self.check_parser(self.cmd, ['node_uuid1'], [])
        self.assertRaises(exceptions.NodeConfigurationError,
                          self.cmd.take_action, parsed_args)

        self.workflow_input['node_uuids'] = ['node_uuid1']
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.configure',
            workflow_input=self.workflow_input
        )

    def test_configure_no_node_or_flag_specified(self):
        self.assertRaises(test_utils.ParserException,
                          self.check_parser,
                          self.cmd, [], [])

    def test_configure_uuids_and_all_both_specified(self):
        argslist = ['node_id1', 'node_id2', '--all-manageable']
        verifylist = [('node_uuids', ['node_id1', 'node_id2']),
                      ('all_manageable', True)]
        self.assertRaises(test_utils.ParserException,
                          self.check_parser,
                          self.cmd, argslist, verifylist)

    def test_configure_kernel_and_ram(self):
        argslist = ['--all-manageable', '--deploy-ramdisk', 'test_ramdisk',
                    '--deploy-kernel', 'test_kernel']
        verifylist = [('deploy_kernel', 'test_kernel'),
                      ('deploy_ramdisk', 'test_ramdisk')]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

        self.workflow_input['kernel_name'] = 'test_kernel'
        self.workflow_input['ramdisk_name'] = 'test_ramdisk'
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.configure_manageable_nodes',
            workflow_input=self.workflow_input
        )

    def test_configure_instance_boot_option(self):
        argslist = ['--all-manageable', '--instance-boot-option', 'netboot']
        verifylist = [('instance_boot_option', 'netboot')]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

        self.workflow_input['instance_boot_option'] = 'netboot'
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.configure_manageable_nodes',
            workflow_input=self.workflow_input
        )

    def test_configure_root_device(self):
        argslist = ['--all-manageable',
                    '--root-device', 'smallest',
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
            'tripleo.baremetal.v1.configure_manageable_nodes',
            workflow_input=self.workflow_input
        )

    def test_configure_specified_node_with_all_arguments(self):
        argslist = ['node_id',
                    '--deploy-kernel', 'test_kernel',
                    '--deploy-ramdisk', 'test_ramdisk',
                    '--instance-boot-option', 'netboot',
                    '--root-device', 'smallest',
                    '--root-device-minimum-size', '2',
                    '--overwrite-root-device-hints']
        verifylist = [('node_uuids', ['node_id']),
                      ('deploy_kernel', 'test_kernel'),
                      ('deploy_ramdisk', 'test_ramdisk'),
                      ('instance_boot_option', 'netboot'),
                      ('root_device', 'smallest'),
                      ('root_device_minimum_size', 2),
                      ('overwrite_root_device_hints', True)]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

        self.workflow_input.update({'node_uuids': ['node_id'],
                                    'kernel_name': 'test_kernel',
                                    'ramdisk_name': 'test_ramdisk',
                                   'instance_boot_option': 'netboot',
                                    'root_device': 'smallest',
                                    'root_device_minimum_size': 2,
                                    'overwrite_root_device_hints': True})
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.configure',
            workflow_input=self.workflow_input
        )
