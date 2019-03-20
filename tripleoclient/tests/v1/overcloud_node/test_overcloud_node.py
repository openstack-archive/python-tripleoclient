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

import collections
import copy
import json
import mock
import os
import tempfile

from osc_lib.tests import utils as test_utils
import yaml

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
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution

    # TODO(someone): This test does not pass with autospec=True, it should
    # probably be fixed so that it can pass with that.
    def test_node_delete(self):
        argslist = ['instance1', 'instance2', '--templates',
                    '--stack', 'overcast', '--timeout', '90']
        verifylist = [
            ('stack', 'overcast'),
            ('nodes', ['instance1', 'instance2'])
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.websocket.wait_for_messages.return_value = iter([{
            "execution_id": "IDID",
            "status": "SUCCESS"
        }])

        self.stack_name.return_value = mock.Mock(stack_name="overcast")

        self.cmd.take_action(parsed_args)

        # Verify
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.scale.v1.delete_node',
            workflow_input={
                'container': 'overcast',
                'nodes': ['instance1', 'instance2'],
                'timeout': 90
            })

    def test_node_wrong_stack(self):
        argslist = ['instance1', '--templates',
                    '--stack', 'overcast']
        verifylist = [
            ('stack', 'overcast'),
            ('nodes', ['instance1', ])
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

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

        self.websocket.wait_for_messages.return_value = iter([{
            "execution_id": "IDID",
            "status": "SUCCESS"
        }])

        self.cmd.take_action(parsed_args)

        # Verify
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.scale.v1.delete_node',
            workflow_input={
                'container': 'overcloud',
                'nodes': ['instance1', ],
                'timeout': 240
            })

    def test_node_delete_wrong_instance(self):

        argslist = ['wrong_instance', '--templates',
                    '--stack', 'overcloud']
        verifylist = [
            ('stack', 'overcloud'),
            ('nodes', ['wrong_instance']),
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.websocket.wait_for_messages.return_value = iter([{
            "status": "FAILED",
            "execution_id": "IDID",
            "message": """Failed to run action ERROR: Couldn't find \
                following instances in stack overcloud: wrong_instance"""
        }])

        self.assertRaises(exceptions.InvalidConfiguration,
                          self.cmd.take_action, parsed_args)

        # Verify
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.scale.v1.delete_node',
            workflow_input={
                'container': 'overcloud',
                'nodes': ['wrong_instance', ],
                'timeout': 240
            })


class TestProvideNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestProvideNode, self).setUp()

        self.workflow = self.app.client_manager.workflow_engine
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()

        # Get the command object to test
        self.cmd = overcloud_node.ProvideNode(self.app, None)

        self.websocket.wait_for_messages.return_value = iter([{
            "status": "SUCCESS",
            "message": "Success",
            "execution_id": "IDID"
        }])

    def test_provide_all_manageable_nodes(self):

        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable'],
                                        [('all_manageable', True)])
        self.cmd.take_action(parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide_manageable_nodes',
            workflow_input={}
        )

    def test_provide_one_node(self):
        node_id = 'node_uuid1'

        parsed_args = self.check_parser(self.cmd,
                                        [node_id],
                                        [('node_uuids', [node_id])])
        self.cmd.take_action(parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide',
            workflow_input={'node_uuids': [node_id]}
        )

    def test_provide_multiple_nodes(self):
        node_id1 = 'node_uuid1'
        node_id2 = 'node_uuid2'

        argslist = [node_id1, node_id2]
        verifylist = [('node_uuids', [node_id1, node_id2])]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide', workflow_input={
                'node_uuids': [node_id1, node_id2]
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
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()

        # Get the command object to test
        self.cmd = overcloud_node.IntrospectNode(self.app, None)

    def _check_introspect_all_manageable(self, parsed_args, provide=False):
        self.websocket.wait_for_messages.return_value = iter([{
            "status": "SUCCESS",
            "message": "Success",
            "introspected_nodes": {},
            "execution_id": "IDID"
        }] * 2)

        self.cmd.take_action(parsed_args)

        call_list = [mock.call(
            'tripleo.baremetal.v1.introspect_manageable_nodes',
            workflow_input={'run_validations': False}
        )]

        if provide:
            call_list.append(mock.call(
                'tripleo.baremetal.v1.provide_manageable_nodes',
                workflow_input={}
            ))

        self.workflow.executions.create.assert_has_calls(call_list)
        self.assertEqual(self.workflow.executions.create.call_count,
                         2 if provide else 1)

    def _check_introspect_nodes(self, parsed_args, nodes, provide=False):
        self.websocket.wait_for_messages.return_value = [{
            "status": "SUCCESS",
            "message": "Success",
            "execution_id": "IDID",
        }]

        self.cmd.take_action(parsed_args)

        call_list = [mock.call(
            'tripleo.baremetal.v1.introspect', workflow_input={
                'node_uuids': nodes,
                'run_validations': False}
        )]

        if provide:
            call_list.append(mock.call(
                'tripleo.baremetal.v1.provide', workflow_input={
                    'node_uuids': nodes}
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


class TestCleanNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestCleanNode, self).setUp()

        self.workflow = self.app.client_manager.workflow_engine
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()

        # Get the command object to test
        self.cmd = overcloud_node.CleanNode(self.app, None)

    def _check_clean_all_manageable(self, parsed_args, provide=False):
        self.websocket.wait_for_messages.return_value = iter([{
            "status": "SUCCESS",
            "message": "Success",
            "cleaned_nodes": {},
            "execution_id": "IDID"
        }] * 2)

        self.cmd.take_action(parsed_args)

        call_list = [mock.call(
            'tripleo.baremetal.v1.clean_manageable_nodes',
            workflow_input={}
        )]

        if provide:
            call_list.append(mock.call(
                'tripleo.baremetal.v1.provide_manageable_nodes',
                workflow_input={}
            ))

        self.workflow.executions.create.assert_has_calls(call_list)
        self.assertEqual(self.workflow.executions.create.call_count,
                         2 if provide else 1)

    def _check_clean_nodes(self, parsed_args, nodes, provide=False):
        self.websocket.wait_for_messages.return_value = [{
            "status": "SUCCESS",
            "message": "Success",
            "execution_id": "IDID"
        }]

        self.cmd.take_action(parsed_args)

        call_list = [mock.call(
            'tripleo.baremetal.v1.clean_nodes', workflow_input={
                'node_uuids': nodes}
        )]

        if provide:
            call_list.append(mock.call(
                'tripleo.baremetal.v1.provide', workflow_input={
                    'node_uuids': nodes}
            ))

        self.workflow.executions.create.assert_has_calls(call_list)
        self.assertEqual(self.workflow.executions.create.call_count,
                         2 if provide else 1)

    def test_clean_all_manageable_nodes_without_provide(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable'],
                                        [('all_manageable', True)])
        self._check_clean_all_manageable(parsed_args, provide=False)

    def test_clean_all_manageable_nodes_with_provide(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable', '--provide'],
                                        [('all_manageable', True),
                                         ('provide', True)])
        self._check_clean_all_manageable(parsed_args, provide=True)

    def test_clean_nodes_without_provide(self):
        nodes = ['node_uuid1', 'node_uuid2']
        parsed_args = self.check_parser(self.cmd,
                                        nodes,
                                        [('node_uuids', nodes)])
        self._check_clean_nodes(parsed_args, nodes, provide=False)

    def test_clean_nodes_with_provide(self):
        nodes = ['node_uuid1', 'node_uuid2']
        argslist = nodes + ['--provide']

        parsed_args = self.check_parser(self.cmd,
                                        argslist,
                                        [('node_uuids', nodes),
                                         ('provide', True)])
        self._check_clean_nodes(parsed_args, nodes, provide=True)


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
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()

        # Get the command object to test
        self.cmd = overcloud_node.ImportNode(self.app, None)

        image = collections.namedtuple('image', ['id', 'name'])
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.image.images.list.return_value = [
            image(id=1, name='bm-deploy-kernel'),
            image(id=2, name='bm-deploy-ramdisk'),
            image(id=3, name='overcloud-full'),
        ]

    def _check_workflow_call(self, parsed_args, introspect=False,
                             provide=False, local=None, no_deploy_image=False):
        self.websocket.wait_for_messages.return_value = [{
            "status": "SUCCESS",
            "message": "Success",
            "registered_nodes": [{
                "uuid": "MOCK_NODE_UUID"
            }],
            "execution_id": "IDID"
        }]

        self.cmd.take_action(parsed_args)

        nodes_list = copy.deepcopy(self.nodes_list)

        call_count = 1
        call_list = [mock.call(
            'tripleo.baremetal.v1.register_or_update', workflow_input={
                'nodes_json': nodes_list,
                'kernel_name': None if no_deploy_image else 'bm-deploy-kernel',
                'ramdisk_name': (None
                                 if no_deploy_image else 'bm-deploy-ramdisk'),
                'instance_boot_option': ('local' if local is True else
                                         'netboot' if local is False else None)
            }
        )]

        if introspect:
            call_count += 1
            call_list.append(mock.call(
                'tripleo.baremetal.v1.introspect', workflow_input={
                    'node_uuids': ['MOCK_NODE_UUID'],
                    'run_validations': False}
            ))

        if provide:
            call_count += 1
            call_list.append(mock.call(
                'tripleo.baremetal.v1.provide', workflow_input={
                    'node_uuids': ['MOCK_NODE_UUID']
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


class TestImportNodeMultiArch(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestImportNodeMultiArch, self).setUp()

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
            "arch": "x86_64",
            "mac": [
                "00:0b:d0:69:7e:58"
            ]
        }, {
            "pm_user": "stack",
            "pm_addr": "192.168.122.3",
            "pm_password": "KEY3",
            "pm_type": "pxe_ssh",
            "arch": "x86_64",
            "platform": "SNB",
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
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()

        # Get the command object to test
        self.cmd = overcloud_node.ImportNode(self.app, None)

        image = collections.namedtuple('image', ['id', 'name'])
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.image.images.list.return_value = [
            image(id=1, name='bm-deploy-kernel'),
            image(id=2, name='bm-deploy-ramdisk'),
            image(id=3, name='overcloud-full'),
            image(id=4, name='x86_64-bm-deploy-kernel'),
            image(id=5, name='x86_64-bm-deploy-ramdisk'),
            image(id=6, name='x86_64-overcloud-full'),
            image(id=7, name='SNB-x86_64-bm-deploy-kernel'),
            image(id=8, name='SNB-x86_64-bm-deploy-ramdisk'),
            image(id=9, name='SNB-x86_64-overcloud-full'),
        ]

    def _check_workflow_call(self, parsed_args, introspect=False,
                             provide=False, local=None, no_deploy_image=False):
        self.websocket.wait_for_messages.return_value = [{
            "status": "SUCCESS",
            "message": "Success",
            "registered_nodes": [{
                "uuid": "MOCK_NODE_UUID"
            }],
            "execution_id": "IDID"
        }]

        self.cmd.take_action(parsed_args)

        nodes_list = copy.deepcopy(self.nodes_list)
        # We expect update_nodes_deploy_data() to set these values for the
        # nodes with an 'arch' field
        nodes_list[1]['kernel_id'] = 4
        nodes_list[1]['ramdisk_id'] = 5
        nodes_list[2]['kernel_id'] = 7
        nodes_list[2]['ramdisk_id'] = 8

        call_count = 1
        call_list = [mock.call(
            'tripleo.baremetal.v1.register_or_update', workflow_input={
                'nodes_json': nodes_list,
                'kernel_name': None if no_deploy_image else 'bm-deploy-kernel',
                'ramdisk_name': (None
                                 if no_deploy_image else 'bm-deploy-ramdisk'),
                'instance_boot_option': ('local' if local is True else
                                         'netboot' if local is False else None)
            }
        )]

        if introspect:
            call_count += 1
            call_list.append(mock.call(
                'tripleo.baremetal.v1.introspect', workflow_input={
                    'node_uuids': ['MOCK_NODE_UUID'],
                    'run_validations': False}
            ))

        if provide:
            call_count += 1
            call_list.append(mock.call(
                'tripleo.baremetal.v1.provide', workflow_input={
                    'node_uuids': ['MOCK_NODE_UUID']
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
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()
        self.websocket.wait_for_messages.return_value = iter([{
            "status": "SUCCESS",
            "message": "",
            "execution_id": "IDID"
        }])

        # Get the command object to test
        self.cmd = overcloud_node.ConfigureNode(self.app, None)

        self.workflow_input = {'kernel_name': 'bm-deploy-kernel',
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
        self.websocket.wait_for_messages.return_value = iter([{
            "status": "FAILED",
            "message": "Test failure.",
            "execution_id": "IDID"
        }])

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
        self.websocket.wait_for_messages.return_value = iter([{
            "status": "FAILED",
            "message": "Test failure.",
            "execution_id": "IDID"
        }])

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


class TestDiscoverNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestDiscoverNode, self).setUp()

        self.workflow = self.app.client_manager.workflow_engine
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()

        self.cmd = overcloud_node.DiscoverNode(self.app, None)

        self.websocket.wait_for_messages.return_value = [{
            "status": "SUCCESS",
            "message": "Success",
            "registered_nodes": [{
                "uuid": "MOCK_NODE_UUID"
            }],
            "execution_id": "IDID"
        }]

    def test_with_ip_range(self):
        argslist = ['--range', '10.0.0.0/24',
                    '--credentials', 'admin:password']
        verifylist = [('ip_addresses', '10.0.0.0/24'),
                      ('credentials', ['admin:password'])]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.discover_and_enroll_nodes',
            workflow_input={'ip_addresses': '10.0.0.0/24',
                            'credentials': [['admin', 'password']],
                            'kernel_name': 'bm-deploy-kernel',
                            'ramdisk_name': 'bm-deploy-ramdisk',
                            'instance_boot_option': 'local'}
        )

    def test_with_address_list(self):
        argslist = ['--ip', '10.0.0.1', '--ip', '10.0.0.2',
                    '--credentials', 'admin:password']
        verifylist = [('ip_addresses', ['10.0.0.1', '10.0.0.2']),
                      ('credentials', ['admin:password'])]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.discover_and_enroll_nodes',
            workflow_input={'ip_addresses': ['10.0.0.1', '10.0.0.2'],
                            'credentials': [['admin', 'password']],
                            'kernel_name': 'bm-deploy-kernel',
                            'ramdisk_name': 'bm-deploy-ramdisk',
                            'instance_boot_option': 'local'}
        )

    def test_with_all_options(self):
        argslist = ['--range', '10.0.0.0/24',
                    '--credentials', 'admin:password',
                    '--credentials', 'admin2:password2',
                    '--port', '623', '--port', '6230',
                    '--introspect', '--provide', '--run-validations',
                    '--no-deploy-image', '--instance-boot-option', 'netboot']
        verifylist = [('ip_addresses', '10.0.0.0/24'),
                      ('credentials', ['admin:password', 'admin2:password2']),
                      ('port', [623, 6230]),
                      ('introspect', True),
                      ('run_validations', True),
                      ('provide', True),
                      ('no_deploy_image', True),
                      ('instance_boot_option', 'netboot')]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

        workflows_calls = [
            mock.call('tripleo.baremetal.v1.discover_and_enroll_nodes',
                      workflow_input={'ip_addresses': '10.0.0.0/24',
                                      'credentials': [['admin', 'password'],
                                                      ['admin2', 'password2']],
                                      'ports': [623, 6230],
                                      'kernel_name': None,
                                      'ramdisk_name': None,
                                      'instance_boot_option': 'netboot'}),
            mock.call('tripleo.baremetal.v1.introspect',
                      workflow_input={'node_uuids': ['MOCK_NODE_UUID'],
                                      'run_validations': True}),
            mock.call('tripleo.baremetal.v1.provide',
                      workflow_input={'node_uuids': ['MOCK_NODE_UUID']}
                      )
        ]
        self.workflow.executions.create.assert_has_calls(workflows_calls)


class TestProvisionNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestProvisionNode, self).setUp()

        self.workflow = self.app.client_manager.workflow_engine
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()
        self.websocket.wait_for_messages.return_value = [{
            "status": "SUCCESS",
            "message": "Success",
            "environment": {"cat": "meow"},
            "execution": {"id": "IDID"}
        }]

        self.cmd = overcloud_node.ProvisionNode(self.app, None)

    def test_ok(self):
        with tempfile.NamedTemporaryFile() as inp:
            with tempfile.NamedTemporaryFile() as outp:
                with tempfile.NamedTemporaryFile() as keyf:
                    inp.write(b'- name: Compute\n- name: Controller\n')
                    inp.flush()
                    keyf.write(b'I am a key')
                    keyf.flush()

                    argslist = ['--output', outp.name,
                                '--overcloud-ssh-key', keyf.name,
                                inp.name]
                    verifylist = [('input', inp.name),
                                  ('output', outp.name),
                                  ('overcloud_ssh_key', keyf.name)]

                    parsed_args = self.check_parser(self.cmd,
                                                    argslist, verifylist)
                    self.cmd.take_action(parsed_args)

                    data = yaml.safe_load(outp)
                    self.assertEqual({"cat": "meow"}, data)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal_deploy.v1.deploy_roles',
            workflow_input={'roles': [{'name': 'Compute'},
                                      {'name': 'Controller'}],
                            'ssh_keys': ['I am a key'],
                            'ssh_user_name': 'heat-admin'}
        )
