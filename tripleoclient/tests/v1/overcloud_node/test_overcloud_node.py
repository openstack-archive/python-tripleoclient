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

from openstackclient.tests import utils as test_utils


from tripleoclient.tests.v1.overcloud_node import fakes
from tripleoclient.v1 import overcloud_node


class TestDeleteNode(fakes.TestDeleteNode):

    def setUp(self):
        super(TestDeleteNode, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_node.DeleteNode(self.app, None)

    # TODO(someone): This test does not pass with autospec=True, it should
    # probably be fixed so that it can pass with that.
    @mock.patch('tripleo_common.scale.ScaleManager')
    def test_node_delete(self, scale_manager):
        argslist = ['instance1', 'instance2', '--templates',
                    '--stack', 'overcloud']
        verifylist = [
            ('stack', 'overcloud'),
            ('nodes', ['instance1', 'instance2'])
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        scale_manager.scaledown(parsed_args.nodes)
        scale_manager.scaledown.assert_called_once_with(['instance1',
                                                         'instance2'])


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
