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

import mock

from osc_lib.tests import utils

from tripleoclient import exceptions
from tripleoclient.workflows import baremetal


class TestBaremetalWorkflows(utils.TestCommand):

    def setUp(self):
        super(TestBaremetalWorkflows, self).setUp()

        self.app.client_manager.workflow_engine = self.workflow = mock.Mock()
        self.tripleoclient = mock.Mock()
        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution

        self.message_success = iter([{
            "execution_id": "IDID",
            "status": "SUCCESS",
            "message": "Success.",
            "registered_nodes": [],
        }])
        self.message_failed = iter([{
            "execution_id": "IDID",
            "status": "FAIL",
            "message": "Fail.",
        }])

    def test_register_or_update_success(self):

        self.websocket.wait_for_messages.return_value = self.message_success

        self.assertEqual(baremetal.register_or_update(
            self.app.client_manager,
            nodes_json=[],
            kernel_name="kernel",
            ramdisk_name="ramdisk"
        ), [])

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.register_or_update',
            workflow_input={
                'kernel_name': 'kernel',
                'nodes_json': [],
                'ramdisk_name': 'ramdisk'
            })

    def test_register_or_update_error(self):

        self.websocket.wait_for_messages.return_value = self.message_failed

        self.assertRaises(
            exceptions.RegisterOrUpdateError,
            baremetal.register_or_update,
            self.app.client_manager,
            nodes_json=[],
            kernel_name="kernel",
            ramdisk_name="ramdisk"
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.register_or_update',
            workflow_input={
                'kernel_name': 'kernel',
                'nodes_json': [],
                'ramdisk_name': 'ramdisk'
            })

    def test_provide_success(self):

        self.websocket.wait_for_messages.return_value = self.message_success

        baremetal.provide(self.app.client_manager, node_uuids=[])

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide',
            workflow_input={
                'node_uuids': [],
            })

    def test_provide_error(self):

        self.websocket.wait_for_messages.return_value = self.message_failed

        self.assertRaises(
            exceptions.NodeProvideError,
            baremetal.provide,
            self.app.client_manager,
            node_uuids=[]
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide',
            workflow_input={
                'node_uuids': [],
            })

    def test_format_errors(self):
        payload = {'message': [{'result': 'Error1a\nError1b'},
                               {'result': 'Error2a\nError2b\n'}]}

        error_string = baremetal._format_errors(payload)
        self.assertEqual(error_string, "Error1b\nError2b")

    def test_provide_error_with_format_message(self):

        self.websocket.wait_for_messages.return_value = iter([{
            "execution_id": "IDID",
            "status": "FAIL",
            "message": ['Error1', 'Error2']
        }])

        self.assertRaises(
            exceptions.NodeProvideError,
            baremetal.provide,
            self.app.client_manager,
            node_uuids=[]
        )

    def test_introspect_success(self):

        self.websocket.wait_for_messages.return_value = self.message_success

        baremetal.introspect(self.app.client_manager, node_uuids=[],
                             run_validations=True)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.introspect',
            workflow_input={
                'node_uuids': [],
                'run_validations': True,
            })

    def test_introspect_error(self):

        self.websocket.wait_for_messages.return_value = self.message_failed

        self.assertRaises(
            exceptions.IntrospectionError,
            baremetal.introspect,
            self.app.client_manager,
            node_uuids=[],
            run_validations=False
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.introspect',
            workflow_input={
                'node_uuids': [],
                'run_validations': False,
            })

    def test_introspect_manageable_nodes_success(self):

        self.websocket.wait_for_messages.return_value = iter([{
            "execution_id": "IDID",
            "status": "SUCCESS",
            "introspected_nodes": {},
        }])

        baremetal.introspect_manageable_nodes(
            self.app.client_manager, run_validations=False
        )
        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.introspect_manageable_nodes',
            workflow_input={
                'run_validations': False,
            })

    def test_introspect_manageable_nodes_error(self):

        self.websocket.wait_for_messages.return_value = self.message_failed

        self.assertRaises(
            exceptions.IntrospectionError,
            baremetal.introspect_manageable_nodes,
            self.app.client_manager,
            run_validations=False
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.introspect_manageable_nodes',
            workflow_input={
                'run_validations': False,
            })

    def test_introspect_manageable_nodes_mixed_status(self):

        self.websocket.wait_for_messages.return_value = iter([{
            "execution_id": "IDID",
            "status": "SUCCESS",
            "introspected_nodes": {'node1': {'error': None},
                                   'node2': {'error': 'Error'}}
        }])

        self.assertRaises(
            exceptions.IntrospectionError,
            baremetal.introspect_manageable_nodes,
            self.app.client_manager,
            run_validations=False
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.introspect_manageable_nodes',
            workflow_input={
                'run_validations': False,
            })

    def test_provide_manageable_nodes_success(self):

        self.websocket.wait_for_messages.return_value = self.message_success

        baremetal.provide_manageable_nodes(
            self.app.client_manager
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide_manageable_nodes',
            workflow_input={}
        )

    def test_provide_manageable_nodes_error(self):

        self.websocket.wait_for_messages.return_value = self.message_failed

        self.assertRaises(
            exceptions.NodeProvideError,
            baremetal.provide_manageable_nodes,
            self.app.client_manager)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide_manageable_nodes',
            workflow_input={}
        )

    def test_configure_success(self):

        self.websocket.wait_for_messages.return_value = self.message_success

        baremetal.configure(self.app.client_manager, node_uuids=[])

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.configure',
            workflow_input={
                'node_uuids': [],
            })

    def test_configure_error(self):

        self.websocket.wait_for_messages.return_value = self.message_failed

        self.assertRaises(
            exceptions.NodeConfigurationError,
            baremetal.configure,
            self.app.client_manager,
            node_uuids=[]
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.configure',
            workflow_input={
                'node_uuids': [],
            })

    def test_configure_manageable_nodes_success(self):

        self.websocket.wait_for_messages.return_value = self.message_success

        baremetal.configure_manageable_nodes(self.app.client_manager)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.configure_manageable_nodes',
            workflow_input={}
        )

    def test_configure_manageable_nodes_error(self):

        self.websocket.wait_for_messages.return_value = self.message_failed

        self.assertRaises(
            exceptions.NodeConfigurationError,
            baremetal.configure_manageable_nodes,
            self.app.client_manager
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.configure_manageable_nodes',
            workflow_input={}
        )

    def test_clean_nodes_success(self):

        self.websocket.wait_for_messages.return_value = self.message_success

        baremetal.clean_nodes(self.app.client_manager, node_uuids=[])

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.clean_nodes',
            workflow_input={
                'node_uuids': [],
            })

    def test_clean_nodes_error(self):

        self.websocket.wait_for_messages.return_value = self.message_failed

        self.assertRaises(
            exceptions.NodeConfigurationError,
            baremetal.clean_nodes,
            self.app.client_manager,
            node_uuids=[]
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.clean_nodes',
            workflow_input={
                'node_uuids': [],
            })

    def test_clean_manageable_nodes_success(self):

        self.websocket.wait_for_messages.return_value = iter([{
            "execution_id": "IDID",
            "status": "SUCCESS",
            "cleaned_nodes": [],
        }])

        baremetal.clean_manageable_nodes(
            self.app.client_manager
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.clean_manageable_nodes',
            workflow_input={}
        )

    def test_clean_manageable_nodes_error(self):

        self.websocket.wait_for_messages.return_value = self.message_failed

        self.assertRaises(
            exceptions.NodeConfigurationError,
            baremetal.clean_manageable_nodes,
            self.app.client_manager)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.clean_manageable_nodes',
            workflow_input={}
        )
