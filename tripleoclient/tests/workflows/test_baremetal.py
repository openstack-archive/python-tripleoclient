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

    def test_register_or_update_success(self):

        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
            "registered_nodes": [],
        }

        self.assertEqual(baremetal.register_or_update(
            self.app.client_manager,
            nodes_json=[],
            queue_name="QUEUE_NAME",
            kernel_name="kernel",
            ramdisk_name="ramdisk"
        ), [])

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.register_or_update',
            workflow_input={
                'kernel_name': 'kernel',
                'queue_name': 'QUEUE_NAME',
                'nodes_json': [],
                'ramdisk_name': 'ramdisk'
            })

    def test_register_or_update_error(self):

        self.websocket.wait_for_message.return_value = {
            "status": "FAIL",
            "message": "FAILED",
        }

        self.assertRaises(
            exceptions.RegisterOrUpdateError,
            baremetal.register_or_update,
            self.app.client_manager,
            nodes_json=[],
            queue_name="QUEUE_NAME",
            kernel_name="kernel",
            ramdisk_name="ramdisk"
        )

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.register_or_update',
            workflow_input={
                'kernel_name': 'kernel',
                'queue_name': 'QUEUE_NAME',
                'nodes_json': [],
                'ramdisk_name': 'ramdisk'
            })

    def test_provide_success(self):

        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
        }

        baremetal.provide(self.app.client_manager, node_uuids=[],
                          queue_name="QUEUE_NAME")

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide',
            workflow_input={
                'node_uuids': [],
                'queue_name': "QUEUE_NAME"
            })

    def test_provide_error(self):

        self.websocket.wait_for_message.return_value = {
            "status": "FAIL",
            "message": "Failed"
        }

        self.assertRaises(
            exceptions.NodeProvideError,
            baremetal.provide,
            self.app.client_manager,
            node_uuids=[],
            queue_name="QUEUE_NAME")

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide',
            workflow_input={
                'node_uuids': [],
                'queue_name': "QUEUE_NAME"
            })

    def test_format_provide_errors(self):
        payload = {'message': [{'result': 'Error1a\nError1b'},
                               {'result': 'Error2a\nError2b\n'}]}

        error_string = baremetal._format_provide_errors(payload)
        self.assertEqual(error_string, "Error1b\nError2b")

    def test_provide_error_with_format_message(self):

        self.websocket.wait_for_message.return_value = {
            "status": "FAIL",
            "message": ['Error1', 'Error2']
        }

        self.assertRaises(
            exceptions.NodeProvideError,
            baremetal.provide,
            self.app.client_manager,
            node_uuids=[],
            queue_name="QUEUE_NAME")

    def test_introspect_success(self):

        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
            "introspected_nodes": {}
        }

        baremetal.introspect(self.app.client_manager, node_uuids=[],
                             queue_name="QUEUE_NAME")

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.introspect',
            workflow_input={
                'node_uuids': [],
                'queue_name': "QUEUE_NAME"
            })

    def test_introspect_error(self):

        self.websocket.wait_for_message.return_value = {
            "status": "FAIL",
            "message": "Failed",
            "introspected_nodes": {}
        }

        self.assertRaises(
            exceptions.IntrospectionError,
            baremetal.introspect,
            self.app.client_manager,
            node_uuids=[],
            queue_name="QUEUE_NAME")

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.introspect',
            workflow_input={
                'node_uuids': [],
                'queue_name': "QUEUE_NAME"
            })

    def test_introspect_manageable_nodes_success(self):

        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
            "introspected_nodes": {},
        }

        baremetal.introspect_manageable_nodes(
            self.app.client_manager, queue_name="QUEUE_NAME")

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.introspect_manageable_nodes',
            workflow_input={'queue_name': "QUEUE_NAME"})

    def test_introspect_manageable_nodes_error(self):

        self.websocket.wait_for_message.return_value = {
            "status": "FAIL",
            "message": "Failed"
        }

        self.assertRaises(
            exceptions.IntrospectionError,
            baremetal.introspect_manageable_nodes,
            self.app.client_manager, queue_name="QUEUE_NAME")

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.introspect_manageable_nodes',
            workflow_input={'queue_name': "QUEUE_NAME"})

    def test_provide_manageable_nodes_success(self):

        self.websocket.wait_for_message.return_value = {
            "status": "SUCCESS",
            "introspected_nodes": {},
            "message": "Success"
        }

        baremetal.provide_manageable_nodes(
            self.app.client_manager, queue_name="QUEUE_NAME")

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide_manageable_nodes',
            workflow_input={'queue_name': "QUEUE_NAME"})

    def test_provide_manageable_nodes_error(self):

        self.websocket.wait_for_message.return_value = {
            "status": "FAIL",
            "message": "Failed"
        }

        self.assertRaises(
            exceptions.NodeProvideError,
            baremetal.provide_manageable_nodes,
            self.app.client_manager, queue_name="QUEUE_NAME")

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.baremetal.v1.provide_manageable_nodes',
            workflow_input={'queue_name': "QUEUE_NAME"})
