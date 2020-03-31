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

import json
import mock

from osc_lib.tests import utils

from tripleoclient import exceptions as ex
from tripleoclient.workflows import base


class TestBaseWorkflows(utils.TestCommand):

    def test_wait_for_messages_success(self):
        payload_a = {
            'status': 'ERROR',
            'execution_id': 2,
            'root_execution_id': 1
        }
        payload_b = {
            'status': 'ERROR',
            'execution_id': 1,
            'root_execution_id': 1
        }

        mistral = mock.Mock()
        websocket = mock.Mock()
        websocket.wait_for_messages.return_value = iter([payload_a, payload_b])
        execution = mock.Mock()
        execution.id = 1

        messages = list(base.wait_for_messages(mistral, websocket, execution))

        self.assertEqual([payload_a, payload_b], messages)

        self.assertFalse(mistral.executions.get.called)
        websocket.wait_for_messages.assert_called_with(timeout=None)

    def test_wait_for_messages_timeout(self):
        mistral = mock.Mock()
        websocket = mock.Mock()
        websocket.wait_for_messages.side_effect = ex.WebSocketTimeout
        execution = mock.Mock()
        execution.id = 1

        messages = base.wait_for_messages(mistral, websocket, execution)

        self.assertRaises(ex.WebSocketTimeout, list, messages)

        self.assertTrue(mistral.executions.get.called)
        websocket.wait_for_messages.assert_called_with(timeout=None)

    def test_wait_for_messages_connection_closed(self):
        mistral = mock.Mock()
        websocket = mock.Mock()
        websocket.wait_for_messages.side_effect = ex.WebSocketConnectionClosed

        execution = mock.Mock()
        execution.id = 1

        messages = base.wait_for_messages(mistral, websocket, execution)

        self.assertRaises(ex.WebSocketConnectionClosed, list, messages)

        self.assertTrue(mistral.executions.get.called)
        websocket.wait_for_messages.assert_called_with(timeout=None)

    def test_wait_for_messages_different_execution(self):
        payload_a = {
            'status': 'RUNNING',
            'execution_id': 'aaaa',
            'root_execution_id': 'aaaa'
        }
        payload_b = {
            'status': 'RUNNING',
            'execution_id': 'bbbb',
            'root_execution_id': 'bbbb'
        }

        mistral = mock.Mock()
        mistral.executions.get.return_value.state = 'RUNNING'
        websocket = mock.Mock()
        websocket.wait_for_messages.return_value = iter([payload_a, payload_b])
        execution = mock.Mock()
        execution.id = 'aaaa'

        messages = list(base.wait_for_messages(mistral, websocket, execution))

        # Assert only payload_a was returned
        self.assertEqual([payload_a], messages)

        websocket.wait_for_messages.assert_called_with(timeout=None)

    def test_backwards_compat_wait_for_messages_success(self):
        payload_a = {
            'status': 'ERROR',
            'execution': {'id': 2,
                          'root_execution_id': 1}
        }
        payload_b = {
            'status': 'ERROR',
            'execution': {'id': 1,
                          'root_execution_id': 1}
        }

        mistral = mock.Mock()
        websocket = mock.Mock()
        websocket.wait_for_messages.return_value = iter([payload_a, payload_b])
        execution = mock.Mock()
        execution.id = 1

        messages = list(base.wait_for_messages(mistral, websocket, execution))

        self.assertEqual([payload_a, payload_b], messages)

        self.assertFalse(mistral.executions.get.called)
        websocket.wait_for_messages.assert_called_with(timeout=None)

    def test_backwards_compatible_call_with_different_execution(self):
        payload_a = {
            'status': 'RUNNING',
            'execution': {'id': 'aaaa',
                          'root_execution_id': 'aaaa'}
        }
        payload_b = {
            'status': 'RUNNING',
            'execution': {'id': 'bbbb',
                          'root_execution_id': 'bbbb'}
        }

        mistral = mock.Mock()
        mistral.executions.get.return_value.state = 'RUNNING'
        websocket = mock.Mock()
        websocket.wait_for_messages.return_value = iter([payload_a, payload_b])
        execution = mock.Mock()
        execution.id = 'aaaa'

        messages = list(base.wait_for_messages(mistral, websocket, execution))

        # Assert only payload_a was returned
        self.assertEqual([payload_a], messages)

        websocket.wait_for_messages.assert_called_with(timeout=None)

    def test_wait_for_messages_execution_complete(self):
        payload_a = {
            'status': 'RUNNING',
            'execution_id': 'aaaa',
            'root_execution_id': 'aaaa'
        }
        payload_b = {
            'status': 'SUCCESS',
            'execution_id': 'aaaa',
            'root_execution_id': 'aaaa'
        }

        mistral = mock.Mock()
        mistral.executions.get.return_value.state = 'SUCCESS'
        mistral.executions.get.return_value.output = json.dumps(payload_b)
        websocket = mock.Mock()
        websocket.wait_for_messages.return_value = iter([payload_a])
        execution = mock.Mock()
        execution.id = 'aaaa'

        messages = list(base.wait_for_messages(mistral, websocket, execution))

        # Assert only payload_b was returned
        self.assertEqual([payload_a, payload_b], messages)
        mistral.executions.get.assert_called_with('aaaa')

        websocket.wait_for_messages.assert_called_with(timeout=None)
