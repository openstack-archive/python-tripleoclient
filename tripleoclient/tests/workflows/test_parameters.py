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
import uuid

from osc_lib.tests import utils

from tripleoclient.workflows import parameters


class TestParameterWorkflows(utils.TestCommand):

    def setUp(self):
        super(TestParameterWorkflows, self).setUp()
        self.app.client_manager.workflow_engine = self.workflow = mock.Mock()
        self.tripleoclient = mock.Mock()
        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    def test_get_overcloud_passwords(self):
        self.websocket.wait_for_messages.return_value = iter([{
            "execution": {"id": "IDID"},
            "status": "SUCCESS",
            "message": "passwords",
        }])

        parameters.get_overcloud_passwords(
            self.app.client_manager,
            container='container-name',
            queue_name=str(uuid.uuid4()))

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.get_passwords',
            workflow_input={'queue_name': 'UUID4',
                            'container': 'container-name'})
