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

from tripleoclient.tests import fakes
from tripleoclient.workflows import baremetal


class TestBaremetalWorkflows(fakes.FakePlaybookExecution):

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

        self.mock_playbook = mock.patch(
            'tripleoclient.utils.run_ansible_playbook',
            autospec=True
        )
        self.mock_playbook.start()
        self.addCleanup(self.mock_playbook.stop)

    def test_register_or_update_success(self):
        self.assertEqual(baremetal.register_or_update(
            self.app.client_manager,
            nodes_json=[],
            instance_boot_option='local'
        ), [mock.ANY])

    def test_provide_success(self):
        baremetal.provide(self.app.client_manager, node_uuids=[])

    def test_format_errors(self):
        payload = {'message': [{'result': 'Error1a\nError1b'},
                               {'result': 'Error2a\nError2b\n'}]}

        error_string = baremetal._format_errors(payload)
        self.assertEqual(error_string, "Error1b\nError2b")

    def test_introspect_success(self):
        baremetal.introspect(self.app.client_manager, node_uuids=[],
                             run_validations=True, concurrency=20,
                             node_timeout=1200, max_retries=1,
                             retry_timeout=120)

    def test_introspect_manageable_nodes_success(self):
        baremetal.introspect_manageable_nodes(
            self.app.client_manager, run_validations=False, concurrency=20,
            node_timeout=1200, max_retries=1, retry_timeout=120,
        )

    def test_provide_manageable_nodes_success(self):
        baremetal.provide_manageable_nodes(
            self.app.client_manager
        )

    def test_configure_success(self):
        baremetal.configure(self.app.client_manager, node_uuids=[])

    def test_configure_manageable_nodes_success(self):
        baremetal.configure_manageable_nodes(self.app.client_manager)

    def test_clean_nodes_success(self):
        baremetal.clean_nodes(node_uuids=[])

    def test_clean_manageable_nodes_success(self):
        baremetal.clean_manageable_nodes(
            self.app.client_manager
        )
