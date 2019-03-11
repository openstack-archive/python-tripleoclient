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

import ironic_inspector_client
from osc_lib.tests import utils


class FakeInspectorClient(object):
    def __init__(self, states=None, data=None):
        self.states = states or {}
        self.data = data or {}
        self.on_introspection = []

    def introspect(self, uuid):
        self.on_introspection.append(uuid)

    def get_status(self, uuid):
        try:
            return self.states[uuid]
        except KeyError:
            raise ironic_inspector_client.ClientError(mock.Mock())

    def get_data(self, uuid):
        try:
            return self.data[uuid]
        except KeyError:
            raise ironic_inspector_client.ClientError(mock.Mock())

    def wait_for_finish(self, uuids):
        return {uuid: self.states[uuid] for uuid in uuids}


class ClientWrapper(object):

    def __init__(self):
        self._instance = None
        self._mock_websocket = mock.Mock()
        self._mock_websocket.__enter__ = mock.Mock(
            return_value=self._mock_websocket)
        # Return False to avoid silencing exceptions
        self._mock_websocket.__exit__ = mock.Mock(return_value=False)

    def messaging_websocket(self):
        return self._mock_websocket


class TestBaremetal(utils.TestCommand):

    def setUp(self):
        super(TestBaremetal, self).setUp()

        self.app.client_manager.auth_ref = mock.Mock(auth_token="TOKEN")
        self.app.client_manager.baremetal = mock.Mock()
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.baremetal_introspection = FakeInspectorClient()
        self.app.client_manager._region_name = "Arcadia"
        self.app.client_manager.session = mock.Mock()
        self.app.client_manager.workflow_engine = mock.Mock()
        self.app.client_manager.tripleoclient = ClientWrapper()

    def tearDown(self):
        super(TestBaremetal, self).tearDown()

        mock.patch.stopall()
