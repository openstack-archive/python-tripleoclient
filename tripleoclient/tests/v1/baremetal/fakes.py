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


class FakeBaremetalNodeClient(object):
    def __init__(self, states={}, transitions={}, transition_errors={}):
        """Create a new test double for the "baremetal node" command.

        :param states: dictionary of nodes' initial states. Keys are uuids and
                       values are states, eg {"ABC: "available"}.
        :param transitions: dictionary of expected state transitions.
                            Keys are (uuid, transition) pairs, and values are
                            the states nodes end up in after that transition,
                            eg {("ABC", "manage"): "manageable"}.
                            Updates which occur are stored in "updates" for
                            later inspection.
        :param transition_errors: dict of errors caused by state transitions.
                                  Keys are (uuid, transition) pairs, and values
                                  are the value of node.last_error after that
                                  transition,
                                  eg {("ABC", "manage"): "Node on fire."}.
        """
        self.states = states
        self.transitions = transitions
        self.transition_errors = transition_errors
        self.last_errors = {}
        self.updates = []  # inspect this to see which transitions occurred

    def set_provision_state(self, node_uuid, transition):
        key = (node_uuid, transition)
        new_state = self.transitions[key]
        self.states[node_uuid] = new_state
        self.last_errors[node_uuid] = self.transition_errors.get(key, None)
        self.updates.append(key)

    def _get(self, uuid, detail=False, **kwargs):
        mock_node = mock.Mock(uuid=uuid, provision_state=self.states[uuid])
        if detail:
            mock_node.last_error = self.last_errors.get(uuid, None)
        else:
            mock_node.mock_add_spec(
                ('instance_uuid', 'maintenance', 'power_state',
                 'provision_state', 'uuid', 'name'),
                spec_set=True)
        return mock_node

    def get(self, uuid):
        return self._get(uuid, detail=True)

    def list(self, *args, **kwargs):
        return [self._get(uuid, **kwargs)
                for uuid in (sorted(self.states.keys()))]


class FakeInspectorClient(object):
    def __init__(self, states=None, data=None):
        self.states = states or {}
        self.data = data or {}
        self.on_introspection = []

    def introspect(self, uuid):
        self.on_introspection.append(uuid)

    def get_status(self, uuid):
        return self.states[uuid]

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
        self._mock_websocket.__exit__ = mock.Mock()

    def messaging_websocket(self, queue_name='tripleo'):
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
