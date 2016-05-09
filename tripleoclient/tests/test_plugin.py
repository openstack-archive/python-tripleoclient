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

from tripleoclient import plugin
from tripleoclient.tests import base
from tripleoclient.tests import fakes


class TestPlugin(base.TestCase):

    @mock.patch("websocket.create_connection")
    def test_make_client(self, ws_create_connection):
        clientmgr = mock.MagicMock()
        clientmgr._api_version.__getitem__.return_value = '1'
        clientmgr.get_endpoint_for_service_type.return_value = fakes.AUTH_URL

        clientmgr.auth.get_token.return_value = "TOKEN"
        clientmgr.identity.projects.get.return_value = mock.MagicMock(id="ID")
        ws_create_connection.return_value.recv.return_value = json.dumps({
            "headers": {
                "status": 200
            }
        })
        client = plugin.make_client(clientmgr)

        websocket = client.messaging_websocket()
        # The second access should return the same client:
        self.assertIs(client.messaging_websocket(), websocket)

        plugin.make_client(clientmgr)

        # And the functions should only be called when the client is created:
        self.assertEqual(clientmgr.auth.get_token.call_count, 1)
        self.assertEqual(clientmgr.get_endpoint_for_service_type.call_count, 1)
        ws_create_connection.assert_called_once_with("ws://0.0.0.0")
