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

from unittest import mock

from tripleoclient import plugin
from tripleoclient.tests import base
from tripleoclient.tests import fakes


class TestPlugin(base.TestCase):

    def test_make_client(self):
        clientmgr = mock.MagicMock()
        clientmgr.get_endpoint_for_service_type.return_value = fakes.WS_URL

        clientmgr.auth.get_token.return_value = "TOKEN"
        clientmgr.auth_ref.project_id = "ID"
        clientmgr.cacert = None

        plugin.make_client(clientmgr)

        # And the functions should only be called when the client is created:
        self.assertEqual(clientmgr.auth.get_token.call_count, 0)
        self.assertEqual(clientmgr.get_endpoint_for_service_type.call_count, 0)
