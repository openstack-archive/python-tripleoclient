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
from osc_lib.tests import utils


class FakeClientWrapper(object):

    def __init__(self):
        self._instance = mock.Mock()
        self._mock_websocket = mock.Mock()
        self._mock_websocket.__enter__ = mock.Mock(
            return_value=self._mock_websocket)
        self._mock_websocket.__exit__ = mock.Mock()

    def messaging_websocket(self, queue_name='tripleo'):
        return self._mock_websocket


class TestDeleteNode(utils.TestCommand):

    def setUp(self):
        super(TestDeleteNode, self).setUp()

        self.app.client_manager.auth_ref = mock.Mock(auth_token="TOKEN")
        self.app.client_manager.orchestration = mock.Mock()
        self.app.client_manager.tripleoclient = FakeClientWrapper()


class TestOvercloudNode(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudNode, self).setUp()

        self.app.client_manager.baremetal = mock.Mock()
        self.app.client_manager.workflow_engine = mock.Mock()
        self.app.client_manager.tripleoclient = FakeClientWrapper()

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)
