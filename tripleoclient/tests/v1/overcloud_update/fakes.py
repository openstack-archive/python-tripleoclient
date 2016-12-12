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

from tripleoclient.tests import fakes


class FakeClientWrapper(object):

    def __init__(self):
        self._instance = mock.Mock()
        self.object_store = FakeObjectClient()

    def messaging_websocket(self, queue_name="tripleo"):
        return fakes.FakeWebSocket()


class FakeObjectClient(object):

    def __init__(self):
        self._instance = mock.Mock()
        self.put_object = mock.Mock()

    def get_object(self, *args):
        return


class TestOvercloudUpdate(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudUpdate, self).setUp()

        self.app.client_manager.auth_ref = mock.Mock(auth_token="TOKEN")
        self.app.client_manager.orchestration = mock.Mock()
        self.app.client_manager.tripleoclient = FakeClientWrapper()
        self.app.client_manager.workflow_engine = mock.Mock()
