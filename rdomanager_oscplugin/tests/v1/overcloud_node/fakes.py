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
from openstackclient.tests import utils


class FakeClientWrapper(object):

    def __init__(self):
        self._instance = mock.Mock()
        self._orchestration = None
        self._management = None

    def orchestration(self):

        if self._orchestration is None:
            self._orchestration = mock.Mock()

        return self._orchestration

    def management(self):

        if self._management is None:
            self._management = mock.Mock()

        return self._management


class TestDeleteNode(utils.TestCommand):

    def setUp(self):
        super(TestDeleteNode, self).setUp()

        self.app.client_manager.auth_ref = mock.Mock(auth_token="TOKEN")
        self.app.client_manager.rdomanager_oscplugin = FakeClientWrapper()
