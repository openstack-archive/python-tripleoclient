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


def create_to_dict_mock(**kwargs):
    mock_plan = mock.Mock()
    mock_plan.configure_mock(**kwargs)
    mock_plan.to_dict.return_value = kwargs
    return mock_plan


class FakeClientWrapper(object):

    def __init__(self):
        self._instance = mock.Mock()
        self._orchestration = mock.Mock()
        self._baremetal = mock.Mock()
        self._management = mock.Mock()

    def orchestration(self):
        return self._orchestration

    def baremetal(self):
        return self._baremetal

    def management(self):
        return self._management


class TestDeployOvercloud(utils.TestCommand):

    def setUp(self):
        super(TestDeployOvercloud, self).setUp()

        self.app.client_manager.auth_ref = mock.Mock(auth_token="TOKEN")
        self.app.client_manager.rdomanager_oscplugin = FakeClientWrapper()
        self.app.client_manager.network = mock.Mock()
        self.app.client_manager.compute = mock.Mock()
        self.app.client_manager.identity = mock.Mock()
