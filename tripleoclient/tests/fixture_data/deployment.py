#   Copyright 2018 Red Hat, Inc.
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

import fixtures


class DeploymentWorkflowFixture(fixtures.Fixture):

    def _setUp(self):
        super(DeploymentWorkflowFixture, self)._setUp()
        self.mock_get_overcloud_hosts = self.useFixture(fixtures.MockPatch(
            'tripleoclient.workflows.deployment.get_overcloud_hosts')
        ).mock
        self.mock_enable_ssh_admin = self.useFixture(fixtures.MockPatch(
            'tripleoclient.workflows.deployment.enable_ssh_admin')
        ).mock
        self.mock_config_download = self.useFixture(fixtures.MockPatch(
            'tripleoclient.workflows.deployment.config_download')
        ).mock
        self.mock_get_horizon_url = self.useFixture(fixtures.MockPatch(
            'tripleoclient.workflows.deployment.get_horizon_url')
        ).mock
