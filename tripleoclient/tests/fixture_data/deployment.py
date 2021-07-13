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
        self.mock_get_hosts_and_enable_ssh_admin = self.useFixture(
            fixtures.MockPatch('tripleoclient.workflows.deployment.'
                               'get_hosts_and_enable_ssh_admin')
        ).mock
        self.mock_config_download = self.useFixture(fixtures.MockPatch(
            'tripleoclient.workflows.deployment.config_download')
        ).mock
        self.mock_set_deployment_status = self.useFixture(fixtures.MockPatch(
            'tripleoclient.workflows.deployment.set_deployment_status')
        ).mock
        self.mock_create_overcloudrc = self.useFixture(fixtures.MockPatch(
            'tripleoclient.workflows.deployment.create_overcloudrc')
        ).mock
        make_config_download_dir = \
            'tripleoclient.workflows.deployment.make_config_download_dir'
        self.mock_make_config_download_dir = self.useFixture(
            fixtures.MockPatch(make_config_download_dir)
        ).mock


class UtilsOvercloudFixture(fixtures.Fixture):

    def _setUp(self):
        super(UtilsOvercloudFixture, self)._setUp()
        self.mock_deploy_tht = self.useFixture(fixtures.MockPatch(
            'tripleoclient.utils.create_tempest_deployer_input')
        ).mock
        self.mock_utils_endpoint = self.useFixture(fixtures.MockPatch(
            'tripleoclient.utils.get_overcloud_endpoint')
        ).mock
        self.mock_update_deployment_status = self.useFixture(
            fixtures.MockPatch(
                'tripleoclient.utils.update_deployment_status')
        ).mock
        self.mock_get_default_working_dir = self.useFixture(fixtures.MockPatch(
            'tripleoclient.utils.get_default_working_dir')
        ).mock
        self.mock_get_default_working_dir.return_value = \
            self.useFixture(fixtures.TempDir()).path


class UtilsFixture(fixtures.Fixture):

    def _setUp(self):
        super(UtilsFixture, self)._setUp()
        self.wait_for_stack_ready_mock = self.useFixture(fixtures.MockPatch(
            'tripleoclient.utils.wait_for_stack_ready',
            return_value=True)
        ).mock
        self.mock_remove_known_hosts = self.useFixture(fixtures.MockPatch(
            'tripleoclient.utils.remove_known_hosts')
        ).mock
        self.mock_run_ansible_playbook = self.useFixture(fixtures.MockPatch(
            'tripleoclient.utils.run_ansible_playbook')
        ).mock
        self.mock_get_heat_launcher = self.useFixture(fixtures.MockPatch(
            'tripleoclient.utils.get_heat_launcher')
        ).mock
        self.mock_launch_heat = self.useFixture(fixtures.MockPatch(
            'tripleoclient.utils.launch_heat')
        ).mock
        self.mock_kill_heat = self.useFixture(fixtures.MockPatch(
            'tripleoclient.utils.kill_heat')
        ).mock
        self.mock_rm_heat = self.useFixture(fixtures.MockPatch(
            'tripleoclient.utils.rm_heat')
        ).mock
        self.mock_export_overcloud = self.useFixture(fixtures.MockPatch(
            'tripleoclient.export.export_overcloud')
        ).mock
        self.mock_export_overcloud.return_value = {}
