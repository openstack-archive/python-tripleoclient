#   Copyright 2016 Red Hat, Inc.
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

from tripleoclient.tests.v1.overcloud_deploy import fakes
from tripleoclient.v1 import overcloud_delete


class TestDeleteOvercloud(fakes.TestDeployOvercloud):

    def setUp(self):
        super(TestDeleteOvercloud, self).setUp()

        self.cmd = overcloud_delete.DeleteOvercloud(self.app, None)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine

    @mock.patch(
        'tripleoclient.workflows.stack_management.plan_undeploy',
        autospec=True)
    def test_plan_undeploy(self, mock_plan_undeploy):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration

        stack = mock.Mock()
        stack.id = 12345
        stack.stack_name = "foobar"
        orchestration_client.stacks.get.return_value = stack

        self.cmd._plan_undeploy(clients, 'overcloud')

        orchestration_client.stacks.get.assert_called_once_with('overcloud')
        mock_plan_undeploy.assert_called_once_with(
            clients, plan="foobar")

    @mock.patch(
        'tripleoclient.workflows.stack_management.base.start_workflow',
        autospec=True)
    def test_plan_undeploy_wf_params(self, mock_plan_undeploy_wf):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        workflow_engine = clients.workflow_engine

        stack = mock.Mock()
        stack.id = 12345
        stack.stack_name = "foobar"
        orchestration_client.stacks.get.return_value = stack

        self.cmd._plan_undeploy(clients, 'overcloud')

        orchestration_client.stacks.get.assert_called_once_with('overcloud')
        mock_plan_undeploy_wf.assert_called_once_with(
            workflow_engine,
            "tripleo.deployment.v1.undeploy_plan",
            workflow_input={"container": "foobar"})

    def test_plan_undeploy_no_stack(self):
        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        type(orchestration_client.stacks.get).return_value = None
        self.cmd.log.warning = mock.MagicMock()

        self.cmd._plan_undeploy(clients, 'overcloud')

        orchestration_client.stacks.get.assert_called_once_with('overcloud')
        self.cmd.log.warning.assert_called_once_with(
            "No stack found ('overcloud'), skipping delete")

    @mock.patch(
        'tripleoclient.workflows.plan_management.delete_deployment_plan',
        autospec=True)
    def test_plan_delete(self, delete_deployment_plan_mock):
        self.cmd._plan_delete(self.workflow, 'overcloud')

        delete_deployment_plan_mock.assert_called_once_with(
            self.workflow,
            container='overcloud')

    @mock.patch('os.path.exists')
    def test_cleanup_ipa_without_tripleo_ipa_installed_succeeds(self, os_mock):
        # Make sure we log a warning and short-circuit the _cleanup_ipa()
        # method if the playbook isn't installed on the system.
        os_mock.return_value = False
        self.cmd.log.debug = mock.MagicMock()

        self.cmd._cleanup_ipa('overcloud')
        self.cmd.log.debug.assert_called_once_with(
            "/usr/share/ansible/tripleo-playbooks/cli-cleanup-ipa.yml "
            "doesn't exist on system. Ignoring IPA cleanup."
        )

    @mock.patch('shutil.rmtree')
    @mock.patch('os.path.exists')
    @mock.patch('tripleoclient.utils.get_tripleo_ansible_inventory')
    @mock.patch('tripleoclient.utils.cleanup_tripleo_ansible_inventory_file')
    @mock.patch('tripleoclient.utils.run_ansible_playbook')
    @mock.patch('tripleo_common.actions.ansible.write_default_ansible_cfg')
    def test_cleanup_ipa_cleans_up_after_failure(
            self, ansible_mock, pb_mock, inv_mock, clean_inv_mock, os_mock,
            shutil_mock):
        os_mock.return_value = True
        pb_mock.return_value = (1, 'fake output')
        inv_mock.return_value = 'fake inventory'
        ansible_mock.return_value = 'fake config'

        self.cmd.log.debug = mock.MagicMock()
        self.cmd.log.warning = mock.MagicMock()

        self.cmd._cleanup_ipa('overcloud')

        self.cmd.log.debug.assert_any_call(
            "Removing static tripleo ansible inventory file"
        )
        self.cmd.log.debug.assert_any_call(
            "Removing temporary ansible configuration directory"
        )
        self.cmd.log.warning.assert_any_call(
            "/usr/share/ansible/tripleo-playbooks/cli-cleanup-ipa.yml "
            "did not complete successfully."
        )
