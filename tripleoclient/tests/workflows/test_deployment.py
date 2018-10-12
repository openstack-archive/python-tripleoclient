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

import mock

from osc_lib.tests import utils

from tripleoclient import exceptions
from tripleoclient.workflows import deployment


class TestDeploymentWorkflows(utils.TestCommand):

    def setUp(self):
        super(TestDeploymentWorkflows, self).setUp()

        self.app.client_manager.workflow_engine = self.workflow = mock.Mock()
        self.tripleoclient = mock.Mock()
        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient

        self.message_success = iter([{
            "execution": {"id": "IDID"},
            "status": "SUCCESS",
            "message": "Success.",
            "registered_nodes": [],
        }])
        self.message_failed = iter([{
            "execution": {"id": "IDID"},
            "status": "FAIL",
            "message": "Fail.",
        }])

    @mock.patch('tripleoclient.workflows.deployment.wait_for_ssh_port')
    @mock.patch('tripleoclient.workflows.deployment.time.sleep')
    @mock.patch('tripleoclient.workflows.deployment.shutil.rmtree')
    @mock.patch('tripleoclient.workflows.deployment.open')
    @mock.patch('tripleoclient.workflows.deployment.tempfile')
    @mock.patch('tripleoclient.workflows.deployment.subprocess.check_call')
    def test_enable_ssh_admin(self, mock_check_call, mock_tempfile,
                              mock_open, mock_rmtree, mock_sleep,
                              mock_wait_for_ssh_port):
        log = mock.Mock()
        hosts = 'a', 'b', 'c'
        ssh_user = 'test-user'
        ssh_key = 'test-key'

        mock_tempfile.mkdtemp.return_value = '/foo'
        mock_read = mock.Mock()
        mock_read.read.return_value = 'key'
        mock_open.return_value = mock_read
        mock_state = mock.Mock()
        mock_state.state = 'SUCCESS'
        self.workflow.executions.get.return_value = mock_state
        deployment.enable_ssh_admin(log, self.app.client_manager,
                                    'overcloud', hosts, ssh_user, ssh_key)

        # once for ssh-keygen, then twice per host
        self.assertEqual(7, mock_check_call.call_count)

        # execution ran
        self.assertEqual(1, self.workflow.executions.create.call_count)
        call_args = self.workflow.executions.create.call_args
        self.assertEqual('tripleo.access.v1.enable_ssh_admin', call_args[0][0])
        self.assertEqual(('a', 'b', 'c'),
                         call_args[1]['workflow_input']['ssh_servers'])
        self.assertEqual('test-user',
                         call_args[1]['workflow_input']['ssh_user'])
        self.assertEqual('key',
                         call_args[1]['workflow_input']['ssh_private_key'])

        # tmpdir should be cleaned up
        self.assertEqual(1, mock_rmtree.call_count)
        self.assertEqual('/foo', mock_rmtree.call_args[0][0])

    @mock.patch('tripleoclient.workflows.deployment.wait_for_ssh_port')
    @mock.patch('tripleoclient.workflows.deployment.time.sleep')
    @mock.patch('tripleoclient.workflows.deployment.shutil.rmtree')
    @mock.patch('tripleoclient.workflows.deployment.open')
    @mock.patch('tripleoclient.workflows.deployment.tempfile')
    @mock.patch('tripleoclient.workflows.deployment.subprocess.check_call')
    def test_enable_ssh_admin_error(self, mock_check_call, mock_tempfile,
                                    mock_open, mock_rmtree, mock_sleep,
                                    mock_wait_for_ssh_port):
        log = mock.Mock()
        hosts = 'a', 'b', 'c'
        ssh_user = 'test-user'
        ssh_key = 'test-key'

        mock_tempfile.mkdtemp.return_value = '/foo'
        mock_read = mock.Mock()
        mock_read.read.return_value = 'key'
        mock_open.return_value = mock_read
        mock_state = mock.Mock()
        mock_state.state = 'ERROR'
        mock_state.to_dict.return_value = dict(state_info='an error')
        self.workflow.executions.get.return_value = mock_state
        self.assertRaises(exceptions.DeploymentError,
                          deployment.enable_ssh_admin,
                          log, self.app.client_manager,
                          'overcloud',
                          hosts, ssh_user, ssh_key)

    @mock.patch('tripleoclient.utils.get_blacklisted_ip_addresses')
    @mock.patch('tripleoclient.utils.get_role_net_ip_map')
    def test_get_overcloud_hosts(self, mock_role_net_ip_map,
                                 mock_blacklisted_ip_addresses):
        stack = mock.Mock()
        mock_role_net_ip_map.return_value = {
            'Controller': {
                'ctlplane': ['1.1.1.1', '2.2.2.2', '3.3.3.3'],
                'external': ['4.4.4.4', '5.5.5.5', '6.6.6.6']},
            'Compute': {
                'ctlplane': ['7.7.7.7', '8.8.8.8', '9.9.9.9'],
                'external': ['10.10.10.10', '11.11.11.11', '12.12.12.12']},
        }
        mock_blacklisted_ip_addresses.return_value = []

        ips = deployment.get_overcloud_hosts(stack, 'ctlplane')
        expected = ['1.1.1.1', '2.2.2.2', '3.3.3.3',
                    '7.7.7.7', '8.8.8.8', '9.9.9.9']
        self.assertEqual(sorted(expected), sorted(ips))

        ips = deployment.get_overcloud_hosts(stack, 'external')
        expected = ['4.4.4.4', '5.5.5.5', '6.6.6.6',
                    '10.10.10.10', '11.11.11.11', '12.12.12.12']
        self.assertEqual(sorted(expected), sorted(ips))

    @mock.patch('tripleoclient.utils.get_blacklisted_ip_addresses')
    @mock.patch('tripleoclient.utils.get_role_net_ip_map')
    def test_get_overcloud_hosts_with_blacklist(
            self, mock_role_net_ip_map,
            mock_blacklisted_ip_addresses):
        stack = mock.Mock()
        mock_role_net_ip_map.return_value = {
            'Controller': {
                'ctlplane': ['1.1.1.1', '2.2.2.2', '3.3.3.3'],
                'external': ['4.4.4.4', '5.5.5.5', '6.6.6.6']},
            'Compute': {
                'ctlplane': ['7.7.7.7', '8.8.8.8', '9.9.9.9'],
                'external': ['10.10.10.10', '11.11.11.11', '12.12.12.12']},
        }

        mock_blacklisted_ip_addresses.return_value = ['8.8.8.8']
        ips = deployment.get_overcloud_hosts(stack, 'ctlplane')
        expected = ['1.1.1.1', '2.2.2.2', '3.3.3.3',
                    '7.7.7.7', '9.9.9.9']
        self.assertEqual(sorted(expected), sorted(ips))

        ips = deployment.get_overcloud_hosts(stack, 'external')
        expected = ['4.4.4.4', '5.5.5.5', '6.6.6.6',
                    '10.10.10.10', '12.12.12.12']
        self.assertEqual(sorted(expected), sorted(ips))

        mock_blacklisted_ip_addresses.return_value = ['7.7.7.7', '9.9.9.9',
                                                      '2.2.2.2']
        ips = deployment.get_overcloud_hosts(stack, 'external')
        expected = ['4.4.4.4', '6.6.6.6', '11.11.11.11']
        self.assertEqual(sorted(expected), sorted(ips))
