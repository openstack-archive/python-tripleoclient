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

import os
import shutil
import tempfile
from unittest import mock


from osc_lib.tests import utils

from tripleoclient.tests.fakes import FakeStackObject
from tripleoclient.workflows import deployment


class TestDeploymentWorkflows(utils.TestCommand):

    def setUp(self):
        super(TestDeploymentWorkflows, self).setUp()
        self.tripleoclient = mock.Mock()
        self.orig_workdir = deployment.DEFAULT_WORK_DIR
        deployment.DEFAULT_WORK_DIR = tempfile.mkdtemp()

    def tearDown(self):
        super(TestDeploymentWorkflows, self).tearDown()
        shutil.rmtree(deployment.DEFAULT_WORK_DIR)
        deployment.DEFAULT_WORK_DIR = self.orig_workdir

    @mock.patch('os.path.join')
    @mock.patch('shutil.rmtree')
    @mock.patch('os.chdir')
    @mock.patch('tripleoclient.utils.tempfile')
    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_enable_ssh_admin(self, mock_playbook, mock_tempfile,
                              mock_chdir, mock_rmtree, mock_join):
        hosts = 'a', 'b', 'c'
        ssh_user = 'test-user'
        ssh_key = 'test-key'
        timeout = 30

        deployment.enable_ssh_admin(
            FakeStackObject,
            hosts,
            ssh_user,
            ssh_key,
            timeout,
            mock.Mock()
        )

        # once for ssh-keygen, then twice per host
        self.assertEqual(1, mock_playbook.call_count)

    @mock.patch('tripleoclient.utils.get_excluded_ip_addresses')
    @mock.patch('tripleoclient.utils.get_role_net_ip_map')
    def test_get_overcloud_hosts(self, mock_role_net_ip_map,
                                 mock_excluded_ip_addresses):
        stack = mock.Mock()
        working_dir = mock.Mock()
        # empty string added to Compute ctlplane to test LP 1990566 fix
        mock_role_net_ip_map.return_value = {
            'Controller': {
                'ctlplane': ['1.1.1.1', '2.2.2.2', '3.3.3.3'],
                'external': ['4.4.4.4', '5.5.5.5', '6.6.6.6']},
            'Compute': {
                'ctlplane': ['7.7.7.7', '', '8.8.8.8', '9.9.9.9'],
                'external': ['10.10.10.10', '11.11.11.11', '12.12.12.12']},
        }
        mock_excluded_ip_addresses.return_value = []

        ips = deployment.get_overcloud_hosts(stack, 'ctlplane', working_dir)
        expected = ['1.1.1.1', '2.2.2.2', '3.3.3.3',
                    '7.7.7.7', '8.8.8.8', '9.9.9.9']
        self.assertEqual(sorted(expected), sorted(ips))

        ips = deployment.get_overcloud_hosts(stack, 'external', working_dir)
        expected = ['4.4.4.4', '5.5.5.5', '6.6.6.6',
                    '10.10.10.10', '11.11.11.11', '12.12.12.12']
        self.assertEqual(sorted(expected), sorted(ips))

    @mock.patch('tripleoclient.utils.get_excluded_ip_addresses')
    @mock.patch('tripleoclient.utils.get_role_net_ip_map')
    def test_get_overcloud_hosts_with_exclude(
            self, mock_role_net_ip_map,
            mock_excluded_ip_addresses):
        stack = mock.Mock()
        working_dir = mock.Mock()
        stack.output_show.return_value = []
        mock_role_net_ip_map.return_value = {
            'Controller': {
                'ctlplane': ['1.1.1.1', '2.2.2.2', '3.3.3.3'],
                'external': ['4.4.4.4', '5.5.5.5', '6.6.6.6']},
            'Compute': {
                'ctlplane': ['7.7.7.7', '8.8.8.8', '9.9.9.9'],
                'external': ['10.10.10.10', '11.11.11.11', '12.12.12.12']},
        }

        mock_excluded_ip_addresses.return_value = ['8.8.8.8']
        ips = deployment.get_overcloud_hosts(stack, 'ctlplane', working_dir)
        expected = ['1.1.1.1', '2.2.2.2', '3.3.3.3',
                    '7.7.7.7', '9.9.9.9']
        self.assertEqual(sorted(expected), sorted(ips))

        ips = deployment.get_overcloud_hosts(stack, 'external', working_dir)
        expected = ['4.4.4.4', '5.5.5.5', '6.6.6.6',
                    '10.10.10.10', '12.12.12.12']
        self.assertEqual(sorted(expected), sorted(ips))

        mock_excluded_ip_addresses.return_value = ['7.7.7.7', '9.9.9.9',
                                                   '2.2.2.2']
        ips = deployment.get_overcloud_hosts(stack, 'external', working_dir)
        expected = ['4.4.4.4', '6.6.6.6', '11.11.11.11']
        self.assertEqual(sorted(expected), sorted(ips))

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_config_download_already_in_progress_for_diff_stack(
            self, mock_playbook):
        log = mock.Mock()
        stack = mock.Mock()
        stack.stack_name = 'stacktest'
        stack.output_show.return_value = {'output': {'output_value': []}}
        clients = mock.Mock()
        deployment.config_download(
            log, clients, 'stacktest', 'templates', 'ssh_user',
            'ssh_key', 'ssh_networks', 'output_dir', False,
            'timeout')

        self.assertEqual(2, mock_playbook.call_count)

    def test_config_download_dirs(self):
        stack = 'teststack'
        old_cd_dir = os.path.join(
            deployment.DEFAULT_WORK_DIR, stack)

        with tempfile.TemporaryDirectory() as new:
            deployment.make_config_download_dir(new, 'teststack')
            # Verify the old config-download dir is a symlink
            self.assertTrue(os.path.islink(old_cd_dir))
            # Verify old config-download dir symlink points to new dir
            self.assertEqual(os.path.join(os.path.realpath(new), stack),
                             os.path.realpath(old_cd_dir))

    def test_config_download_migrate_dirs(self):
        stack = 'teststack'
        old_cd_dir = os.path.join(
            deployment.DEFAULT_WORK_DIR, stack)

        with tempfile.TemporaryDirectory() as new:
            os.makedirs(old_cd_dir)
            with open(os.path.join(old_cd_dir, 'testfile'), 'w') as old_file:
                old_file.write('foo')

            deployment.make_config_download_dir(new, stack)
            # Verify the old cd dir was copied to the new dir
            self.assertTrue(os.path.exists(
                os.path.join(new, stack, old_file.name)))
            # Verify the old config-download dir is a symlink
            self.assertTrue(os.path.islink(old_cd_dir))
            # Verify old config-download dir symlink points to new dir
            self.assertEqual(os.path.join(os.path.realpath(new), stack),
                             os.path.realpath(old_cd_dir))

    def test_config_download_no_migrate_dirs(self):
        stack = 'teststack'
        old_cd_dir = os.path.join(
            deployment.DEFAULT_WORK_DIR, stack)

        with tempfile.TemporaryDirectory() as new:
            new_cd_dir = os.path.join(new, stack)
            os.makedirs(new_cd_dir)
            os.makedirs(old_cd_dir)
            with open(os.path.join(old_cd_dir, 'testfile'), 'w') as old_file:
                old_file.write('foo')

            deployment.make_config_download_dir(new, stack)
            # Verify the old cd dir was not copied to the new dir as it already
            # exists
            self.assertFalse(os.path.exists(
                os.path.join(new, stack, old_file.name)))
            # Verify the old config-download dir is a symlink
            self.assertTrue(os.path.islink(old_cd_dir))
            # Verify old config-download dir symlink points to new dir
            self.assertEqual(os.path.join(os.path.realpath(new), stack),
                             os.path.realpath(old_cd_dir))
