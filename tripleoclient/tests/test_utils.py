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


import ansible_runner
import argparse
import datetime
import fixtures
import logging
import openstack
import os
import os.path
import shutil
import socket
import subprocess
import tempfile
from unittest import mock

import sys

from heatclient import exc as hc_exc

from uuid import uuid4

from testscenarios import TestWithScenarios
from unittest import TestCase
import yaml

from tripleoclient import exceptions
from tripleoclient import utils

from tripleoclient.tests import base
from tripleoclient.tests import fakes

from configparser import ConfigParser
from urllib import error as url_error

from ansible_runner import Runner


class TestRunAnsiblePlaybook(TestCase):
    def setUp(self):
        self.unlink_patch = mock.patch('os.unlink')
        self.addCleanup(self.unlink_patch.stop)
        self.unlink_patch.start()
        self.mock_log = mock.Mock('logging.getLogger')
        self.ansible_playbook_cmd = "ansible-playbook"
        self.orig_workdir = utils.constants.DEFAULT_WORK_DIR
        utils.constants.DEFAULT_WORK_DIR = utils.TempDirs().dir
        utils.makedirs(
            os.path.join(
                utils.constants.DEFAULT_WORK_DIR,
                'overcloud'
            )
        )
        ansible_runner.Runner.stdout = mock.MagicMock()
        ansible_runner.Runner.stdout.read = mock.MagicMock(return_value='')

    def tearDown(self):
        utils.constants.DEFAULT_WORK_DIR = self.orig_workdir

    @mock.patch('os.makedirs')
    @mock.patch('os.path.exists', return_value=False)
    @mock.patch('tripleoclient.utils.run_command_and_log')
    @mock.patch('ansible_runner.utils.dump_artifact', autospec=True,
                return_value="/foo/inventory.yaml")
    def test_no_playbook(self, mock_dump_artifact, mock_run, mock_exists,
                         mock_mkdir):
        self.assertRaises(
            RuntimeError,
            utils.run_ansible_playbook,
            'non-existing.yaml',
            'localhost,',
            utils.constants.DEFAULT_WORK_DIR
        )
        mock_exists.assert_called_with(os.path.join(
            utils.constants.DEFAULT_WORK_DIR, 'non-existing.yaml'))
        mock_run.assert_not_called()

    @mock.patch('tempfile.mkstemp', return_value=('foo', os.path.join(
        utils.constants.DEFAULT_WORK_DIR, 'fooBar.cfg')))
    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('os.makedirs')
    @mock.patch.object(
        Runner,
        'run',
        return_value=fakes.fake_ansible_runner_run_return(rc=1)
    )
    @mock.patch('ansible_runner.utils.dump_artifact', autospec=True,
                return_value="/foo/inventory.yaml")
    def test_subprocess_error(self, mock_dump_artifact,
                              mock_run, mock_mkdirs, mock_exists,
                              mock_mkstemp):
        with self.assertRaises(RuntimeError):
            utils.run_ansible_playbook(
                'existing.yaml',
                'localhost,',
                utils.constants.DEFAULT_WORK_DIR
            )

    @mock.patch('tempfile.mkstemp', return_value=('foo', os.path.join(
        utils.constants.DEFAULT_WORK_DIR, 'fooBar.cfg')))
    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('os.makedirs')
    @mock.patch.object(
        Runner,
        'run',
        return_value=fakes.fake_ansible_runner_run_return()
    )
    @mock.patch('ansible_runner.utils.dump_artifact', autospec=True,
                return_value="/foo/inventory.yaml")
    def test_run_success_default(self, mock_dump_artifact, mock_run,
                                 mock_mkdirs, mock_exists, mock_mkstemp):
        utils.run_ansible_playbook(
            playbook='existing.yaml',
            inventory='localhost,',
            workdir=utils.constants.DEFAULT_WORK_DIR
        )

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('os.makedirs')
    @mock.patch.object(
        Runner,
        'run',
        return_value=fakes.fake_ansible_runner_run_return()
    )
    @mock.patch('ansible_runner.utils.dump_artifact', autospec=True,
                return_value="/foo/inventory.yaml")
    def test_run_success_ansible_cfg(self, mock_dump_artifact, mock_run,
                                     mock_mkdirs, mock_exists):
        utils.run_ansible_playbook(
            playbook='existing.yaml',
            inventory='localhost,',
            workdir=utils.constants.DEFAULT_WORK_DIR
        )

    @mock.patch('tempfile.mkstemp', return_value=('foo', os.path.join(
        utils.constants.DEFAULT_WORK_DIR, 'fooBar.cfg')))
    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('os.makedirs')
    @mock.patch.object(
        Runner,
        'run',
        return_value=fakes.fake_ansible_runner_run_return()
    )
    @mock.patch('ansible_runner.utils.dump_artifact', autospec=True,
                return_value="/foo/inventory.yaml")
    def test_run_success_connection_local(self, mock_dump_artifact, mock_run,
                                          mock_mkdirs, mock_exists,
                                          mock_mkstemp):
        utils.run_ansible_playbook(
            playbook='existing.yaml',
            inventory='localhost,',
            workdir=utils.constants.DEFAULT_WORK_DIR,
            connection='local'
        )

    @mock.patch('os.makedirs', return_value=None)
    @mock.patch('tempfile.mkstemp', return_value=('foo', os.path.join(
        utils.constants.DEFAULT_WORK_DIR, 'fooBar.cfg')))
    @mock.patch('os.path.exists', return_value=True)
    @mock.patch.object(
        Runner,
        'run',
        return_value=fakes.fake_ansible_runner_run_return()
    )
    @mock.patch('ansible_runner.utils.dump_artifact', autospec=True,
                return_value="/foo/inventory.yaml")
    def test_run_success_gathering_policy(self, mock_dump_artifact, mock_run,
                                          mock_exists, mock_mkstemp,
                                          mock_makedirs):
        utils.run_ansible_playbook(
            playbook='existing.yaml',
            inventory='localhost,',
            workdir=utils.constants.DEFAULT_WORK_DIR,
            connection='local',
            gathering_policy='smart'
        )

    @mock.patch('os.makedirs', return_value=None)
    @mock.patch('tempfile.mkstemp', return_value=('foo', os.path.join(
        utils.constants.DEFAULT_WORK_DIR, 'fooBar.cfg')))
    @mock.patch('os.path.exists', return_value=True)
    @mock.patch.object(
        Runner,
        'run',
        return_value=fakes.fake_ansible_runner_run_return()
    )
    @mock.patch('ansible_runner.utils.dump_artifact', autospec=True,
                return_value="/foo/inventory.yaml")
    def test_run_success_extra_vars(self, mock_dump_artifact, mock_run,
                                    mock_exists, mock_mkstemp, mock_makedirs):
        arglist = {
            'var_one': 'val_one',
        }
        utils.run_ansible_playbook(
            playbook='existing.yaml',
            inventory='localhost,',
            workdir=utils.constants.DEFAULT_WORK_DIR,
            connection='local',
            gathering_policy='smart',
            extra_vars=arglist
        )

    @mock.patch('os.chmod')
    @mock.patch('builtins.open')
    @mock.patch('tripleoclient.utils.makedirs')
    @mock.patch('os.path.exists', side_effect=(False, True, True))
    def test_run_with_timeout(self, mock_exists, mock_mkdir, mock_open,
                              mock_chmod):
        ansible_runner.ArtifactLoader = mock.MagicMock()
        ansible_runner.Runner.run = mock.MagicMock(return_value=('', 0))
        ansible_runner.runner_config = mock.MagicMock()
        utils.run_ansible_playbook(
            playbook='existing.yaml',
            inventory='localhost,',
            workdir=utils.constants.DEFAULT_WORK_DIR,
            timeout=42
        )
        self.assertIn(mock.call(os.path.join(utils.constants.DEFAULT_WORK_DIR,
                                             'env/settings'), 'w'),
                      mock_open.mock_calls)
        self.assertIn(
            mock.call().__enter__().write('job_timeout: 2520\n'),  # 42m * 60
            mock_open.mock_calls)

    @mock.patch('os.chmod')
    @mock.patch('builtins.open')
    @mock.patch('tripleoclient.utils.makedirs')
    @mock.patch('os.path.exists', side_effect=(False, True, True))
    def test_run_with_extravar_file(self, mock_exists, mock_mkdir, mock_open,
                                    mock_chmod):
        ansible_runner.ArtifactLoader = mock.MagicMock()
        ansible_runner.Runner.run = mock.MagicMock(return_value=('', 0))
        ansible_runner.runner_config = mock.MagicMock()
        utils.run_ansible_playbook(
            playbook='existing.yaml',
            inventory='localhost,',
            workdir=utils.constants.DEFAULT_WORK_DIR,
            extra_vars_file={
                'foo': 'bar',
                'things': {
                    'more': 'options'
                },
                'num': 42
            }
        )
        self.assertIn(
            mock.call(os.path.join(utils.constants.DEFAULT_WORK_DIR,
                                   'env/extravars'), 'w'),
            mock_open.mock_calls
        )
        self.assertIn(
            mock.call().__enter__().write(
                'foo: bar\nnum: 42\nthings:\n  more: options\n'
            ),
            mock_open.mock_calls
        )


class TestRunRolePlaybooks(TestCase):
    def setUp(self):
        tmp_dir = utils.TempDirs().dir
        self.work_dir = os.path.join(tmp_dir, 'working_dir')
        utils.makedirs(self.work_dir)
        self.inventory_path = os.path.join(
            self.work_dir, 'tripleo-ansible-inventory.yaml')
        with open(self.inventory_path, 'w') as f:
            f.write('{}')

        self.cmd = mock.Mock()
        self.cmd.app.options.debug = False
        self.cmd.app_args.verbose_level = 0

    @mock.patch('tripleoclient.utils.run_ansible_playbook')
    def test_network_config(self, mock_run):
        roles = [
            {'count': 10, 'name': 'Compute'},
            {'count': 3, 'name': 'Controller'}
        ]
        utils.run_role_playbooks(self.cmd, self.work_dir, self.work_dir,
                                 roles, True)

        self.assertEqual(3, mock_run.call_count)
        mock_run.assert_has_calls([
            mock.call(
                playbook='/usr/share/ansible/tripleo-playbooks/'
                         'cli-overcloud-node-growvols.yaml',
                inventory={},
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=0,
                limit_hosts='Compute',
                extra_vars={}
            ),
            mock.call(
                playbook='/usr/share/ansible/tripleo-playbooks/'
                         'cli-overcloud-node-growvols.yaml',
                inventory={},
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=0,
                limit_hosts='Controller',
                extra_vars={}
            ),
            mock.call(
                playbook='/usr/share/ansible/tripleo-playbooks/'
                         'cli-overcloud-node-network-config.yaml',
                inventory={},
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=0,
                limit_hosts=None,
                extra_vars={}
            )
        ])

    @mock.patch('tripleoclient.utils.run_ansible_playbook')
    def test_no_network_config(self, mock_run):
        roles = [
            {'count': 10, 'name': 'Compute'},
            {'count': 3, 'name': 'Controller'}
        ]
        utils.run_role_playbooks(self.cmd, self.work_dir, self.work_dir,
                                 roles, False)

        self.assertEqual(2, mock_run.call_count)
        mock_run.assert_has_calls([
            mock.call(
                playbook='/usr/share/ansible/tripleo-playbooks/'
                         'cli-overcloud-node-growvols.yaml',
                inventory={},
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=0,
                limit_hosts='Compute',
                extra_vars={}
            ),
            mock.call(
                playbook='/usr/share/ansible/tripleo-playbooks/'
                         'cli-overcloud-node-growvols.yaml',
                inventory={},
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=0,
                limit_hosts='Controller',
                extra_vars={}
            )
        ])

    @mock.patch('tripleoclient.utils.run_ansible_playbook')
    def test_override_growvols(self, mock_run):
        roles = [
            {'count': 10, 'name': 'Compute'},
            {
                'count': 3,
                'name': 'Controller',
                'ansible_playbooks': [
                    {
                        'playbook': '/usr/share/ansible/tripleo-playbooks/'
                                    'cli-overcloud-node-growvols.yaml',
                        'extra_vars': {
                            'growvols_args': '/var=50% /srv=50%'
                        }
                    }
                ]
            }
        ]
        utils.run_role_playbooks(self.cmd, self.work_dir, self.work_dir,
                                 roles, False)

        self.assertEqual(2, mock_run.call_count)
        mock_run.assert_has_calls([
            mock.call(
                playbook='/usr/share/ansible/tripleo-playbooks/'
                         'cli-overcloud-node-growvols.yaml',
                inventory={},
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=0,
                limit_hosts='Compute',
                extra_vars={}
            ),
            mock.call(
                playbook='/usr/share/ansible/tripleo-playbooks/'
                         'cli-overcloud-node-growvols.yaml',
                inventory={},
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=0,
                limit_hosts='Controller',
                extra_vars={'growvols_args': '/var=50% /srv=50%'}
            )
        ])

    @mock.patch('tripleoclient.utils.run_ansible_playbook')
    def test_role_playbooks(self, mock_run):
        roles = [
            # No playbooks should execute for the role if count is 0.
            {'count': 0, 'name': 'ZeroNodesRole'},
            {'count': 10, 'name': 'Compute'},
            {
                'count': 3,
                'name': 'Controller',
                'ansible_playbooks': [
                    {
                        'playbook': 'the_thing.yaml'
                    },
                    {
                        'playbook': '/usr/share/ansible/tripleo-playbooks/'
                                    'cli-overcloud-node-growvols.yaml',
                        'extra_vars': {
                            'growvols_args': '/var=50% /srv=50%'
                        }
                    },
                    {
                        'playbook': 'the_other_thing.yaml'
                    },
                ]
            }
        ]
        utils.run_role_playbooks(self.cmd, self.work_dir, self.work_dir,
                                 roles, True)

        self.assertEqual(5, mock_run.call_count)
        mock_run.assert_has_calls([
            mock.call(
                playbook='/usr/share/ansible/tripleo-playbooks/'
                         'cli-overcloud-node-growvols.yaml',
                inventory={},
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=0,
                limit_hosts='Compute',
                extra_vars={}
            ),
            mock.call(
                playbook=os.path.join(self.work_dir, 'the_thing.yaml'),
                inventory={},
                workdir=mock.ANY,
                playbook_dir=self.work_dir,
                verbosity=0,
                limit_hosts='Controller',
                extra_vars={}
            ),
            mock.call(
                playbook='/usr/share/ansible/tripleo-playbooks/'
                         'cli-overcloud-node-growvols.yaml',
                inventory={},
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=0,
                limit_hosts='Controller',
                extra_vars={'growvols_args': '/var=50% /srv=50%'}
            ),
            mock.call(
                playbook=os.path.join(self.work_dir, 'the_other_thing.yaml'),
                inventory={},
                workdir=mock.ANY,
                playbook_dir=self.work_dir,
                verbosity=0,
                limit_hosts='Controller',
                extra_vars={}
            ),
            mock.call(
                playbook='/usr/share/ansible/tripleo-playbooks/'
                         'cli-overcloud-node-network-config.yaml',
                inventory={},
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=0,
                limit_hosts=None,
                extra_vars={}
            )
        ])


class TestRunCommandAndLog(TestCase):
    def setUp(self):
        self.mock_logger = mock.Mock(spec=logging.Logger)

        self.mock_process = mock.Mock()
        self.mock_process.stdout.readline.side_effect = ['foo\n', 'bar\n']
        self.mock_process.wait.side_effect = [0]
        self.mock_process.returncode = 0

        mock_sub = mock.patch('subprocess.Popen',
                              return_value=self.mock_process)
        self.mock_popen = mock_sub.start()
        self.addCleanup(mock_sub.stop)

        self.cmd = ['exit', '0']
        self.e_cmd = ['exit', '1']
        self.log_calls = [mock.call('foo'),
                          mock.call('bar')]

    def test_success_default(self):
        retcode = utils.run_command_and_log(self.mock_logger, self.cmd)
        self.mock_popen.assert_called_once_with(self.cmd,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT,
                                                shell=False,
                                                cwd=None, env=None)
        self.assertEqual(retcode, 0)
        self.mock_logger.warning.assert_has_calls(self.log_calls,
                                                  any_order=False)

    @mock.patch('subprocess.Popen')
    def test_error_subprocess(self, mock_popen):
        mock_process = mock.Mock()
        mock_process.stdout.readline.side_effect = ['Error\n']
        mock_process.wait.side_effect = [1]
        mock_process.returncode = 1

        mock_popen.return_value = mock_process

        retcode = utils.run_command_and_log(self.mock_logger, self.e_cmd)
        mock_popen.assert_called_once_with(self.e_cmd, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           shell=False, cwd=None,
                                           env=None)

        self.assertEqual(retcode, 1)
        self.mock_logger.warning.assert_called_once_with('Error')

    def test_success_env(self):
        test_env = os.environ.copy()
        retcode = utils.run_command_and_log(self.mock_logger, self.cmd,
                                            env=test_env)
        self.mock_popen.assert_called_once_with(self.cmd,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT,
                                                shell=False,
                                                cwd=None, env=test_env)
        self.assertEqual(retcode, 0)
        self.mock_logger.warning.assert_has_calls(self.log_calls,
                                                  any_order=False)

    def test_success_cwd(self):
        test_cwd = '/usr/local/bin'
        retcode = utils.run_command_and_log(self.mock_logger, self.cmd,
                                            cwd=test_cwd)
        self.mock_popen.assert_called_once_with(self.cmd,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT,
                                                shell=False,
                                                cwd=test_cwd, env=None)
        self.assertEqual(retcode, 0)
        self.mock_logger.warning.assert_has_calls(self.log_calls,
                                                  any_order=False)


class TestWaitForStackUtil(TestCase):
    def setUp(self):
        self.mock_orchestration = mock.Mock()
        sleep_patch = mock.patch('time.sleep')
        self.addCleanup(sleep_patch.stop)
        sleep_patch.start()

    def mock_event(self, resource_name, id, resource_status_reason,
                   resource_status, event_time):
        e = mock.Mock()
        e.resource_name = resource_name
        e.id = id
        e.resource_status_reason = resource_status_reason
        e.resource_status = resource_status
        e.event_time = event_time
        return e

    @mock.patch("heatclient.common.event_utils.get_events")
    def test_wait_for_stack_ready(self, mock_el):
        stack = mock.Mock()
        stack.stack_name = 'stack'
        stack.stack_status = "CREATE_COMPLETE"
        self.mock_orchestration.stacks.get.return_value = stack

        complete = utils.wait_for_stack_ready(self.mock_orchestration, 'stack')
        self.assertTrue(complete)

    @mock.patch("time.sleep")
    @mock.patch("heatclient.common.event_utils.poll_for_events")
    @mock.patch("tripleoclient.utils.get_stack")
    def test_wait_for_stack_ready_retry(self, mock_get_stack, mock_poll,
                                        mock_time):
        stack = mock.Mock()
        stack.stack_name = 'stack'
        stack.stack_id = 'id'
        stack.stack_status = "CREATE_COMPLETE"
        mock_get_stack.return_value = stack
        mock_poll.side_effect = [hc_exc.HTTPException(code=504),
                                 ("CREATE_COMPLETE", "ready retry message")]

        complete = utils.wait_for_stack_ready(self.mock_orchestration, 'stack')
        self.assertTrue(complete)

    @mock.patch("time.sleep")
    @mock.patch("heatclient.common.event_utils.poll_for_events")
    @mock.patch("tripleoclient.utils.get_stack")
    def test_wait_for_stack_ready_retry_fail(self, mock_get_stack, mock_poll,
                                             mock_time):
        stack = mock.Mock()
        stack.stack_name = 'stack'
        stack.stack_id = 'id'
        stack.stack_status = "CREATE_COMPLETE"
        mock_get_stack.return_value = stack
        mock_poll.side_effect = hc_exc.HTTPException(code=504)

        self.assertRaises(RuntimeError,
                          utils.wait_for_stack_ready,
                          self.mock_orchestration, 'stack')

    @mock.patch("time.sleep")
    @mock.patch("heatclient.common.event_utils.poll_for_events")
    @mock.patch("tripleoclient.utils.get_stack")
    def test_wait_for_stack_ready_server_fail(self, mock_get_stack, mock_poll,
                                              mock_time):
        stack = mock.Mock()
        stack.stack_name = 'stack'
        stack.stack_id = 'id'
        stack.stack_status = "CREATE_COMPLETE"
        mock_get_stack.return_value = stack
        mock_poll.side_effect = hc_exc.HTTPException(code=500)

        self.assertRaises(RuntimeError,
                          utils.wait_for_stack_ready,
                          self.mock_orchestration, 'stack')

    def test_wait_for_stack_ready_no_stack(self):
        self.mock_orchestration.stacks.get.return_value = None

        complete = utils.wait_for_stack_ready(self.mock_orchestration, 'stack')

        self.assertFalse(complete)

    @mock.patch("heatclient.common.event_utils.get_events")
    def test_wait_for_stack_ready_failed(self, mock_el):
        stack = mock.Mock()
        stack.stack_name = 'stack'
        stack.stack_status = "CREATE_FAILED"
        self.mock_orchestration.stacks.get.return_value = stack

        complete = utils.wait_for_stack_ready(self.mock_orchestration, 'stack')

        self.assertFalse(complete)

    @mock.patch("heatclient.common.event_utils.poll_for_events")
    def test_wait_for_stack_in_progress(self, mock_poll_for_events):

        mock_poll_for_events.return_value = ("CREATE_IN_PROGRESS", "MESSAGE")

        stack = mock.Mock()
        stack.stack_name = 'stack'
        stack.stack_status = 'CREATE_IN_PROGRESS'
        self.mock_orchestration.stacks.get.return_value = stack

        result = utils.wait_for_stack_ready(self.mock_orchestration, 'stack')
        self.assertEqual(False, result)

    def test_check_service_vips_migrated_to_service(self):
        env_reg = {
            'OS::TripleO::Network::Ports::RedisVipPort': 'val',
            'OS::TripleO::Network::Ports::OVNDBsVipPort': 'val',
        }
        env = {
            'resource_registry':  env_reg
        }

        self.assertRaises(exceptions.InvalidConfiguration,
                          utils.check_service_vips_migrated_to_service,
                          env)

    def test_check_ceph_fsid_matches_env_files(self):
        stack_params = {
            'CephClusterFSID': 'ceph_fsid_val',
            'key1': 'val1',
            'key2': 'val2',
        }
        mock_stack = mock.MagicMock()
        mock_stack.environment = mock.MagicMock()
        mock_stack.environment.return_value = {
            'parameter_defaults': stack_params
        }
        provided_env = {
            'parameter_defaults': {
                'CephClusterFSID': mock_stack.environment()
                                             .get('parameter_defaults', {})
                                             .get('CephClusterFSID', False),
                'key1': 'val1',
                'key2': 'val2',
            }
        }
        utils.check_ceph_fsid_matches_env_files(mock_stack.environment(),
                                                provided_env)

    def test_check_ceph_fsid_matches_env_files_fail(self):
        stack_params = {
            'CephClusterFSID': 'ceph_fsid_val',
            'key1': 'val1',
            'key2': 'val2',
        }
        provided_env = {
            'parameter_defaults': {
                'CephClusterFSID': 'new_or_wrong_fsid_val',
                'key1': 'val1',
                'key2': 'val2',
            }
        }
        mock_stack = mock.MagicMock()
        mock_stack.environment = mock.MagicMock()
        mock_stack.environment.return_value = {
            'parameter_defaults': stack_params
        }
        with self.assertRaises(exceptions.InvalidConfiguration):
            utils.check_ceph_fsid_matches_env_files(mock_stack.environment(),
                                                    provided_env)

    def test_check_ceph_ansible(self):
        res_reg = {
            'resource_registry': {
                'OS::Tripleo::Services::CephMon': '/path/to/ceph-ansible.yml',
            }
        }

        utils.check_ceph_ansible(res_reg.get('resource_registry', {}),
                                 'UpgradePrepare')
        utils.check_ceph_ansible(res_reg.get('resource_registry', {}),
                                 'UpgradeConverge')

    def test_check_ceph_ansible_fail(self):
        res_reg = {
            'resource_registry': {
                'OS::Tripleo::Services::CephMon': '/path/to/ceph-ansible.yml',
            }
        }

        with self.assertRaises(exceptions.InvalidConfiguration):
            utils.check_ceph_ansible(res_reg.get('resource_registry', {}),
                                     'DeployOvercloud')

    def test_check_deployed_ceph_stage(self):

        env = {
            'resource_registry': {
                'OS::Tripleo::Services::CephMon': '/path/cephadm/ceph-mon.yml',
                'OS::TripleO::Services::CephMgr': '/path/cephadm/ceph-mgr.yml',
                'OS::TripleO::Services::CephMon': '/path/cephadm/ceph-mon.yml',
                'OS::TripleO::Services::CephOSD': '/path/cephadm/ceph-osd.yml',
                'OS::TripleO::Services::CephMds': '/path/cephadm/ceph-mds.yml',
                'OS::TripleO::Services::CephNfs': '/path/cephadm/ceph-nfs.yml',
                'OS::TripleO::Services::CephRgw': '/path/cephadm/ceph-rgw.yml',
            },
            'parameter_defaults': {
                'DeployedCeph': True
            }
        }

        utils.check_deployed_ceph_stage(env)

    def test_check_deployed_ceph_stage_fail(self):

        env = {
            'resource_registry': {
                'OS::Tripleo::Services::CephMon': '/path/cephadm/ceph-mon.yml',
                'OS::TripleO::Services::CephMgr': '/path/cephadm/ceph-mgr.yml',
                'OS::TripleO::Services::CephMon': '/path/cephadm/ceph-mon.yml',
                'OS::TripleO::Services::CephOSD': '/path/cephadm/ceph-osd.yml',
                'OS::TripleO::Services::CephMds': '/path/cephadm/ceph-mds.yml',
                'OS::TripleO::Services::CephNfs': '/path/cephadm/ceph-nfs.yml',
                'OS::TripleO::Services::CephRgw': '/path/cephadm/ceph-rgw.yml',
            },
            'parameter_defaults': {
                'DeployedCeph': False
            }
        }

        with self.assertRaises(exceptions.InvalidConfiguration):
            utils.check_deployed_ceph_stage(env)

    def test_check_deployed_ceph_stage_external(self):

        env = {
            'resource_registry': {
                'OS::Tripleo::Services::CephExternal': '/path/cephadm/ceph-client.yml',  # noqa E501
            },
            'parameter_defaults': {
                'DeployedCeph': False
            }
        }

        with self.assertRaises(exceptions.InvalidConfiguration):
            utils.check_deployed_ceph_stage(env)

    def test_check_swift_and_rgw(self):
        stack_reg = {
            'OS::TripleO::Services::SwiftProxy': 'OS::Heat::None',
        }
        env_reg = {
            'OS::TripleO::Services::CephRgw': 'val',
        }
        mock_stack = mock.MagicMock()
        mock_stack.environment = mock.MagicMock()
        mock_stack.environment.return_value = {
            'resource_registry': stack_reg,
        }
        env = {
            'resource_registry': env_reg,
        }

        utils.check_swift_and_rgw(mock_stack.environment(),
                                  env, 'UpgradePrepare')

    def test_check_swift_and_rgw_fail(self):
        stack_reg = {
            'OS::TripleO::Services::SwiftProxy': 'val',
        }
        env_reg = {
            'OS::TripleO::Services::CephRgw': 'val',
        }
        mock_stack = mock.MagicMock()
        mock_stack.environment = mock.MagicMock()
        mock_stack.environment.return_value = {
            'resource_registry': stack_reg,
        }
        env = {
            'resource_registry': env_reg,
        }
        with self.assertRaises(exceptions.InvalidConfiguration):
            utils.check_swift_and_rgw(mock_stack.environment(),
                                      env, 'UpgradePrepare')

    @mock.patch('os.path.isfile', return_value=False)
    def test_check_network_plugin_no_neutron(self, mock_file):
        fake_env = {
            'parameter_defaults': {
                'NeutronMechanismDrivers': ['ovn']},
        }
        utils.check_network_plugin('/tmp',
                                   fake_env)
        mock_file.assert_not_called()

    @mock.patch('os.path.isfile', return_value=False)
    def test_check_network_plugin_inventory_missing(self, mock_file):
        fake_env = {
            'parameter_defaults': {
                'NeutronMechanismDrivers': ['ovn']},
            'resource_registry': {
                'OS::TripleO::Services::NeutronApi': 'foo'}
        }
        with self.assertRaises(exceptions.InvalidConfiguration):
            utils.check_network_plugin('/tmp',
                                       fake_env)

    @mock.patch('os.path.isfile', return_value=True)
    def test_check_network_plugin_inventory_ovs_match(self, mock_file):
        fake_env = {
            'parameter_defaults': {
                'NeutronMechanismDrivers': ['openvswitch']},
            'resource_registry': {
                'OS::TripleO::Services::NeutronApi': 'foo'}
        }
        mock_open_ctx = mock.mock_open(read_data='neutron_ovs_agent')
        with mock.patch('builtins.open', mock_open_ctx):
            utils.check_network_plugin('/tmp',
                                       fake_env)

    @mock.patch('os.path.isfile', return_value=True)
    def test_check_network_plugin_inventory_ovs_mismatch(self, mock_file):
        fake_env = {
            'parameter_defaults': {
                'NeutronMechanismDrivers': ['ovn']},
            'resource_registry': {
                'OS::TripleO::Services::NeutronApi': 'foo'}
        }
        with self.assertRaises(exceptions.InvalidConfiguration):
            mock_open_ctx = mock.mock_open(read_data='neutron_ovs_agent')
            with mock.patch('builtins.open', mock_open_ctx):
                utils.check_network_plugin('/tmp',
                                           fake_env)

    @mock.patch('os.path.isfile', return_value=True)
    def test_check_network_plugin_inventory_ovn_match(self, mock_file):
        fake_env = {
            'parameter_defaults': {
                'NeutronMechanismDrivers': ['ovn']},
            'resource_registry': {
                'OS::TripleO::Services::NeutronApi': 'foo'}
        }
        mock_open_ctx = mock.mock_open(read_data='ovn_controller')
        with mock.patch('builtins.open', mock_open_ctx):
            utils.check_network_plugin('/tmp',
                                       fake_env)

    @mock.patch('os.path.isfile', return_value=True)
    def test_check_network_plugin_inventory_ovn_mismatch(self, mock_file):
        fake_env = {
            'parameter_defaults': {
                'NeutronMechanismDrivers': ['openvswitch']},
            'resource_registry': {
                'OS::TripleO::Services::NeutronApi': 'foo'}
        }
        with self.assertRaises(exceptions.InvalidConfiguration):
            mock_open_ctx = mock.mock_open(read_data='ovn_controller')
            with mock.patch('builtins.open', mock_open_ctx):
                utils.check_network_plugin('/tmp',
                                           fake_env)

    @mock.patch('subprocess.check_call')
    @mock.patch('os.path.exists')
    def test_remove_known_hosts(self, mock_exists, mock_check_call):

        mock_exists.return_value = True

        utils.remove_known_hosts('192.168.0.1')
        known_hosts = os.path.expanduser("~/.ssh/known_hosts")

        mock_check_call.assert_called_with(
            ['ssh-keygen', '-R', '192.168.0.1', '-f', known_hosts])

    @mock.patch('subprocess.check_call')
    @mock.patch('os.path.exists')
    def test_remove_known_hosts_no_file(self, mock_exists, mock_check_call):

        mock_exists.return_value = False

        utils.remove_known_hosts('192.168.0.1')

        mock_check_call.assert_not_called()

    def test_empty_file_checksum(self):
        # Used a NamedTemporaryFile since it's deleted when the file is closed.
        with tempfile.NamedTemporaryFile() as empty_temp_file:
            self.assertEqual(
                utils.file_checksum(empty_temp_file.name),
                (
                    'cf83e1357eefb8bdf1542850d66d8007'
                    'd620e4050b5715dc83f4a921d36ce9ce47'
                    'd0d13c5d85f2b0ff8318d2877eec2f63b'
                    '931bd47417a81a538327af927da3e'))

    def test_non_empty_file_checksum(self):
        # Used a NamedTemporaryFile since it's deleted when the file is closed.
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(b'foo')
            temp_file.flush()

            self.assertEqual(
                utils.file_checksum(temp_file.name),
                (
                    'f7fbba6e0636f890e56fbbf3283e52'
                    '4c6fa3204ae298382d624741d0dc663'
                    '8326e282c41be5e4254d8820772c55'
                    '18a2c5a8c0c7f7eda19594a7eb539453e1ed7'))

    def test_non_empty_file_checksum_SHA256(self):
        """Test 'file_checksum' function with an alternative algorithm.
        """
        # Used a NamedTemporaryFile since it's deleted when the file is closed.
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(b'foo')
            temp_file.flush()

            self.assertEqual(
                utils.file_checksum(temp_file.name, 'sha256'),
                (
                    '2c26b46b68ffc68ff99b453c1d304134'
                    '13422d706483bfa0f98a5e886266e7ae'))

    def test_non_empty_file_checksum_non_compliant(self):
        """Test 'file_checksum' function with an alternative algorithm
        that isn't permitted by the FIPS.
        """
        # Used a NamedTemporaryFile since it's deleted when the file is closed.
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(b'foo')
            temp_file.flush()

            self.assertRaises(RuntimeError, utils.file_checksum,
                              temp_file.name, 'md5')

    def test_shouldnt_checksum_open_special_files(self):
        self.assertRaises(ValueError, utils.file_checksum, '/dev/random')
        self.assertRaises(ValueError, utils.file_checksum, '/dev/zero')


class TestEnsureRunAsNormalUser(TestCase):

    @mock.patch('os.geteuid')
    def test_ensure_run_as_normal_user(self, os_geteuid_mock):
        os_geteuid_mock.return_value = 1000
        self.assertIsNone(utils.ensure_run_as_normal_user())

    @mock.patch('os.geteuid')
    def test_ensure_run_as_normal_user_root(self, os_geteuid_mock):
        os_geteuid_mock.return_value = 0
        self.assertRaises(exceptions.RootUserExecution,
                          utils.ensure_run_as_normal_user)

    @mock.patch('getpass.getuser')
    def test_get_deployment_user(self, mock_getpass):
        mock_getpass.return_value = 'stack'
        u = utils.get_deployment_user()
        self.assertEqual('stack', u)


class TestCreateTempestDeployerInput(TestCase):

    def test_create_tempest_deployer_input(self):
        with tempfile.NamedTemporaryFile() as cfgfile:
            filepath = cfgfile.name
            utils.create_tempest_deployer_input(filepath)
            with open(filepath, 'rt') as f:
                cfg = f.read()
            # Just make a simple test, to make sure it created a proper file:
            self.assertIn(
                '[volume-feature-enabled]\nbootable = true', cfg)


class TestGetStackOutputItem(TestCase):

    def test_get_stack_output_item(self):
        stack = mock.MagicMock()
        emap = {'KeystonePublic': {'uri': 'http://foo:8000/'}}
        stack.to_dict.return_value = {
            'outputs': [{'output_key': 'EndpointMap',
                         'output_value': emap}]
        }

        endpoint_map = utils.get_stack_output_item(stack, 'EndpointMap')
        self.assertEqual(endpoint_map,
                         {'KeystonePublic': {'uri': 'http://foo:8000/'}})

    def test_get_stack_output_item_not_found(self):
        stack = mock.MagicMock()
        stack.to_dict.return_value = {
            'outputs': [{'output_key': 'foo',
                         'output_value': 'bar'}]
        }

        val = utils.get_stack_output_item(stack, 'baz')
        self.assertEqual(val, None)

    def test_get_stack_output_item_no_stack(self):
        stack = None
        val = utils.get_stack_output_item(stack, 'baz')
        self.assertEqual(val, None)


class TestGetEndpointMap(TestCase):

    @mock.patch('tripleoclient.utils.get_stack_saved_output_item')
    def test_get_endpoint_map(self, mock_saved_output_item):
        working_dir = mock.Mock()
        emap = {'KeystonePublic': {'uri': 'http://foo:8000/'}}
        mock_saved_output_item.return_value = emap
        endpoint_map = utils.get_endpoint_map(working_dir)
        self.assertEqual(endpoint_map,
                         {'KeystonePublic': {'uri': 'http://foo:8000/'}})


class TestNodeGetCapabilities(TestCase):
    def test_with_capabilities(self):
        node = mock.Mock(properties={'capabilities': 'x:y,foo:bar'})
        self.assertEqual({'x': 'y', 'foo': 'bar'},
                         utils.node_get_capabilities(node))

    def test_no_capabilities(self):
        node = mock.Mock(properties={})
        self.assertEqual({}, utils.node_get_capabilities(node))


class TestNodeAddCapabilities(TestCase):
    def test_add(self):
        bm_client = mock.Mock()
        node = mock.Mock(uuid='uuid1', properties={})
        new_caps = utils.node_add_capabilities(bm_client, node, x='y')
        bm_client.node.update.assert_called_once_with(
            'uuid1', [{'op': 'add', 'path': '/properties/capabilities',
                       'value': 'x:y'}])
        self.assertEqual('x:y', node.properties['capabilities'])
        self.assertEqual({'x': 'y'}, new_caps)


class TestAssignVerifyProfiles(TestCase):
    def setUp(self):

        super(TestAssignVerifyProfiles, self).setUp()
        self.bm_client = mock.Mock(spec=['node'],
                                   node=mock.Mock(spec=['list', 'update']))
        self.nodes = []
        self.bm_client.node.list.return_value = self.nodes
        self.flavors = {name: (fakes.FakeFlavor(name), 1)
                        for name in ('compute', 'control')}

    def _get_fake_node(self, profile=None, possible_profiles=[],
                       provision_state='available'):
        caps = {'%s_profile' % p: '1'
                for p in possible_profiles}
        if profile is not None:
            caps['profile'] = profile
        caps = utils.dict_to_capabilities(caps)
        return mock.Mock(uuid=str(uuid4()),
                         properties={'capabilities': caps},
                         provision_state=provision_state,
                         spec=['uuid', 'properties', 'provision_state'])

    def _test(self, expected_errors, expected_warnings,
              assign_profiles=True, dry_run=False):
        errors, warnings = utils.assign_and_verify_profiles(self.bm_client,
                                                            self.flavors,
                                                            assign_profiles,
                                                            dry_run)
        self.assertEqual(errors, expected_errors)
        self.assertEqual(warnings, expected_warnings)

    def test_no_matching_without_scale(self):
        self.flavors = {name: (object(), 0)
                        for name in self.flavors}
        self.nodes[:] = [self._get_fake_node(profile='fake'),
                         self._get_fake_node(profile='fake')]

        self._test(0, 0)
        self.assertFalse(self.bm_client.node.update.called)

    def test_exact_match(self):
        self.nodes[:] = [self._get_fake_node(profile='compute'),
                         self._get_fake_node(profile='control')]

        self._test(0, 0)
        self.assertFalse(self.bm_client.node.update.called)

    def test_nodes_with_no_profiles_present(self):
        self.nodes[:] = [self._get_fake_node(profile='compute'),
                         self._get_fake_node(profile=None),
                         self._get_fake_node(profile='foobar'),
                         self._get_fake_node(profile='control')]

        self._test(0, 1)
        self.assertFalse(self.bm_client.node.update.called)

    def test_more_nodes_with_profiles_present(self):
        self.nodes[:] = [self._get_fake_node(profile='compute'),
                         self._get_fake_node(profile='compute'),
                         self._get_fake_node(profile='compute'),
                         self._get_fake_node(profile='control')]

        self._test(0, 1)
        self.assertFalse(self.bm_client.node.update.called)

    def test_no_nodes(self):
        # One error per each flavor
        self._test(2, 0)
        self.assertFalse(self.bm_client.node.update.called)

    def test_not_enough_nodes(self):
        self.nodes[:] = [self._get_fake_node(profile='compute')]
        self._test(1, 0)
        self.assertFalse(self.bm_client.node.update.called)

    def test_assign_profiles(self):
        self.nodes[:] = [self._get_fake_node(possible_profiles=['compute']),
                         self._get_fake_node(possible_profiles=['control']),
                         self._get_fake_node(possible_profiles=['compute'])]

        # one warning for a redundant node
        self._test(0, 1, assign_profiles=True)
        self.assertEqual(2, self.bm_client.node.update.call_count)

        actual_profiles = [utils.node_get_capabilities(node).get('profile')
                           for node in self.nodes]
        actual_profiles.sort(key=lambda x: str(x))
        self.assertEqual([None, 'compute', 'control'], actual_profiles)

    def test_assign_profiles_multiple_options(self):
        self.nodes[:] = [self._get_fake_node(possible_profiles=['compute',
                                                                'control']),
                         self._get_fake_node(possible_profiles=['compute',
                                                                'control'])]

        self._test(0, 0, assign_profiles=True)
        self.assertEqual(2, self.bm_client.node.update.call_count)

        actual_profiles = [utils.node_get_capabilities(node).get('profile')
                           for node in self.nodes]
        actual_profiles.sort(key=lambda x: str(x))
        self.assertEqual(['compute', 'control'], actual_profiles)

    def test_assign_profiles_not_enough(self):
        self.nodes[:] = [self._get_fake_node(possible_profiles=['compute']),
                         self._get_fake_node(possible_profiles=['compute']),
                         self._get_fake_node(possible_profiles=['compute'])]

        self._test(1, 1, assign_profiles=True)
        # no node update for failed flavor
        self.assertEqual(1, self.bm_client.node.update.call_count)

        actual_profiles = [utils.node_get_capabilities(node).get('profile')
                           for node in self.nodes]
        actual_profiles.sort(key=lambda x: str(x))
        self.assertEqual([None, None, 'compute'], actual_profiles)

    def test_assign_profiles_dry_run(self):
        self.nodes[:] = [self._get_fake_node(possible_profiles=['compute']),
                         self._get_fake_node(possible_profiles=['control']),
                         self._get_fake_node(possible_profiles=['compute'])]

        self._test(0, 1, dry_run=True)
        self.assertFalse(self.bm_client.node.update.called)

        actual_profiles = [utils.node_get_capabilities(node).get('profile')
                           for node in self.nodes]
        self.assertEqual([None] * 3, actual_profiles)

    def test_scale(self):
        # active nodes with assigned profiles are fine
        self.nodes[:] = [self._get_fake_node(profile='compute',
                                             provision_state='active'),
                         self._get_fake_node(profile='control')]

        self._test(0, 0, assign_profiles=True)
        self.assertFalse(self.bm_client.node.update.called)

    def test_assign_profiles_wrong_state(self):
        # active nodes are not considered for assigning profiles
        self.nodes[:] = [self._get_fake_node(possible_profiles=['compute'],
                                             provision_state='active'),
                         self._get_fake_node(possible_profiles=['control'],
                                             provision_state='cleaning'),
                         self._get_fake_node(profile='compute',
                                             provision_state='error')]

        self._test(2, 1, assign_profiles=True)
        self.assertFalse(self.bm_client.node.update.called)

    def test_no_spurious_warnings(self):
        self.nodes[:] = [self._get_fake_node(profile=None)]
        self.flavors = {'baremetal': (fakes.FakeFlavor('baremetal', None), 1)}
        self._test(0, 0)


class TestPromptUser(TestCase):
    def setUp(self):
        super(TestPromptUser, self).setUp()
        self.logger = mock.MagicMock()
        self.logger.info = mock.MagicMock()

    @mock.patch('sys.stdin')
    def test_user_accepts(self, stdin_mock):
        stdin_mock.isatty.return_value = True
        stdin_mock.readline.return_value = "yes"
        result = utils.prompt_user_for_confirmation("[y/N]?", self.logger)
        self.assertTrue(result)

    @mock.patch('sys.stdin')
    def test_user_declines(self, stdin_mock):
        stdin_mock.isatty.return_value = True
        stdin_mock.readline.return_value = "no"
        result = utils.prompt_user_for_confirmation("[y/N]?", self.logger)
        self.assertFalse(result)

    @mock.patch('sys.stdin')
    def test_user_no_tty(self, stdin_mock):
        stdin_mock.isatty.return_value = False
        stdin_mock.readline.return_value = "yes"
        result = utils.prompt_user_for_confirmation("[y/N]?", self.logger)
        self.assertFalse(result)

    @mock.patch('sys.stdin')
    def test_user_aborts_control_c(self, stdin_mock):
        stdin_mock.isatty.return_value = False
        stdin_mock.readline.side_effect = KeyboardInterrupt()
        result = utils.prompt_user_for_confirmation("[y/N]?", self.logger)
        self.assertFalse(result)

    @mock.patch('sys.stdin')
    def test_user_aborts_with_control_d(self, stdin_mock):
        stdin_mock.isatty.return_value = False
        stdin_mock.readline.side_effect = EOFError()
        result = utils.prompt_user_for_confirmation("[y/N]?", self.logger)
        self.assertFalse(result)


class TestReplaceLinks(TestCase):

    def setUp(self):
        super(TestReplaceLinks, self).setUp()
        self.link_replacement = {
            'file:///home/stack/test.sh':
                'user-files/home/stack/test.sh',
            'file:///usr/share/extra-templates/my.yml':
                'user-files/usr/share/extra-templates/my.yml',
        }

    def test_replace_links(self):
        source = (
            'description: my template\n'
            'heat_template_version: "2014-10-16"\n'
            'parameters:\n'
            '  foo:\n'
            '    default: ["bar"]\n'
            '    type: json\n'
            '  bar:\n'
            '    default: []\n'
            'resources:\n'
            '  test_config:\n'
            '    properties:\n'
            '      config: {get_file: "file:///home/stack/test.sh"}\n'
            '    type: OS::Heat::SoftwareConfig\n'
        )
        expected = (
            'description: my template\n'
            'heat_template_version: "2014-10-16"\n'
            'parameters:\n'
            '  foo:\n'
            '    default: ["bar"]\n'
            '    type: json\n'
            '  bar:\n'
            '    default: []\n'
            'resources:\n'
            '  test_config:\n'
            '    properties:\n'
            '      config: {get_file: user-files/home/stack/test.sh}\n'
            '    type: OS::Heat::SoftwareConfig\n'
        )

        # the yaml->string dumps aren't always character-precise, so
        # we need to parse them into dicts for comparison
        expected_dict = yaml.safe_load(expected)
        result_dict = yaml.safe_load(utils.replace_links_in_template_contents(
            source, self.link_replacement))
        self.assertEqual(expected_dict, result_dict)

    def test_replace_links_not_template(self):
        # valid JSON/YAML, but doesn't have heat_template_version
        source = '{"get_file": "file:///home/stack/test.sh"}'
        self.assertEqual(
            source,
            utils.replace_links_in_template_contents(
                source, self.link_replacement))

    def test_replace_links_not_yaml(self):
        # invalid JSON/YAML -- curly brace left open
        source = '{"invalid JSON"'
        self.assertEqual(
            source,
            utils.replace_links_in_template_contents(
                source, self.link_replacement))

    def test_relative_link_replacement(self):
        current_dir = 'user-files/home/stack'
        expected = {
            'file:///home/stack/test.sh':
                'test.sh',
            'file:///usr/share/extra-templates/my.yml':
                '../../usr/share/extra-templates/my.yml',
        }
        self.assertEqual(expected, utils.relative_link_replacement(
            self.link_replacement, current_dir))


class TestBracketIPV6(TestCase):
    def test_basic(self):
        result = utils.bracket_ipv6('::1')
        self.assertEqual('[::1]', result)

    def test_hostname(self):
        result = utils.bracket_ipv6('hostname')
        self.assertEqual('hostname', result)

    def test_already_bracketed(self):
        result = utils.bracket_ipv6('[::1]')
        self.assertEqual('[::1]', result)


class TestIsValidIP(TestCase):
    def test_with_valid_ipv4(self):
        result = utils.is_valid_ip('192.168.0.1')
        self.assertEqual(True, result)

    def test_with_valid_ipv6(self):
        result = utils.is_valid_ip('::1')
        self.assertEqual(True, result)

    def test_with_invalid_ip(self):
        result = utils.is_valid_ip('192.168.1%bad')
        self.assertEqual(False, result)


class TestIsLoopback(TestCase):
    def test_with_loopback(self):
        result = utils.is_loopback('127.0.0.1')
        self.assertEqual(True, result)

    def test_with_no_loopback(self):
        result = utils.is_loopback('10.0.0.1')
        self.assertEqual(False, result)


class TestGetHostIps(TestCase):
    def test_get_host_ips(self):
        with mock.patch.object(socket, 'getaddrinfo') as mock_addrinfo:
            mock_addrinfo.return_value = [('', '', 6, '', ('127.0.0.1', 0))]
            result = utils.get_host_ips('myhost.domain')
            self.assertEqual(['127.0.0.1'], result)


class TestGetSingleIp(TestCase):
    def test_with_fqdn_and_valid_ip(self):
        with mock.patch.object(utils, 'get_host_ips') as mock_gethostips:
            mock_gethostips.return_value = ['192.168.0.1']
            result = utils.get_single_ip('myhost.domain')
            self.assertEqual('192.168.0.1', result)

    def test_with_fqdn_and_loopback(self):
        with mock.patch.object(utils, 'get_host_ips') as mock_gethostips:
            mock_gethostips.return_value = ['127.0.0.1']
            self.assertRaises(exceptions.LookupError,
                              utils.get_single_ip, 'myhost.domain')

    def test_with_too_much_ips(self):
        with mock.patch.object(utils, 'get_host_ips') as mock_gethostips:
            mock_gethostips.return_value = ['192.168.0.1', '192.168.0.2']
            self.assertRaises(exceptions.LookupError,
                              utils.get_single_ip, 'myhost.domain')

    def test_without_ip(self):
        with mock.patch.object(utils, 'get_host_ips') as mock_gethostips:
            mock_gethostips.return_value = []
            self.assertRaises(exceptions.LookupError,
                              utils.get_single_ip, 'myhost.domain')

    def test_with_invalid_ip(self):
        with mock.patch.object(utils, 'get_host_ips') as mock_gethostips:
            mock_gethostips.return_value = ['192.168.23.x']
            self.assertRaises(exceptions.LookupError,
                              utils.get_single_ip, 'myhost.domain')


class TestStoreCliParam(TestCase):

    def setUp(self):
        self.args = argparse.ArgumentParser()

    @mock.patch('os.path.isdir')
    @mock.patch('os.path.exists')
    def test_exists_but_not_dir(self, mock_exists, mock_isdir):
        mock_exists.return_value = True
        mock_isdir.return_value = False
        self.assertRaises(exceptions.InvalidConfiguration,
                          utils.store_cli_param,
                          "overcloud deploy", self.args)

    @mock.patch('os.path.isdir')
    @mock.patch('os.path.exists')
    def test_write_cli_param(self, mock_exists, mock_isdir):
        history_path = os.path.join(os.path.expanduser("~"), '.tripleo')
        mock_exists.return_value = True
        mock_isdir.return_value = True
        mock_file = mock.mock_open()

        class ArgsFake(object):
            def __init__(self):
                self.a = 1

        dt = datetime.datetime(2017, 11, 22)
        with mock.patch("builtins.open", mock_file):
            with mock.patch('tripleoclient.utils.datetime') as mock_date:
                mock_date.datetime.now.return_value = dt
                utils.store_cli_param("overcloud plan list", ArgsFake())

        expected_call = [
            mock.call("%s/history" % history_path, 'a'),
            mock.call().write('2017-11-22 00:00:00 overcloud-plan-list a=1 \n')
        ]
        mock_file.assert_has_calls(expected_call, any_order=True)

    @mock.patch('builtins.open')
    @mock.patch('os.path.isdir')
    @mock.patch('os.path.exists')
    def test_fail_to_write_data(self, mock_exists, mock_isdir, mock_open):
        mock_exists.return_value = True
        mock_isdir.return_value = True
        mock_open.side_effect = IOError()
        self.assertRaises(IOError, utils.store_cli_param, "command", self.args)


class ProcessMultipleEnvironments(TestCase):

    def setUp(self):
        self.tht_root = '/twd/templates'
        self.user_tht_root = '/tmp/thtroot/'
        self.created_env_files = [
            './inside.yaml', '/tmp/thtroot/abs.yaml',
            '/tmp/thtroot/puppet/foo.yaml',
            '/tmp/thtroot/environments/myenv.yaml',
            '/tmp/thtroot42/notouch.yaml',
            './tmp/thtroot/notouch2.yaml',
            '../outside.yaml']

    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', return_value=({}, {}),
                autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'get_template_contents', return_value=({}, {}),
                autospec=True)
    @mock.patch('heatclient.common.environment_format.'
                'parse', autospec=True, return_value=dict())
    @mock.patch('heatclient.common.template_format.'
                'parse', autospec=True, return_value=dict())
    def test_redirect_templates_paths(self,
                                      mock_hc_templ_parse,
                                      mock_hc_env_parse,
                                      mock_hc_get_templ_cont,
                                      mock_hc_process):
        utils.process_multiple_environments(self.created_env_files,
                                            self.tht_root,
                                            self.user_tht_root)

        mock_hc_process.assert_has_calls([
            mock.call(env_path='./inside.yaml',
                      include_env_in_files=False),
            mock.call(env_path='/twd/templates/abs.yaml',
                      include_env_in_files=False),
            mock.call(env_path='/twd/templates/puppet/foo.yaml',
                      include_env_in_files=False),
            mock.call(env_path='/twd/templates/environments/myenv.yaml',
                      include_env_in_files=False),
            mock.call(env_path='/tmp/thtroot42/notouch.yaml',
                      include_env_in_files=False),
            mock.call(env_path='./tmp/thtroot/notouch2.yaml',
                      include_env_in_files=False),
            mock.call(env_path='../outside.yaml',
                      include_env_in_files=False)])

    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files',
                autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'get_template_contents', return_value=({}, {}),
                autospec=True)
    @mock.patch('heatclient.common.environment_format.'
                'parse', autospec=True, return_value=dict())
    @mock.patch('heatclient.common.template_format.'
                'parse', autospec=True, return_value=dict())
    @mock.patch('yaml.safe_dump', autospec=True)
    @mock.patch('yaml.safe_load', autospec=True)
    @mock.patch('builtins.open')
    @mock.patch('tempfile.NamedTemporaryFile', autospec=True)
    def test_rewrite_env_files(self,
                               mock_temp, mock_open,
                               mock_yaml_load,
                               mock_yaml_dump,
                               mock_hc_templ_parse,
                               mock_hc_env_parse,
                               mock_hc_get_templ_cont,
                               mock_hc_process):

        def hc_process(*args, **kwargs):
            if 'abs.yaml' in kwargs['env_path']:
                raise hc_exc.CommandError
            else:
                return ({}, {})

        mock_hc_process.side_effect = hc_process
        rewritten_env = {'resource_registry': {
            'OS::Foo::Bar': '/twd/outside.yaml',
            'OS::Foo::Baz': '/twd/templates/inside.yaml',
            'OS::Foo::Qux': '/twd/templates/abs.yaml',
            'OS::Foo::Quux': '/tmp/thtroot42/notouch.yaml',
            'OS::Foo::Corge': '/twd/templates/puppet/foo.yaml'
            }
        }
        myenv = {'resource_registry': {
            'OS::Foo::Bar': '../outside.yaml',
            'OS::Foo::Baz': './inside.yaml',
            'OS::Foo::Qux': '/tmp/thtroot/abs.yaml',
            'OS::Foo::Quux': '/tmp/thtroot42/notouch.yaml',
            'OS::Foo::Corge': '/tmp/thtroot/puppet/foo.yaml'
            }
        }
        mock_yaml_load.return_value = myenv

        utils.process_multiple_environments(self.created_env_files,
                                            self.tht_root,
                                            self.user_tht_root, None, False)

        mock_yaml_dump.assert_has_calls([mock.call(rewritten_env,
                                        default_flow_style=False)])


class GetTripleoAnsibleInventory(TestCase):

    def setUp(self):
        super(GetTripleoAnsibleInventory, self).setUp()
        self.inventory_file = ''
        self.ssh_user = 'heat_admin'
        self.stack = 'foo-overcloud'

    @mock.patch('tripleoclient.utils.get_tripleo_ansible_inventory',
                autospec=True)
    def test_get_tripleo_ansible_inventory(self, mock_inventory):

        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True

            self.cmd = utils.get_tripleo_ansible_inventory(
                inventory_file=self.inventory_file,
                ssh_user=self.ssh_user,
                stack=self.stack)

            self.cmd.take_action()

            mock_inventory.assert_called_once_with(
                inventory_file='',
                ssh_user='heat_admin',
                stack='foo-overcloud'
            )


class TestNormalizeFilePath(TestCase):

    @mock.patch('os.path.isfile', return_value=True)
    def test_norm_path_abs(self, mock_exists):
        self.assertEqual(
            utils.rel_or_abs_path('/foobar.yaml', '/tmp'),
            '/foobar.yaml')

    @mock.patch('os.path.isfile', side_effect=[False, True])
    def test_norm_path_rel(self, mock_exists):
        self.assertEqual(
            utils.rel_or_abs_path('baz/foobar.yaml', '/bar'),
            '/bar/baz/foobar.yaml')


class TestFetchRolesFile(TestCase):

    @mock.patch('os.path.exists', return_value=True)
    def test_fetch_roles_file(self, mock_exists):
        with tempfile.NamedTemporaryFile(mode='w') as roles_file:
            yaml.dump([{'name': 'Foobar'}], roles_file)
            with mock.patch('tripleoclient.utils.rel_or_abs_path') as mock_rf:
                mock_rf.return_value = roles_file.name
                self.assertEqual(utils.fetch_roles_file(roles_file.name),
                                 [{'name': 'Foobar'}])


class TestOvercloudNameScenarios(TestWithScenarios):
    scenarios = [
        ('kernel_default',
         dict(func=utils.overcloud_kernel,
              basename='overcloud-full',
              expected=('overcloud-full-vmlinuz', '.vmlinuz'))),
        ('kernel_arch',
         dict(func=utils.overcloud_kernel,
              basename='overcloud-full',
              arch='x86_64',
              expected=('x86_64-overcloud-full-vmlinuz', '.vmlinuz'))),
        ('kernel_arch_platform',
         dict(func=utils.overcloud_kernel,
              basename='overcloud-full',
              arch='x86_64',
              platform='SNB',
              expected=('SNB-x86_64-overcloud-full-vmlinuz', '.vmlinuz'))),
        ('kernel_platform',
         dict(func=utils.overcloud_kernel,
              basename='overcloud-full',
              platform='SNB',
              expected=('overcloud-full-vmlinuz', '.vmlinuz'))),
        ('ramdisk_default',
         dict(func=utils.overcloud_ramdisk,
              basename='overcloud-full',
              expected=('overcloud-full-initrd', '.initrd'))),
        ('ramdisk_arch',
         dict(func=utils.overcloud_ramdisk,
              basename='overcloud-full',
              arch='x86_64',
              expected=('x86_64-overcloud-full-initrd', '.initrd'))),
        ('ramdisk_arch_platform',
         dict(func=utils.overcloud_ramdisk,
              basename='overcloud-full',
              arch='x86_64',
              platform='SNB',
              expected=('SNB-x86_64-overcloud-full-initrd', '.initrd'))),
        ('ramdisk_platform',
         dict(func=utils.overcloud_ramdisk,
              basename='overcloud-full',
              platform='SNB',
              expected=('overcloud-full-initrd', '.initrd'))),
        ('image_default',
         dict(func=utils.overcloud_image,
              basename='overcloud-full',
              expected=('overcloud-full', '.raw'))),
        ('image_arch',
         dict(func=utils.overcloud_image,
              basename='overcloud-full',
              arch='x86_64',
              expected=('x86_64-overcloud-full', '.raw'))),
        ('image_arch_platform',
         dict(func=utils.overcloud_image,
              basename='overcloud-full',
              arch='x86_64',
              platform='SNB',
              expected=('SNB-x86_64-overcloud-full', '.raw'))),
        ('image_platform',
         dict(func=utils.overcloud_image,
              basename='overcloud-full',
              platform='SNB',
              expected=('overcloud-full', '.raw'))),
    ]

    def test_overcloud_params(self):
        kwargs = dict()
        for attr in ['arch', 'platform']:
            if hasattr(self, attr):
                kwargs[attr] = getattr(self, attr)

        if kwargs:
            observed = self.func(self.basename, **kwargs)
        else:
            observed = self.func(self.basename)

        self.assertEqual(self.expected, observed)


class TestDeployNameScenarios(TestWithScenarios):
    scenarios = [
        ('kernel_default',
         dict(func=utils.deploy_kernel,
              expected='agent.kernel')),
        ('kernel_arch',
         dict(func=utils.deploy_kernel,
              arch='x86_64',
              expected='x86_64/agent.kernel')),
        ('kernel_arch_platform',
         dict(func=utils.deploy_kernel,
              arch='x86_64',
              platform='SNB',
              expected='SNB-x86_64/agent.kernel')),
        ('kernel_platform',
         dict(func=utils.deploy_kernel,
              platform='SNB',
              expected='agent.kernel')),
        ('ramdisk_default',
         dict(func=utils.deploy_ramdisk,
              expected='agent.ramdisk')),
        ('ramdisk_arch',
         dict(func=utils.deploy_ramdisk,
              arch='x86_64',
              expected='x86_64/agent.ramdisk')),
        ('ramdisk_arch_platform',
         dict(func=utils.deploy_ramdisk,
              arch='x86_64',
              platform='SNB',
              expected='SNB-x86_64/agent.ramdisk')),
        ('ramdisk_platform',
         dict(func=utils.deploy_ramdisk,
              platform='SNB',
              expected='agent.ramdisk')),
    ]

    def test_deploy_params(self):
        kwargs = {}
        for attr in ['arch', 'platform']:
            if hasattr(self, attr):
                kwargs[attr] = getattr(self, attr)

        if kwargs:
            observed = self.func(**kwargs)
        else:
            observed = self.func()

        self.assertEqual(self.expected, observed)


class TestDeploymentPythonInterpreter(TestCase):
    def test_system_default(self):
        args = mock.MagicMock()
        args.deployment_python_interpreter = None
        py = utils.get_deployment_python_interpreter(args)
        self.assertEqual(py, sys.executable)

    def test_provided_interpreter(self):
        args = mock.MagicMock()
        args.deployment_python_interpreter = 'foo'
        py = utils.get_deployment_python_interpreter(args)
        self.assertEqual(py, 'foo')


class TestWaitApiPortReady(TestCase):
    @mock.patch('urllib.request.urlopen')
    def test_success(self, urlopen_mock):
        has_errors = utils.wait_api_port_ready(8080)
        self.assertFalse(has_errors)

    @mock.patch(
        'urllib.request.urlopen',
        side_effect=[
            url_error.HTTPError("", 201, None, None, None), socket.timeout,
            url_error.URLError("")
        ] * 10)
    @mock.patch('time.sleep')
    def test_throw_exception_at_max_retries(self, urlopen_mock, sleep_mock):
        with self.assertRaises(RuntimeError):
            utils.wait_api_port_ready(8080)
        self.assertEqual(urlopen_mock.call_count, 30)
        self.assertEqual(sleep_mock.call_count, 30)

    @mock.patch(
        'urllib.request.urlopen',
        side_effect=[
            socket.timeout,
            url_error.URLError(""),
            url_error.HTTPError("", 201, None, None, None), None
        ])
    @mock.patch('time.sleep')
    def test_recovers_from_exception(self, urlopen_mock, sleep_mock):
        self.assertFalse(utils.wait_api_port_ready(8080))
        self.assertEqual(urlopen_mock.call_count, 4)
        self.assertEqual(sleep_mock.call_count, 4)

    @mock.patch(
        'urllib.request.urlopen',
        side_effect=[
            socket.timeout,
            url_error.URLError(""),
            url_error.HTTPError("", 300, None, None, None)
        ] * 10)
    @mock.patch('time.sleep')
    def test_recovers_from_multiple_choices_error_code(self, urlopen_mock,
                                                       sleep_mock):
        self.assertTrue(utils.wait_api_port_ready(8080))
        self.assertEqual(urlopen_mock.call_count, 3)
        self.assertEqual(sleep_mock.call_count, 3)

    @mock.patch('urllib.request.urlopen', side_effect=NameError)
    @mock.patch('time.sleep')
    def test_dont_retry_at_unknown_exception(self, urlopen_mock, sleep_mock):
        with self.assertRaises(NameError):
            utils.wait_api_port_ready(8080)
        self.assertEqual(urlopen_mock.call_count, 1)
        self.assertEqual(sleep_mock.call_count, 1)


class TestCheckHostname(TestCase):
    @mock.patch('tripleoclient.utils.run_command')
    def test_hostname_ok(self, mock_run):
        mock_run.side_effect = ['host.domain', 'host.domain']
        mock_open_ctx = mock.mock_open(read_data='127.0.0.1 host.domain')
        with mock.patch('tripleoclient.utils.open', mock_open_ctx):
            utils.check_hostname(False)
        run_calls = [
            mock.call(['hostnamectl', '--static'], name='hostnamectl'),
            mock.call(['hostnamectl', '--transient'], name='hostnamectl')]
        self.assertEqual(mock_run.mock_calls, run_calls)

    @mock.patch('tripleoclient.utils.run_command')
    def test_hostname_fix_hosts_ok(self, mock_run):
        mock_run.side_effect = ['host.domain', 'host.domain', '']
        mock_open_ctx = mock.mock_open(read_data='')
        with mock.patch('tripleoclient.utils.open', mock_open_ctx):
            utils.check_hostname(True)
        sed_cmd = 'sed -i "s/127.0.0.1\\(\\s*\\)/127.0.0.1\\\\1host.domain ' \
                  'host /" /etc/hosts'
        run_calls = [
            mock.call(['hostnamectl', '--static'], name='hostnamectl'),
            mock.call(['hostnamectl', '--transient'], name='hostnamectl'),
            mock.call(['sudo', '/bin/bash', '-c', sed_cmd],
                      name='hostname-to-etc-hosts')]
        import pprint
        pprint.pprint(mock_run.mock_calls)
        self.assertEqual(mock_run.mock_calls, run_calls)

    @mock.patch('tripleoclient.utils.run_command')
    def test_hostname_mismatch_fail(self, mock_run):
        mock_run.side_effect = ['host.domain', '']
        self.assertRaises(RuntimeError, utils.check_hostname)

    @mock.patch('tripleoclient.utils.run_command')
    def test_hostname_short_fail(self, mock_run):
        mock_run.side_effect = ['host', 'host']
        self.assertRaises(RuntimeError, utils.check_hostname)


class TestCheckEnvForProxy(TestCase):
    def test_no_proxy(self):
        utils.check_env_for_proxy()

    @mock.patch.dict(os.environ,
                     {'http_proxy': 'foo:1111',
                      'no_proxy': 'foo'})
    def test_http_proxy_ok(self):
        utils.check_env_for_proxy(['foo'])

    @mock.patch.dict(os.environ,
                     {'https_proxy': 'bar:1111',
                      'no_proxy': 'foo,bar'})
    def test_https_proxy_ok(self):
        utils.check_env_for_proxy(['foo', 'bar'])

    @mock.patch.dict(os.environ,
                     {'http_proxy': 'foo:1111',
                      'https_proxy': 'bar:1111',
                      'no_proxy': 'foobar'})
    def test_proxy_fail(self):
        self.assertRaises(RuntimeError,
                          utils.check_env_for_proxy,
                          ['foo', 'bar'])

    @mock.patch.dict(os.environ,
                     {'http_proxy': 'foo:1111',
                      'https_proxy': 'bar:1111',
                      'no_proxy': 'foobar'})
    def test_proxy_fail_partial_match(self):
        self.assertRaises(RuntimeError,
                          utils.check_env_for_proxy,
                          ['foo', 'bar'])

    @mock.patch.dict(os.environ,
                     {'http_proxy': 'foo:1111',
                      'https_proxy': 'bar:1111'})
    def test_proxy_fail_no_proxy_unset(self):
        self.assertRaises(RuntimeError,
                          utils.check_env_for_proxy,
                          ['foo', 'bar'])


class TestConfigParser(TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        if self.tmp_dir:
            shutil.rmtree(self.tmp_dir)
            self.tmp_dir = None

    def test_get_config_value(self):
        cfg = ConfigParser()
        cfg.add_section('foo')
        cfg.set('foo', 'bar', 'baz')
        config = utils.get_from_cfg(cfg, 'bar', 'foo')
        self.assertEqual(config, 'baz')

    def test_getboolean_config_value(self):
        cfg = ConfigParser()
        cfg.add_section('foo')
        test_data_set = [
            (True, 'True'),
            (True, 'true'),
            (False, 'False'),
            (False, 'false')
        ]
        for test_data in test_data_set:
            expected_value, config_value = test_data
            cfg.set('foo', 'bar', config_value)
            obtained_value = utils.getboolean_from_cfg(cfg, 'bar', 'foo')
            self.assertEqual(obtained_value, expected_value)

    def test_getboolean_bad_config_value(self):
        cfg = ConfigParser()
        cfg.add_section('foo')
        cfg.set('foo', 'bar', 'I am not a boolean')
        self.assertRaises(exceptions.NotFound,
                          utils.getboolean_from_cfg,
                          cfg, 'bar', 'foo')

    def test_get_config_value_multiple_files(self):
        _, cfile1_name = tempfile.mkstemp(dir=self.tmp_dir, text=True)
        _, cfile2_name = tempfile.mkstemp(dir=self.tmp_dir, text=True)
        cfiles = [cfile1_name, cfile2_name]
        cfg = ConfigParser()
        cfg.add_section('foo')
        cfg.set('foo', 'bar', 'baz')
        with open(cfile1_name, 'w') as fp:
            cfg.write(fp)
        cfg.set('foo', 'bar', 'boop')
        with open(cfile2_name, 'w') as fp:
            cfg.write(fp)
        cfgs = utils.get_read_config(cfiles)
        config = utils.get_from_cfg(cfgs, 'bar', 'foo')
        self.assertEqual(config, 'boop')

    def test_get_config_value_bad_file(self):
        self.assertRaises(AttributeError,
                          utils.get_from_cfg,
                          'does-not-exist', 'bar', 'foo')


class TestGetLocalTimezone(TestCase):
    @mock.patch('tripleoclient.utils.run_command')
    def test_get_local_timezone(self, run_mock):
        run_mock.return_value = "" \
            "               Local time: Thu 2019-03-14 12:05:49 EDT\n" \
            "           Universal time: Thu 2019-03-14 16:05:49 UTC\n" \
            "                 RTC time: Thu 2019-03-14 16:15:50\n" \
            "                Time zone: America/New_York (EDT, -0400)\n" \
            "System clock synchronized: yes\n" \
            "              NTP service: active\n"\
            "          RTC in local TZ: no\n"
        self.assertEqual('America/New_York', utils.get_local_timezone())

    @mock.patch('tripleoclient.utils.run_command')
    def test_get_local_timezone_bad_timedatectl(self, run_mock):
        run_mock.return_value = "meh"
        self.assertEqual('UTC', utils.get_local_timezone())

    @mock.patch('tripleoclient.utils.run_command')
    def test_get_local_timezone_bad_timezone_line(self, run_mock):
        run_mock.return_value = "" \
            "                Time zone: "
        self.assertEqual('UTC', utils.get_local_timezone())


class TestParseExtraVars(TestCase):
    def test_simple_case_text_format(self):
        input_parameter = ['key1=val1', 'key2=val2 key3=val3']
        expected = {
            'key1': 'val1',
            'key2': 'val2',
            'key3': 'val3'
        }
        result = utils.parse_extra_vars(input_parameter)
        self.assertEqual(result, expected)

    def test_simple_case_json_format(self):
        input_parameter = ['{"key1": "val1", "key2": "val2"}']
        expected = {
            'key1': 'val1',
            'key2': 'val2'
        }
        result = utils.parse_extra_vars(input_parameter)
        self.assertEqual(result, expected)

    def test_multiple_format(self):
        input_parameter = [
            'key1=val1', 'key2=val2 key3=val3',
            '{"key4": "val4", "key5": "val5"}']
        expected = {
            'key1': 'val1',
            'key2': 'val2',
            'key3': 'val3',
            'key4': 'val4',
            'key5': 'val5'
        }
        result = utils.parse_extra_vars(input_parameter)
        self.assertEqual(result, expected)

    def test_same_key(self):
        input_parameter = [
            'key1=val1', 'key2=val2 key3=val3',
            '{"key1": "other_value", "key5": "val5"}']
        expected = {
            'key1': 'other_value',
            'key2': 'val2',
            'key3': 'val3',
            'key5': 'val5'
        }
        result = utils.parse_extra_vars(input_parameter)
        self.assertEqual(result, expected)

    def test_with_multiple_space(self):
        input_parameter = ['key1=val1', ' key2=val2   key3=val3 ']
        expected = {
            'key1': 'val1',
            'key2': 'val2',
            'key3': 'val3'
        }
        result = utils.parse_extra_vars(input_parameter)
        self.assertEqual(result, expected)

    def test_invalid_string(self):
        input_parameter = [
            'key1=val1', 'key2=val2 key3=val3',
            '{"key1": "other_value", "key5": "val5']
        self.assertRaises(
            ValueError, utils.parse_extra_vars, input_parameter)

    def test_invalid_format(self):
        input_parameter = ['key1 val1']
        self.assertRaises(
            ValueError, utils.parse_extra_vars, input_parameter)


class TestGeneralUtils(base.TestCommand):

    def setUp(self):
        super(TestGeneralUtils, self).setUp()

    @mock.patch('tripleoclient.utils.safe_write')
    def test_update_deployment_status(self, mock_write):
        mock_status = {
            'deployment_status': 'TESTING'
        }
        utils.update_deployment_status(
            'overcloud',
            mock_status,
            ''
        )
        mock_write.assert_called()

    def test_playbook_limit_parse(self):
        limit_nodes = 'controller0, compute0:compute1,!compute2'
        limit_hosts_expected = 'controller0:compute0:compute1:!compute2'
        limit_hosts_actual = utils.playbook_limit_parse(limit_nodes)
        self.assertEqual(limit_hosts_actual, limit_hosts_expected)


class TestTempDirs(base.TestCase):

    @mock.patch('tripleoclient.utils.tempfile.mkdtemp',
                autospec=True,
                return_value='foo')
    @mock.patch('tripleoclient.utils.Pushd', autospec=True)
    def test_init_dirpath(self, mock_pushd, mock_mkdtemp):

        utils.TempDirs(dir_path='bar')

        mock_pushd.assert_called_once_with(directory='foo')
        mock_mkdtemp.assert_called_once_with(
            dir='bar',
            prefix='tripleo')

    @mock.patch('tripleoclient.utils.tempfile.mkdtemp',
                autospec=True,
                return_value='foo')
    @mock.patch('tripleoclient.utils.Pushd', autospec=True,)
    def test_init_no_prefix(self, mock_pushd, mock_mkdtemp):

        utils.TempDirs(dir_prefix=None)

        mock_pushd.assert_called_once_with(directory='foo')
        mock_mkdtemp.assert_called_once_with()

    @mock.patch('tripleoclient.utils.LOG.warning', autospec=True,)
    @mock.patch('tripleoclient.utils.tempfile.mkdtemp',
                autospec=True,
                return_value='foo')
    @mock.patch('tripleoclient.utils.Pushd', autospec=True)
    def test_exit_warning(self, mock_pushd, mock_mkdtemp, mock_log):

        temp_dirs = utils.TempDirs(cleanup=False, chdir=False)

        temp_dirs.__exit__()

        mock_log.assert_called_once_with(
            "Not cleaning temporary directory [ foo ]")


class TestGetCtlplaneAttrs(base.TestCase):

    @mock.patch('openstack.connect', autospec=True)
    @mock.patch.object(openstack.connection, 'Connection', autospec=True)
    def test_get_ctlplane_attrs_no_network(self, mock_conn, mock_connect):
        mock_connect.return_value = mock_conn
        mock_conn.network.find_network.return_value = None
        expected = dict()
        self.assertEqual(expected, utils.get_ctlplane_attrs())

    @mock.patch('openstack.connect', autospec=True)
    def test_get_ctlplane_attrs_no_config(self, mock_connect):
        mock_connect.side_effect = openstack.exceptions.ConfigException

        expected = dict()
        self.assertEqual(expected, utils.get_ctlplane_attrs())

    @mock.patch('openstack.connect', autospec=True)
    @mock.patch.object(openstack.connection, 'Connection', autospec=True)
    def test_get_ctlplane_attrs(self, mock_conn, mock_connect):
        mock_connect.return_value = mock_conn
        fake_network = fakes.FakeNeutronNetwork(
            name='net_name',
            mtu=1440,
            dns_domain='ctlplane.localdomain.',
            tags=[],
            subnet_ids=['subnet_id'])
        fake_subnet = fakes.FakeNeutronSubnet(
            id='subnet_id',
            name='subnet_name',
            cidr='192.168.24.0/24',
            gateway_ip='192.168.24.1',
            host_routes=[
                {'destination': '192.168.25.0/24', 'nexthop': '192.168.24.1'}],
            dns_nameservers=['192.168.24.254'],
            ip_version=4
        )
        mock_conn.network.find_network.return_value = fake_network
        mock_conn.network.get_subnet.return_value = fake_subnet
        expected = {
            'network': {
                'dns_domain': 'ctlplane.localdomain.',
                'mtu': 1440,
                'name': 'net_name',
                'tags': []},
            'subnets': {
                'subnet_name': {
                    'cidr': '192.168.24.0/24',
                    'dns_nameservers': ['192.168.24.254'],
                    'gateway_ip': '192.168.24.1',
                    'host_routes': [{'destination': '192.168.25.0/24',
                                     'nexthop': '192.168.24.1'}],
                    'ip_version': 4,
                    'name': 'subnet_name'}
            }
        }
        self.assertEqual(expected, utils.get_ctlplane_attrs())


class TestGetHostEntry(base.TestCase):

    @mock.patch('subprocess.Popen', autospec=True)
    def test_get_undercloud_host_entry(self, mock_popen):
        mock_process = mock.Mock()
        mock_hosts = {
            'fd12::1 uc.ctlplane.localdomain uc.ctlplane':
                'fd12::1 uc.ctlplane.localdomain uc.ctlplane',
            'fd12::1 uc.ctlplane.localdomain uc.ctlplane\n'
            'fd12::1 uc.ctlplane.localdomain uc.ctlplane':
                'fd12::1 uc.ctlplane.localdomain uc.ctlplane',
            '1.2.3.4 uc.ctlplane foo uc.ctlplane bar uc.ctlplane':
                '1.2.3.4 uc.ctlplane foo bar'
        }
        for value, expected in mock_hosts.items():
            mock_process.communicate.return_value = (value, '')
            mock_process.returncode = 0
            mock_popen.return_value = mock_process
            self.assertEqual(expected, utils.get_undercloud_host_entry())


class TestProhibitedOverrides(base.TestCommand):

    def setUp(self):
        super(TestProhibitedOverrides, self).setUp()
        self.tmp_dir = self.useFixture(fixtures.TempDir())

    def test_extend_protected_overrides(self):
        protected_overrides = {
            'registry_entries': {'OS::Foo::Bar': ['foo_bar_file']}}
        output_path = self.tmp_dir.join('env-file.yaml')
        fake_env = {
            'parameter_defaults': {
                'DeployedNetworkEnvironment': {'foo': 'bar'}},
            'resource_registry': {
                'OS::TripleO::Network': 'foo'}
        }
        with open(output_path, 'w') as temp_file:
            yaml.safe_dump(fake_env, temp_file)

        utils.extend_protected_overrides(protected_overrides, output_path)
        self.assertEqual({
            'registry_entries': {
                'OS::Foo::Bar': ['foo_bar_file'],
                'OS::TripleO::Network': [output_path]}},
            protected_overrides)

    def test_check_prohibited_overrides_with_conflict(self):
        protected_overrides = {
            'registry_entries': {'OS::Foo::Bar': ['foo_bar_file']}}
        user_env = self.tmp_dir.join('env-file01.yaml')
        fake_env = {'parameter_defaults': {'foo_param': {'foo': 'bar'}},
                    'resource_registry': {'OS::Foo::Bar': 'foo'}}
        with open(user_env, 'w') as temp_file:
            yaml.safe_dump(fake_env, temp_file)

        self.assertRaises(exceptions.DeploymentError,
                          utils.check_prohibited_overrides,
                          protected_overrides, [(user_env, user_env)])
        self.assertRaisesRegex(
            exceptions.DeploymentError,
            'ERROR: Protected resource registry overrides detected!',
            utils.check_prohibited_overrides,
            protected_overrides, [(user_env, user_env)])

    def test_check_prohibited_overrides_with_no_conflict(self):
        protected_overrides = {
            'registry_entries': {'OS::Foo::Bar': ['foo_bar_file']}}
        user_env = self.tmp_dir.join('env-file01.yaml')
        fake_env = {'parameter_defaults': {'bar_param': {'bar': 'foo'}},
                    'resource_registry': {'OS::Bar::Foo': 'bar'}}
        with open(user_env, 'w') as temp_file:
            yaml.safe_dump(fake_env, temp_file)

        self.assertIsNone(
            utils.check_prohibited_overrides(protected_overrides,
                                             [(user_env, user_env)]))

    def test_check_neutron_resources(self):
        resource_registry = {
            "a": "A",
            "neutron": "OS::Neutron::Port"
        }
        environment = dict(resource_registry=resource_registry)
        self.assertRaises(
            exceptions.InvalidConfiguration,
            utils.check_neutron_resources,
            environment)
        resource_registry["neutron"] = "OS::Neutron::Network"
        self.assertRaises(
            exceptions.InvalidConfiguration,
            utils.check_neutron_resources,
            environment)
        resource_registry.pop("neutron")
        self.assertIsNone(utils.check_neutron_resources(environment))


class TestParseContainerImagePrepare(TestCase):

    fake_env = {'parameter_defaults': {'ContainerImagePrepare':
                                       [{'push_destination': 'foo.com', 'set':
                                         {'ceph_image': 'ceph',
                                          'ceph_namespace': 'quay.io:443/ceph',
                                          'ceph_tag': 'latest'}}],
                                       'ContainerImageRegistryCredentials':
                                       {'quay.io:443': {'quay_username':
                                                        'quay_password'}}}}

    def test_parse_container_image_prepare(self):
        key = 'ContainerImagePrepare'
        keys = ['ceph_namespace', 'ceph_image', 'ceph_tag']
        reg_expected = {'ceph_image': 'ceph',
                        'ceph_namespace': 'quay.io:443/ceph',
                        'ceph_tag': 'latest'}
        with tempfile.NamedTemporaryFile(mode='w') as cfgfile:
            yaml.safe_dump(self.fake_env, cfgfile)
            reg_actual = \
                utils.parse_container_image_prepare(key, keys,
                                                    cfgfile.name)
        self.assertEqual(reg_actual, reg_expected)

    def test_parse_container_image_prepare_push_dest(self):
        key = 'ContainerImagePrepare'
        keys = ['ceph_namespace', 'ceph_image', 'ceph_tag']
        push_sub_keys = ['ceph_namespace']
        reg_expected = {'ceph_image': 'ceph',
                        'ceph_namespace': 'foo.com/ceph',
                        'ceph_tag': 'latest',
                        'push_destination_boolean': True}
        with tempfile.NamedTemporaryFile(mode='w') as cfgfile:
            yaml.safe_dump(self.fake_env, cfgfile)
            reg_actual = \
                utils.parse_container_image_prepare(key, keys,
                                                    cfgfile.name,
                                                    push_sub_keys)
        self.assertEqual(reg_actual, reg_expected)

    def test_parse_container_image_prepare_push_dest_no_slash(self):
        # Cover case from https://bugs.launchpad.net/tripleo/+bug/1979554
        key = 'ContainerImagePrepare'
        keys = ['ceph_namespace', 'ceph_image', 'ceph_tag']
        push_sub_keys = ['ceph_namespace']
        reg_expected = {'ceph_image': 'ceph',
                        'ceph_namespace': 'foo.com',
                        'ceph_tag': 'latest',
                        'push_destination_boolean': True}
        local_fake_env = self.fake_env
        # Remove '/ceph' from 'quay.io:443/ceph' in local copy to
        # make sure parse_container_image_prepare() can handle it
        local_fake_env['parameter_defaults'][
            'ContainerImagePrepare'][0]['set']['ceph_namespace'] \
            = 'quay.io:443'
        with tempfile.NamedTemporaryFile(mode='w') as cfgfile:
            yaml.safe_dump(local_fake_env, cfgfile)
            reg_actual = \
                utils.parse_container_image_prepare(key, keys,
                                                    cfgfile.name,
                                                    push_sub_keys)
        self.assertEqual(reg_actual, reg_expected)

    def test_parse_container_image_prepare_credentials(self):
        key = 'ContainerImageRegistryCredentials'
        keys = ['quay.io:443/ceph']
        reg_expected = {'registry_url': 'quay.io:443',
                        'registry_username': 'quay_username',
                        'registry_password': 'quay_password'}
        with tempfile.NamedTemporaryFile(mode='w') as cfgfile:
            yaml.safe_dump(self.fake_env, cfgfile)
            reg_actual = \
                utils.parse_container_image_prepare(key, keys,
                                                    cfgfile.name)
        self.assertEqual(reg_actual, reg_expected)


class TestWorkingDirDefaults(base.TestCase):

    def setUp(self):
        super(TestWorkingDirDefaults, self).setUp()
        self.working_dir = tempfile.mkdtemp()
        self.stack = 'overcloud'
        self.wd_roles_file = os.path.join(
            self.working_dir,
            utils.constants.WD_DEFAULT_ROLES_FILE_NAME.format(self.stack))
        self.wd_networks_file = os.path.join(
            self.working_dir,
            utils.constants.WD_DEFAULT_NETWORKS_FILE_NAME.format(self.stack))
        self.wd_vip_file = os.path.join(
            self.working_dir,
            utils.constants.WD_DEFAULT_VIP_FILE_NAME.format(self.stack))
        self.wd_barametal_file = os.path.join(
            self.working_dir,
            utils.constants.WD_DEFAULT_BAREMETAL_FILE_NAME.format(self.stack))

    def tearDown(self):
        super(TestWorkingDirDefaults, self).tearDown()
        shutil.rmtree(self.working_dir)

    @mock.patch.object(utils, 'rewrite_ansible_playbook_paths', autospec=True)
    @mock.patch.object(shutil, 'copy', autospec=True)
    def test_update_working_dir_defaults(self, mock_shutil_copy,
                                         mock_rewrite_ansible_playbook_paths):
        args = mock.Mock()
        args.stack = self.stack
        args.templates = '/tht_root'
        args.roles_file = '/dir/roles_file.yaml'
        args.networks_file = '/dir/networks_file.yaml'
        args.vip_file = '/dir/vip_file.yaml'
        args.baremetal_deployment = '/dir/baremetal_deployment.yaml'

        utils.update_working_dir_defaults(self.working_dir, args)

        mock_shutil_copy.assert_has_calls(
            [mock.call(args.baremetal_deployment, self.wd_barametal_file),
             mock.call(args.roles_file, self.wd_roles_file),
             mock.call(args.networks_file, self.wd_networks_file),
             mock.call(args.vip_file, self.wd_vip_file)])

    def test_rewrite_ansible_playbook_paths(self):
        src = '/rel/path/baremetal.yaml'
        dest = self.wd_barametal_file
        roles = '''
        - name: Controller
          ansible_playbooks:
          - playbook: controller-playbook.yaml
          - playbook: /abs/path/controller-playbook.yaml
        - name: Compute
          ansible_playbooks:
          - playbook: compute-playbook.yaml
          - playbook: /abs/path/compute-playbook.yaml
        '''
        with open(dest, 'w') as f:
            f.write(roles)
        utils.rewrite_ansible_playbook_paths(src, dest)
        with open(dest, 'r') as f:
            data = yaml.safe_load(f.read())
        self.assertEqual(data[0]['ansible_playbooks'][0]['playbook'],
                         '/rel/path/controller-playbook.yaml')
        self.assertEqual(data[0]['ansible_playbooks'][1]['playbook'],
                         '/abs/path/controller-playbook.yaml')
        self.assertEqual(data[1]['ansible_playbooks'][0]['playbook'],
                         '/rel/path/compute-playbook.yaml')
        self.assertEqual(data[1]['ansible_playbooks'][1]['playbook'],
                         '/abs/path/compute-playbook.yaml')


class TestGetCephNetworks(TestCase):

    fake_network_data_default = []

    fake_network_data = [
        {'name': 'StorageCloud0',
         'name_lower': 'storage',
         'ip_subnet': '172.16.1.0/24',
         'ipv6_subnet': 'fd00:fd00:fd00:3000::/64'},
        {'name': 'StorageMgmtCloud0',
         'name_lower': 'storage_mgmt',
         'ip_subnet': '172.16.3.0/24',
         'ipv6_subnet': 'fd00:fd00:fd00:4000::/64'}]

    fake_network_data_subnet = [
        {'name': 'Storage',
         'name_lower': 'storage_cloud_0',
         'service_net_map_replace': 'storage',
         'subnets':
         {'storage_cloud_0_subnet_0':
          {'ip_subnet': '172.16.11.0/24'}}},
        {'name': 'Storage',
         'name_lower': 'storage_mgmt_cloud_0',
         'service_net_map_replace': 'storage_mgmt',
         'subnets':
         {'storage_mgmt_cloud_0_subnet_0':
          {'ip_subnet': '172.16.12.0/24'}}}]

    fake_double_subnet = yaml.safe_load('''
    - name: StorageMgmtCloud0
      name_lower: storage_mgmt_cloud_0
      service_net_map_replace: storage_mgmt
      subnets:
        storage_mgmt_cloud_0_subnet12:
          ip_subnet: '172.16.12.0/24'
        storage_mgmt_cloud_0_subnet13:
          ip_subnet: '172.16.13.0/24'
    - name: StorageCloud0
      name_lower: storage_cloud_0
      service_net_map_replace: storage
      subnets:
        storage_cloud_0_subnet14:
          ip_subnet: '172.16.14.0/24'
        storage_cloud_0_subnet15:
          ip_subnet: '172.16.15.0/24'
    ''')

    def test_network_data_default(self):
        expected = {'cluster_network': '192.168.24.0/24',
                    'cluster_network_name': 'ctlplane',
                    'public_network': '192.168.24.0/24',
                    'public_network_name': 'ctlplane',
                    'ms_bind_ipv4': True, 'ms_bind_ipv6': False}
        with tempfile.NamedTemporaryFile(mode='w') as cfgfile:
            yaml.safe_dump(self.fake_network_data_default, cfgfile)
            net_name = utils.get_ceph_networks(cfgfile.name,
                                               'storage', 'storage_mgmt')
        self.assertEqual(expected, net_name)

    def test_network_data(self):
        expected = {'cluster_network': '172.16.3.0/24',
                    'cluster_network_name': 'storage_mgmt',
                    'public_network': '172.16.1.0/24',
                    'public_network_name': 'storage',
                    'ms_bind_ipv4': True, 'ms_bind_ipv6': False}
        with tempfile.NamedTemporaryFile(mode='w') as cfgfile:
            yaml.safe_dump(self.fake_network_data, cfgfile)
            net_name = utils.get_ceph_networks(cfgfile.name,
                                               'storage', 'storage_mgmt')
        self.assertEqual(expected, net_name)

    def test_network_data_v6(self):
        expected = {'cluster_network': 'fd00:fd00:fd00:4000::/64',
                    'cluster_network_name': 'storage_mgmt',
                    'public_network': 'fd00:fd00:fd00:3000::/64',
                    'public_network_name': 'storage',
                    'ms_bind_ipv4': False, 'ms_bind_ipv6': True}
        [net.setdefault('ipv6', True) for net in self.fake_network_data]
        with tempfile.NamedTemporaryFile(mode='w') as cfgfile:
            yaml.safe_dump(self.fake_network_data, cfgfile)
            net_name = utils.get_ceph_networks(cfgfile.name,
                                               'storage', 'storage_mgmt')
        self.assertEqual(expected, net_name)

    def test_network_data_subnets(self):
        expected = {'cluster_network': '172.16.12.0/24',
                    'cluster_network_name': 'storage_mgmt_cloud_0',
                    'public_network': '172.16.11.0/24',
                    'public_network_name': 'storage_cloud_0',
                    'ms_bind_ipv4': True, 'ms_bind_ipv6': False}
        with tempfile.NamedTemporaryFile(mode='w') as cfgfile:
            yaml.safe_dump(self.fake_network_data_subnet, cfgfile)
            net_name = utils.get_ceph_networks(cfgfile.name,
                                               'storage', 'storage_mgmt')
        self.assertEqual(expected, net_name)

    def test_network_data_subnets_override_names(self):
        expected = {'cluster_network': '172.16.12.0/24',
                    'cluster_network_name': 'storage_mgmt_cloud_0',
                    'public_network': '172.16.11.0/24',
                    'public_network_name': 'storage_cloud_0',
                    'ms_bind_ipv4': True, 'ms_bind_ipv6': False}
        with tempfile.NamedTemporaryFile(mode='w') as cfgfile:
            yaml.safe_dump(self.fake_network_data_subnet, cfgfile)
            net_name = utils.get_ceph_networks(cfgfile.name,
                                               'storage_cloud_0',
                                               'storage_mgmt_cloud_0')
        self.assertEqual(expected, net_name)

    def test_network_data_subnets_multiple(self):
        expected = {'cluster_network': '172.16.12.0/24,172.16.13.0/24',
                    'cluster_network_name': 'storage_mgmt_cloud_0',
                    'public_network': '172.16.14.0/24,172.16.15.0/24',
                    'public_network_name': 'storage_cloud_0',
                    'ms_bind_ipv4': True, 'ms_bind_ipv6': False}
        with tempfile.NamedTemporaryFile(mode='w') as cfgfile:
            yaml.safe_dump(self.fake_double_subnet, cfgfile)
            net_name = utils.get_ceph_networks(cfgfile.name,
                                               'storage', 'storage_mgmt')
        self.assertEqual(expected, net_name)


class TestGetHostsFromCephSpec(TestCase):

    specs = []
    specs.append(yaml.safe_load('''
    addr: 192.168.24.13
    hostname: ceph-0
    labels:
    - _admin
    - mon
    - mgr
    service_type: host
    '''))

    specs.append(yaml.safe_load('''
    addr: 192.168.24.20
    hostname: ceph-1
    labels:
    - _admin
    - mon
    - mgr
    service_type: host
    '''))

    specs.append(yaml.safe_load('''
    addr: 192.168.24.16
    hostname: ceph-2
    labels:
    - _admin
    - mon
    - mgr
    service_type: host
    '''))

    specs.append(yaml.safe_load('''
    addr: 192.168.24.14
    hostname: ceph-3
    labels:
    - osd
    service_type: host
    '''))

    specs.append(yaml.safe_load('''
    addr: 192.168.24.21
    hostname: ceph-4
    labels:
    - osd
    service_type: host
    '''))

    specs.append(yaml.safe_load('''
    addr: 192.168.24.17
    hostname: ceph-5
    labels:
    - osd
    service_type: host
    '''))

    specs.append(yaml.safe_load('''
    placement:
      hosts:
      - ceph-0
      - ceph-1
      - ceph-2
    service_id: mon
    service_name: mon
    service_type: mon
    '''))

    specs.append(yaml.safe_load('''
    placement:
      hosts:
      - ceph-0
      - ceph-1
      - ceph-2
    service_id: mgr
    service_name: mgr
    service_type: mgr
    '''))

    specs.append(yaml.safe_load('''
    data_devices:
      all: true
    placement:
      hosts:
      - ceph-3
      - ceph-4
      - ceph-5
    service_id: default_drive_group
    service_name: osd.default_drive_group
    service_type: osd
    '''))

    def test_get_hosts_from_ceph_spec(self):
        expected = {'ceph__admin': ['ceph-0', 'ceph-1', 'ceph-2'],
                    'ceph_mon': ['ceph-0', 'ceph-1', 'ceph-2'],
                    'ceph_mgr': ['ceph-0', 'ceph-1', 'ceph-2'],
                    'ceph_osd': ['ceph-3', 'ceph-4', 'ceph-5'],
                    'ceph_non_admin': ['ceph-3', 'ceph-4', 'ceph-5']}

        cfgfile = tempfile.NamedTemporaryFile()
        for spec in self.specs:
            with open(cfgfile.name, 'a') as f:
                f.write('---\n')
                f.write(yaml.safe_dump(spec))
        hosts = utils.get_host_groups_from_ceph_spec(cfgfile.name,
                                                     prefix='ceph_')
        cfgfile.close()

        self.assertEqual(expected, hosts)

    def test_get_addr_from_ceph_spec(self):
        expected = {'_admin': ['192.168.24.13',
                               '192.168.24.20',
                               '192.168.24.16'],
                    'mon': ['192.168.24.13',
                            '192.168.24.20',
                            '192.168.24.16'],
                    'mgr': ['192.168.24.13',
                            '192.168.24.20',
                            '192.168.24.16'],
                    'osd': ['192.168.24.14',
                            '192.168.24.21',
                            '192.168.24.17']}

        cfgfile = tempfile.NamedTemporaryFile()
        for spec in self.specs:
            with open(cfgfile.name, 'a') as f:
                f.write('---\n')
                f.write(yaml.safe_dump(spec))
        hosts = utils.get_host_groups_from_ceph_spec(cfgfile.name,
                                                     key='addr',
                                                     get_non_admin=False)
        cfgfile.close()

        self.assertEqual(expected, hosts)


class TestProcessCephDaemons(TestCase):

    def test_process_ceph_daemons(self):

        daemon_opt = yaml.safe_load('''
        ceph_nfs:
          cephfs_data: manila_data
          cephfs_metadata: manila_metadata
        ''')

        expected = {
         'tripleo_cephadm_daemon_ceph_nfs': True,
         'cephfs_data': 'manila_data',
         'cephfs_metadata': 'manila_metadata'
        }

        # daemon_input = tempfile.NamedTemporaryFile()
        with tempfile.NamedTemporaryFile(mode='w') as f:
            yaml.safe_dump(daemon_opt, f)
            found = utils.process_ceph_daemons(f.name)

        self.assertEqual(found, expected)


class TestCheckDeployBackups(TestCase):

    @mock.patch('tripleoclient.utils.LOG')
    @mock.patch('prettytable.PrettyTable')
    @mock.patch('os.statvfs')
    @mock.patch('glob.iglob')
    def test_check_deploy_backups(
            self, mock_iglob,
            mock_statvfs, mock_prettytable, mock_log):
        working_dir = '/home/foo/overcloud-deploy/overcloud'
        mock_iglob.return_value = ['x', 'y', 'z']
        mock_table = mock.Mock()
        mock_prettytable.return_value = mock_table
        mock_stat_return1 = mock.Mock()
        mock_stat_return2 = mock.Mock()
        mock_stat_return3 = mock.Mock()
        mock_stat_return1.st_size = 1024
        mock_stat_return2.st_size = 2048
        mock_stat_return3.st_size = 4096
        mock_statvfs_return = mock.Mock()
        mock_statvfs.return_value = mock_statvfs_return
        mock_statvfs_return.f_frsize = 1024
        mock_statvfs_return.f_blocks = 100
        mock_statvfs_return.f_bfree = 10

        with mock.patch('os.stat') as mock_stat:
            mock_stat.side_effect = [
                mock_stat_return1,
                mock_stat_return2,
                mock_stat_return3]
            utils.check_deploy_backups(working_dir)

        self.assertEqual(3, mock_table.add_row.call_count)
        self.assertEqual(1.0, mock_table.add_row.call_args_list[0][0][0][1])
        self.assertEqual(2.0, mock_table.add_row.call_args_list[1][0][0][1])
        self.assertEqual(4.0, mock_table.add_row.call_args_list[2][0][0][1])
        mock_statvfs.assert_called_once_with('z')
        self.assertIn(
            'Disk usage 90.00% exceeds 80% percent of disk size',
            mock_log.warning.call_args_list[0][0][0])

        mock_log.reset_mock()
        mock_stat_return3.st_size = 81920

        with mock.patch('os.stat') as mock_stat:
            mock_stat.side_effect = [
                mock_stat_return1,
                mock_stat_return2,
                mock_stat_return3]
            utils.check_deploy_backups(working_dir)
        self.assertIn(
            'Deploy backup files disk usage 90.00% exceeds 50% percent',
            mock_log.warning.call_args_list[0][0][0])


class TestGetCephadmKeys(TestCase):

    def test_get_cephadm_keys(self):
        user = 'openstack'
        key = 'AQC+vYNXgDAgAhAAc8UoYt+OTz5uhV7ItLdwUw=='
        pools = ['foo', 'bar']
        keys = utils.get_tripleo_cephadm_keys(user,
                                              key,
                                              pools)
        expected = [
            {'name': 'client.openstack',
             'key': key,
             'mode': '0600',
             'caps': {
                 'mgr': 'allow *',
                 'mon': 'profile rbd',
                 'osd': 'profile rbd pool=foo, profile rbd pool=bar'}}]

        self.assertEqual(keys, expected)
