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
import logging
import mock
import os
import os.path
import shutil
import socket
import subprocess
import tempfile

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

from six.moves.configparser import ConfigParser
from six.moves.urllib import error as url_error

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

    def tearDown(self):
        utils.constants.DEFAULT_WORK_DIR = self.orig_workdir

    @mock.patch('os.path.exists', return_value=False)
    @mock.patch('tripleoclient.utils.run_command_and_log')
    @mock.patch('ansible_runner.utils.dump_artifact', autospec=True,
                return_value="/foo/inventory.yaml")
    def test_no_playbook(self, mock_dump_artifact, mock_run, mock_exists):
        self.assertRaises(
            RuntimeError,
            utils.run_ansible_playbook,
            'non-existing.yaml',
            'localhost,',
            '/tmp'
        )
        mock_exists.assert_called_with('/tmp/non-existing.yaml')
        mock_run.assert_not_called()

    @mock.patch('tempfile.mkstemp', return_value=('foo', '/tmp/fooBar.cfg'))
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
                '/tmp'
            )

    @mock.patch('tempfile.mkstemp', return_value=('foo', '/tmp/fooBar.cfg'))
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
            workdir='/tmp'
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
            workdir='/tmp'
        )

    @mock.patch('tempfile.mkstemp', return_value=('foo', '/tmp/fooBar.cfg'))
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
            workdir='/tmp',
            connection='local'
        )

    @mock.patch('os.makedirs', return_value=None)
    @mock.patch('tempfile.mkstemp', return_value=('foo', '/tmp/fooBar.cfg'))
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
            workdir='/tmp',
            connection='local',
            gathering_policy='smart'
        )

    @mock.patch('os.makedirs', return_value=None)
    @mock.patch('tempfile.mkstemp', return_value=('foo', '/tmp/fooBar.cfg'))
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
            workdir='/tmp',
            connection='local',
            gathering_policy='smart',
            extra_vars=arglist
        )

    @mock.patch('six.moves.builtins.open')
    @mock.patch('tripleoclient.utils.makedirs')
    @mock.patch('os.path.exists', side_effect=(False, True, True))
    def test_run_with_timeout(self, mock_exists, mock_mkdir, mock_open):
        ansible_runner.ArtifactLoader = mock.MagicMock()
        ansible_runner.Runner.run = mock.MagicMock(return_value=('', 0))
        ansible_runner.runner_config = mock.MagicMock()
        utils.run_ansible_playbook(
            playbook='existing.yaml',
            inventory='localhost,',
            workdir='/tmp',
            timeout=42
        )
        self.assertIn(mock.call('/tmp/env/settings', 'w'),
                      mock_open.mock_calls)
        self.assertIn(
            mock.call().__enter__().write('job_timeout: 2520\n'),  # 42m * 60
            mock_open.mock_calls)

    @mock.patch('six.moves.builtins.open')
    @mock.patch('tripleoclient.utils.makedirs')
    @mock.patch('os.path.exists', side_effect=(False, True, True))
    def test_run_with_extravar_file(self, mock_exists, mock_mkdir, mock_open):
        ansible_runner.ArtifactLoader = mock.MagicMock()
        ansible_runner.Runner.run = mock.MagicMock(return_value=('', 0))
        ansible_runner.runner_config = mock.MagicMock()
        utils.run_ansible_playbook(
            playbook='existing.yaml',
            inventory='localhost,',
            workdir='/tmp',
            extra_vars_file={
                'foo': 'bar',
                'things': {
                    'more': 'options'
                },
                'num': 42
            }
        )
        self.assertIn(
            mock.call('/tmp/env/extravars', 'w'),
            mock_open.mock_calls
        )
        self.assertIn(
            mock.call().__enter__().write(
                'foo: bar\nnum: 42\nthings:\n  more: options\n'
            ),
            mock_open.mock_calls
        )


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

    def test_success_no_retcode(self):
        run = utils.run_command_and_log(self.mock_logger, self.cmd,
                                        retcode_only=False)
        self.mock_popen.assert_called_once_with(self.cmd,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT,
                                                shell=False,
                                                cwd=None, env=None)
        self.assertEqual(run, self.mock_process)
        self.mock_logger.warning.assert_not_called()


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

    def test_check_stack_network_matches_env_files(self):
        stack_reg = {
            'OS::TripleO::Network': 'val',
            'OS::TripleO::Network::External': 'val',
            'OS::TripleO::Network::ExtraConfig': 'OS::Heat::None',
            'OS::TripleO::Network::InternalApi': 'val',
            'OS::TripleO::Network::Port::InternalApi': 'val',
            'OS::TripleO::Network::Management': 'val',
            'OS::TripleO::Network::Storage': 'val',
            'OS::TripleO::Network::StorageMgmt': 'val',
            'OS::TripleO::Network::Tenant': 'val'
        }
        env_reg = {
            'OS::TripleO::Network': 'newval',
            'OS::TripleO::Network::External': 'newval',
            'OS::TripleO::Network::ExtraConfig': 'OS::Heat::None',
            'OS::TripleO::Network::InternalApi': 'newval',
            'OS::TripleO::Network::Management': 'newval',
            'OS::TripleO::Network::Storage': 'val',
            'OS::TripleO::Network::StorageMgmt': 'val',
            'OS::TripleO::Network::Tenant': 'val'
        }
        mock_stack = mock.MagicMock()
        mock_stack.environment = mock.MagicMock()
        mock_stack.environment.return_value = {
            'resource_registry':  stack_reg
        }
        env = {
            'resource_registry':  env_reg
        }
        utils.check_stack_network_matches_env_files(mock_stack, env)

    def test_check_stack_network_matches_env_files_fail(self):
        stack_reg = {
            'OS::TripleO::LoggingConfiguration': 'val',
            'OS::TripleO::Network': 'val',
            'OS::TripleO::Network::External': 'val',
            'OS::TripleO::Network::ExtraConfig': 'OS::Heat::None',
            'OS::TripleO::Network::InternalApi': 'val',
            'OS::TripleO::Network::Port::InternalApi': 'val',
            'OS::TripleO::Network::Management': 'val',
            'OS::TripleO::Network::Storage': 'val',
            'OS::TripleO::Network::StorageMgmt': 'val',
            'OS::TripleO::Network::Tenant': 'val'
        }
        env_reg = {
            'OS::TripleO::LoggingConfiguration': 'newval',
            'OS::TripleO::Network': 'newval',
            'OS::TripleO::Network::InternalApi': 'newval'
        }
        mock_stack = mock.MagicMock()
        mock_stack.environment = mock.MagicMock()
        mock_stack.environment.return_value = {
            'resource_registry':  stack_reg
        }
        env = {
            'resource_registry':  env_reg
        }
        with self.assertRaises(exceptions.InvalidConfiguration):
            utils.check_stack_network_matches_env_files(mock_stack, env)

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
        utils.check_ceph_fsid_matches_env_files(mock_stack, provided_env)

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
            utils.check_ceph_fsid_matches_env_files(mock_stack, provided_env)

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
            self.assertEqual(utils.file_checksum(empty_temp_file.name),
                             'd41d8cd98f00b204e9800998ecf8427e')

    def test_non_empty_file_checksum(self):
        # Used a NamedTemporaryFile since it's deleted when the file is closed.
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(b'foo')
            temp_file.flush()

            self.assertEqual(utils.file_checksum(temp_file.name),
                             'acbd18db4cc2f85cedef654fccc4a4d8')

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

    def test_get_endpoint_map(self):
        stack = mock.MagicMock()
        emap = {'KeystonePublic': {'uri': 'http://foo:8000/'}}
        stack.to_dict.return_value = {
            'outputs': [{'output_key': 'EndpointMap',
                         'output_value': emap}]
        }

        endpoint_map = utils.get_endpoint_map(stack)
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


class FakeFlavor(object):
    def __init__(self, name, profile=''):
        self.name = name
        self.profile = name
        if profile != '':
            self.profile = profile

    def get_keys(self):
        return {
            'capabilities:boot_option': 'local',
            'capabilities:profile': self.profile
        }


class TestAssignVerifyProfiles(TestCase):
    def setUp(self):

        super(TestAssignVerifyProfiles, self).setUp()
        self.bm_client = mock.Mock(spec=['node'],
                                   node=mock.Mock(spec=['list', 'update']))
        self.nodes = []
        self.bm_client.node.list.return_value = self.nodes
        self.flavors = {name: (FakeFlavor(name), 1)
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
        self.flavors = {'baremetal': (FakeFlavor('baremetal', None), 1)}
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
        with mock.patch("six.moves.builtins.open", mock_file):
            with mock.patch('tripleoclient.utils.datetime') as mock_date:
                mock_date.datetime.now.return_value = dt
                utils.store_cli_param("overcloud plan list", ArgsFake())

        expected_call = [
            mock.call("%s/history" % history_path, 'a'),
            mock.call().write('2017-11-22 00:00:00 overcloud-plan-list a=1 \n')
        ]
        mock_file.assert_has_calls(expected_call, any_order=True)

    @mock.patch('six.moves.builtins.open')
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
            mock.call(env_path='./inside.yaml'),
            mock.call(env_path='/twd/templates/abs.yaml'),
            mock.call(env_path='/twd/templates/puppet/foo.yaml'),
            mock.call(env_path='/twd/templates/environments/myenv.yaml'),
            mock.call(env_path='/tmp/thtroot42/notouch.yaml'),
            mock.call(env_path='./tmp/thtroot/notouch2.yaml'),
            mock.call(env_path='../outside.yaml')])

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
    @mock.patch('yaml.safe_dump', autospec=True)
    @mock.patch('yaml.safe_load', autospec=True)
    @mock.patch('six.moves.builtins.open')
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
                                            self.user_tht_root, False)

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
              expected=('overcloud-full', '.qcow2'))),
        ('image_arch',
         dict(func=utils.overcloud_image,
              basename='overcloud-full',
              arch='x86_64',
              expected=('x86_64-overcloud-full', '.qcow2'))),
        ('image_arch_platform',
         dict(func=utils.overcloud_image,
              basename='overcloud-full',
              arch='x86_64',
              platform='SNB',
              expected=('SNB-x86_64-overcloud-full', '.qcow2'))),
        ('image_platform',
         dict(func=utils.overcloud_image,
              basename='overcloud-full',
              platform='SNB',
              expected=('overcloud-full', '.qcow2'))),
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
    @mock.patch('six.moves.urllib.request.urlopen')
    def test_success(self, urlopen_mock):
        has_errors = utils.wait_api_port_ready(8080)
        self.assertFalse(has_errors)

    @mock.patch(
        'six.moves.urllib.request.urlopen',
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
        'six.moves.urllib.request.urlopen',
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
        'six.moves.urllib.request.urlopen',
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

    @mock.patch('six.moves.urllib.request.urlopen', side_effect=NameError)
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
        self.tc = self.app.client_manager.tripleoclient = mock.Mock()
        obj = self.tc.object_store = mock.Mock()
        obj.put_object = mock.Mock()
        obj.put_container = mock.Mock()

    def test_update_deployment_status(self):
        mock_status = {
            'status_update': 'TESTING',
            'deployment_status': 'TESTING'
        }
        utils.update_deployment_status(
            self.app.client_manager,
            'overcloud',
            mock_status
        )
        self.tc.object_store.put_object.assert_called()
        self.tc.object_store.put_container.assert_called()

    def test_playbook_limit_parse(self):
        limit_nodes = 'controller0, compute0:compute1,!compute2'
        limit_hosts_expected = 'controller0:compute0:compute1:!compute2'
        limit_hosts_actual = utils.playbook_limit_parse(limit_nodes)
        self.assertEqual(limit_hosts_actual, limit_hosts_expected)
