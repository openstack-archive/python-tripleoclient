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

from uuid import uuid4

import argparse
import mock
from mock import call
import os.path
import tempfile

from unittest import TestCase
import yaml

from tripleoclient import exceptions
from tripleoclient import utils


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

    @mock.patch('tripleoclient.utils.wait_for_provision_state')
    def test_set_nodes_state(self, wait_for_state_mock):

        wait_for_state_mock.return_value = True
        bm_client = mock.Mock()

        # One node already deployed, one in the manageable state after
        # introspection.
        nodes = [
            mock.Mock(uuid="ABCDEFGH", provision_state="active"),
            mock.Mock(uuid="IJKLMNOP", provision_state="manageable")
        ]

        skipped_states = ('active', 'available')
        uuids = list(utils.set_nodes_state(bm_client, nodes, 'provide',
                                           'available', skipped_states))

        bm_client.node.set_provision_state.assert_has_calls([
            mock.call('IJKLMNOP', 'provide'),
        ])

        self.assertEqual(uuids, ['IJKLMNOP', ])

    def test_wait_for_provision_state(self):

        baremetal_client = mock.Mock()

        baremetal_client.node.get.return_value = mock.Mock(
            provision_state="available", last_error=None)

        utils.wait_for_provision_state(baremetal_client, 'UUID', "available")

    def test_wait_for_provision_state_not_found(self):

        baremetal_client = mock.Mock()

        baremetal_client.node.get.return_value = None

        utils.wait_for_provision_state(baremetal_client, 'UUID', "available")

    def test_wait_for_provision_state_timeout(self):

        baremetal_client = mock.Mock()

        baremetal_client.node.get.return_value = mock.Mock(
            provision_state="not what we want", last_error=None)

        with self.assertRaises(exceptions.Timeout):
            utils.wait_for_provision_state(baremetal_client, 'UUID',
                                           "available", loops=1, sleep=0.01)

    def test_wait_for_provision_state_fail(self):

        baremetal_client = mock.Mock()

        baremetal_client.node.get.return_value = mock.Mock(
            provision_state="enroll",
            last_error="node on fire; returning to previous state.")

        with self.assertRaises(exceptions.StateTransitionFailed):
            utils.wait_for_provision_state(baremetal_client, 'UUID',
                                           "available", loops=1, sleep=0.01)

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


class TestCreateOvercloudRC(TestCase):

    def test_write_overcloudrc(self):
        stack_name = 'teststack'

        tempdir = tempfile.mkdtemp()
        rcfile = os.path.join(tempdir, 'teststackrc')
        rcfile_v3 = os.path.join(tempdir, 'teststackrc.v3')

        overcloudrcs = {
            "overcloudrc": "overcloudrc not v3",
            "overcloudrc.v3": "overcloudrc.v3",
        }

        try:
            utils.write_overcloudrc(stack_name, overcloudrcs,
                                    config_directory=tempdir)
            rc = open(rcfile, 'rt').read()
            self.assertIn('overcloudrc not v3', rc)
            rc_v3 = open(rcfile_v3, 'rt').read()
            self.assertIn('overcloudrc.v3', rc_v3)
        finally:
            if os.path.exists(rcfile):
                os.unlink(rcfile)
            if os.path.exists(rcfile_v3):
                os.unlink(rcfile_v3)

            os.rmdir(tempdir)


class TestCreateTempestDeployerInput(TestCase):

    def test_create_tempest_deployer_input(self):
        with tempfile.NamedTemporaryFile() as cfgfile:
            filepath = cfgfile.name
            utils.create_tempest_deployer_input(filepath)
            cfg = open(filepath, 'rt').read()
            # Just make a simple test, to make sure it created a proper file:
            self.assertIn(
                '[volume-feature-enabled]\nbootable = true', cfg)


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
            'resources:\n'
            '  test_config:\n'
            '    properties:\n'
            '      config: {get_file: "file:///home/stack/test.sh"}\n'
            '    type: OS::Heat::SoftwareConfig\n'
        )
        expected = (
            'description: my template\n'
            'heat_template_version: "2014-10-16"\n'
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


class TestStoreCliParam(TestCase):

    def setUp(self):
        self.args = argparse.ArgumentParser()

    @mock.patch('os.mkdir')
    @mock.patch('os.path.exists')
    def test_fail_to_create_file(self, mock_exists, mock_mkdir):
        mock_exists.return_value = False
        mock_mkdir.side_effect = OSError()
        self.assertRaises(OSError, utils.store_cli_param, self.args)

    @mock.patch('os.path.isdir')
    @mock.patch('os.path.exists')
    def test_exists_but_not_dir(self, mock_exists, mock_isdir):
        mock_exists.return_value = True
        mock_isdir.return_value = False
        self.assertRaises(exceptions.InvalidConfiguration,
                          utils.store_cli_param,
                          self.args)

    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.isdir')
    @mock.patch('os.path.exists')
    def test_write_cli_param(self, mock_exists, mock_isdir, mock_open):
        history_path = os.path.join(os.path.expanduser("~"), '.tripleo')
        mock_exists.return_value = True
        mock_isdir.return_value = True
        utils.store_cli_param(self.args)
        expected_call = [call("%s/history" % history_path, 'a')]
        mock_open.assert_has_calls(expected_call)

    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.isdir')
    @mock.patch('os.path.exists')
    def test_fail_to_write_data(self, mock_exists, mock_isdir, mock_open):
        mock_exists.return_value = True
        mock_isdir.return_value = True
        mock_open.side_effect = IOError()
        self.assertRaises(IOError, utils.store_cli_param, self.args)
