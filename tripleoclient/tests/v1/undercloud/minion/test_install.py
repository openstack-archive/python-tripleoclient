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

import fixtures
import mock

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture

from tripleoclient.tests.v1.test_plugin import TestPluginV1

# Load the plugin init module for the plugin list and show commands
from tripleoclient.v1 import undercloud_minion


class FakePluginV1Client(object):
    def __init__(self, **kwargs):
        self.auth_token = kwargs['token']
        self.management_url = kwargs['endpoint']


class TestMinionInstall(TestPluginV1):

    def setUp(self):
        super(TestMinionInstall, self).setUp()

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        # don't actually load config from ~/minion.conf
        self.mock_config_load = self.useFixture(
            fixtures.MockPatch('tripleoclient.utils.load_config'))
        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = undercloud_minion.InstallUndercloudMinion(self.app,
                                                             app_args)

    @mock.patch('tripleoclient.v1.minion_config.prepare_minion_deploy')
    @mock.patch('tripleoclient.utils.ensure_run_as_normal_user')
    @mock.patch('tripleoclient.utils.configure_logging')
    @mock.patch('subprocess.check_call', autospec=True)
    def test_take_action(self, mock_subprocess, mock_logging, mock_usercheck,
                         mock_prepare_deploy):
        arglist = []
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        mock_prepare_deploy.return_value = ['foo']
        self.cmd.take_action(parsed_args)
        mock_prepare_deploy.assert_called_once_with(
                dry_run=False, force_stack_update=False, no_validations=False,
                verbose_level=1)
        mock_usercheck.assert_called_once()
        mock_subprocess.assert_called_with(['foo'])

    @mock.patch('tripleoclient.v1.minion_config.prepare_minion_deploy')
    @mock.patch('tripleoclient.utils.ensure_run_as_normal_user')
    @mock.patch('tripleoclient.utils.configure_logging')
    @mock.patch('subprocess.check_call', autospec=True)
    def test_take_action_dry_run(self, mock_subprocess, mock_logging,
                                 mock_usercheck, mock_prepare_deploy):
        arglist = ['--dry-run']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)
        mock_prepare_deploy.assert_called_once_with(
                dry_run=True, force_stack_update=False, no_validations=True,
                verbose_level=1)
        mock_usercheck.assert_called_once()
        self.assertItemsEqual(mock_subprocess.call_args_list, [])


class TestMinionUpgrade(TestPluginV1):

    def setUp(self):
        super(TestMinionUpgrade, self).setUp()

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        # don't actually load config from ~/minion.conf
        self.mock_config_load = self.useFixture(
            fixtures.MockPatch('tripleoclient.utils.load_config'))
        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = undercloud_minion.UpgradeUndercloudMinion(self.app,
                                                             app_args)

    @mock.patch('tripleoclient.v1.minion_config.prepare_minion_deploy')
    @mock.patch('tripleoclient.utils.ensure_run_as_normal_user')
    @mock.patch('tripleoclient.utils.configure_logging')
    @mock.patch('subprocess.check_call', autospec=True)
    def test_take_action(self, mock_subprocess, mock_logging, mock_usercheck,
                         mock_prepare_deploy):
        arglist = []
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        mock_prepare_deploy.return_value = ['foo']
        self.cmd.take_action(parsed_args)
        mock_prepare_deploy.assert_called_once_with(
                force_stack_update=False, no_validations=False, upgrade=True,
                verbose_level=1, yes=False)
        mock_usercheck.assert_called_once()
        mock_subprocess.assert_called_with(['foo'])

    @mock.patch('tripleoclient.v1.minion_config.prepare_minion_deploy')
    @mock.patch('tripleoclient.utils.ensure_run_as_normal_user')
    @mock.patch('tripleoclient.utils.configure_logging')
    @mock.patch('subprocess.check_call', autospec=True)
    def test_take_action_yes(self, mock_subprocess, mock_logging,
                             mock_usercheck, mock_prepare_deploy):
        arglist = ['--yes']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        mock_prepare_deploy.return_value = ['foo']
        self.cmd.take_action(parsed_args)
        mock_prepare_deploy.assert_called_once_with(
                force_stack_update=False, no_validations=False, upgrade=True,
                verbose_level=1, yes=True)
        mock_usercheck.assert_called_once()
        mock_subprocess.assert_called_with(['foo'])
