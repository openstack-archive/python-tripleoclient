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

from unittest import mock

from osc_lib.tests.utils import ParserException
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient.tests.v1.overcloud_update import fakes
from tripleoclient.v1 import overcloud_update


class TestOvercloudUpdatePrepare(fakes.TestOvercloudUpdatePrepare):

    def setUp(self):
        super(TestOvercloudUpdatePrepare, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_update.UpdatePrepare(self.app, app_args)

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch('tripleoclient.utils.ensure_run_as_normal_user')
    @mock.patch('tripleoclient.utils.prompt_user_for_confirmation',
                return_value=True)
    @mock.patch('builtins.open')
    @mock.patch('os.path.abspath')
    @mock.patch('yaml.safe_load')
    @mock.patch('shutil.copytree', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'take_action', autospec=True)
    def test_update_failed(self, mock_deploy, mock_copy, mock_yaml,
                           mock_abspath, mock_open,
                           mock_confirm, mock_usercheck):
        mock_deploy.side_effect = exceptions.DeploymentError()
        mock_yaml.return_value = {'fake_container': 'fake_value'}
        argslist = ['--stack', 'overcloud', '--templates', ]
        verifylist = [
            ('stack', 'overcloud'),
            ('templates', constants.TRIPLEO_HEAT_TEMPLATES),
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        with mock.patch('os.path.exists') as mock_exists, \
                mock.patch('os.path.isfile') as mock_isfile:
            mock_exists.return_value = True
            mock_isfile.return_value = True
            self.assertRaises(exceptions.DeploymentError,
                              self.cmd.take_action, parsed_args)
            mock_usercheck.assert_called_once()

    @mock.patch('tripleoclient.utils.get_ctlplane_attrs', autospec=True,
                return_value={})
    @mock.patch('tripleoclient.utils.ensure_run_as_normal_user')
    @mock.patch('tripleoclient.utils.prompt_user_for_confirmation',
                return_value=True)
    @mock.patch('tripleoclient.utils.get_undercloud_host_entry', autospec=True,
                return_value='192.168.0.1 uc.ctlplane.localhost uc.ctlplane')
    @mock.patch('tripleoclient.v1.overcloud_update.UpdatePrepare.log',
                autospec=True)
    @mock.patch('os.path.abspath')
    @mock.patch('yaml.safe_load')
    @mock.patch('shutil.copytree', autospec=True)
    @mock.patch('builtins.open')
    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                'take_action', autospec=True)
    def test_update_out(self, mock_deploy, mock_open, mock_copy, mock_yaml,
                        mock_abspath, mock_logger,
                        mock_get_undercloud_host_entry,
                        mock_confirm, mock_usercheck,
                        mock_get_ctlplane_attrs):
        mock_yaml.return_value = {'fake_container': 'fake_value'}

        argslist = ['--stack', 'overcloud', '--templates']

        verifylist = [
            ('stack', 'overcloud'),
            ('templates', constants.TRIPLEO_HEAT_TEMPLATES),
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        with mock.patch('os.path.exists') as mock_exists, \
                mock.patch('os.path.isfile') as mock_isfile:
            mock_exists.return_value = True
            mock_isfile.return_value = True
            self.cmd.take_action(parsed_args)
            mock_usercheck.assert_called_once()
            mock_deploy.assert_called_once()


class TestOvercloudUpdateRun(fakes.TestOvercloudUpdateRun):

    def setUp(self):
        super(TestOvercloudUpdateRun, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_update.UpdateRun(self.app, app_args)

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch('tripleoclient.utils.prompt_user_for_confirmation',
                return_value=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('builtins.open')
    def test_update_with_no_limit(
            self, mock_open, mock_execute, mock_expanduser, update_ansible,
            mock_confirm):
        mock_expanduser.return_value = '/home/fake/'
        argslist = []
        verifylist = [
            ('static_inventory', None),
            ('playbook', 'all')
        ]
        self.assertRaises(ParserException, lambda: self.check_parser(
            self.cmd, argslist, verifylist))
