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

import mock

from tripleoclient.tests import fakes as ooofakes
from tripleoclient.tests.v1.overcloud_external_update import fakes
from tripleoclient.v1 import overcloud_external_update


class TestOvercloudExternalUpdateRun(fakes.TestOvercloudExternalUpdateRun):

    def setUp(self):
        super(TestOvercloudExternalUpdateRun, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = overcloud_external_update.ExternalUpdateRun(
            self.app, app_args)

        uuid4_patcher = mock.patch('uuid.uuid4', return_value="UUID4")
        self.mock_uuid4 = uuid4_patcher.start()
        self.addCleanup(self.mock_uuid4.stop)

    @mock.patch(
        'ansible_runner.runner_config.RunnerConfig',
        autospec=True,
        return_value=ooofakes.FakeRunnerConfig()
    )
    @mock.patch(
        'ansible_runner.Runner.run',
        return_value=ooofakes.fake_ansible_runner_run_return()
    )
    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_update_with_user_and_tags(self, mock_open, mock_execute,
                                       mock_expanduser, update_ansible,
                                       mock_run, mock_run_prepare):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--ssh-user', 'tripleo-admin',
                    '--tags', 'ceph']
        verifylist = [
            ('ssh_user', 'tripleo-admin'),
            ('tags', 'ceph'),
        ]

        self.check_parser(self.cmd, argslist, verifylist)

    @mock.patch(
        'ansible_runner.runner_config.RunnerConfig',
        autospec=True,
        return_value=ooofakes.FakeRunnerConfig()
    )
    @mock.patch(
        'ansible_runner.Runner.run',
        return_value=ooofakes.fake_ansible_runner_run_return()
    )
    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    @mock.patch('os.path.expanduser')
    @mock.patch('oslo_concurrency.processutils.execute')
    @mock.patch('six.moves.builtins.open')
    def test_update_with_user_and_extra_vars(self, mock_open, mock_execute,
                                             mock_expanduser, update_ansible,
                                             mock_run, mock_run_prepare):
        mock_expanduser.return_value = '/home/fake/'
        argslist = ['--ssh-user', 'tripleo-admin',
                    '--extra-vars', 'key1=val1',
                    '--extra-vars', 'key2=val2']
        verifylist = [
            ('ssh_user', 'tripleo-admin'),
            ('extra_vars', ['key1=val1', 'key2=val2'])
        ]

        self.check_parser(self.cmd, argslist, verifylist)
