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
import mock
import shutil
import tempfile

from tripleoclient.tests.v1 import test_plugin
from tripleoclient.v1 import overcloud_credentials


class TestOvercloudCredentials(test_plugin.TestPluginV1):

    def setUp(self):
        super(TestOvercloudCredentials, self).setUp()

        self.cmd = overcloud_credentials.OvercloudCredentials(self.app, None)
        self.tripleoclient = mock.Mock()
        self.app.client_manager.tripleoclient = self.tripleoclient

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    def test_ok(self, mock_run_playbook):
        arglist = ['overcloud', ]
        verifylist = [
            ('plan', 'overcloud'),
            ('directory', '.')
        ]

        self.check_parser(self.cmd, arglist, verifylist)

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    def test_okay_custom_dir(self, mock_run_playbook):

        temp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp)

        arglist = ['overcloud', '--directory', temp]
        verifylist = [
            ('plan', 'overcloud'),
            ('directory', temp)
        ]
        self.check_parser(self.cmd, arglist, verifylist)
