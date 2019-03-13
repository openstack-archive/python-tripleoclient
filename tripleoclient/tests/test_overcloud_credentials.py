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
        workflow = execution = mock.Mock()
        execution.id = "IDID"
        workflow.executions.create.return_value = execution
        self.app.client_manager.workflow_engine = workflow
        self.app.client_manager.workflow_engine = self.workflow = workflow
        self.tripleoclient = mock.Mock()
        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient

        self.websocket.wait_for_messages.return_value = iter([{
            "execution_id": "IDID",
            "status": "SUCCESS",
            "message": {
                "overcloudrc": "OVERCLOUDRC CONTENTS",
            }
        }])

    @mock.patch('os.chmod')
    def test_ok(self, mock_chmod):
        arglist = ['overcloud', ]
        verifylist = [
            ('plan', 'overcloud'),
            ('directory', '.')
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        with mock.patch("tripleoclient.utils.open", create=True) as m:
            self.cmd.take_action(parsed_args)

        self.assertIn(mock.call('./overcloudrc', 'w'), m.call_args_list)
        mock_chmod.assert_has_calls([
            mock.call('./overcloudrc', 384)])

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.deployment.v1.create_overcloudrc',
            workflow_input={'container': 'overcloud'})

    @mock.patch('os.chmod')
    def test_okay_custom_dir(self, mock_chmod):

        temp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp)

        arglist = ['overcloud', '--directory', temp]
        verifylist = [
            ('plan', 'overcloud'),
            ('directory', temp)
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        with mock.patch("tripleoclient.utils.open", create=True) as m:
            self.cmd.take_action(parsed_args)

        path = "{}/overcloudrc".format(temp)

        self.assertIn(mock.call(path, 'w'), m.call_args_list)
        mock_chmod.assert_has_calls([
            mock.call(path, 384)])

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.deployment.v1.create_overcloudrc',
            workflow_input={'container': 'overcloud'})
