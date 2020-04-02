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

import json
import mock
import os
import tempfile

from osc_lib.tests import utils
import yaml

from tripleoclient import exceptions
from tripleoclient.tests import fakes
from tripleoclient.v1 import overcloud_parameters


class TestSetParameters(utils.TestCommand):

    def setUp(self):
        super(TestSetParameters, self).setUp()
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.options = fakes.FakeOptions()
        self.cmd = overcloud_parameters.SetParameters(self.app, app_args)
        self.app.client_manager.workflow_engine = mock.Mock()

        self.workflow = self.app.client_manager.workflow_engine

    def _test_set_parameters(self, extension, dumper, data):

        # Setup
        with tempfile.NamedTemporaryFile(
                suffix=extension, delete=False, mode="wt") as params_file:
            self.addCleanup(os.unlink, params_file.name)
            params_file.write(dumper(data))

        arglist = ['overcast', params_file.name]
        verifylist = [
            ('name', 'overcast')
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.workflow.action_executions.create.return_value = mock.MagicMock(
            output=json.dumps({
                "result": None
            })
        )

        playbook_runner = mock.patch(
            'tripleoclient.utils.run_ansible_playbook',
            autospec=True
        )
        playbook_runner.start()
        self.addCleanup(playbook_runner.stop)

        # Run
        self.cmd.take_action(parsed_args)

    def test_json_params_file(self):
        self._test_set_parameters(".json", json.dumps, {
            "param1": "value1",
            "param2": "value2",
        })

    def test_yaml_params_file(self):
        self._test_set_parameters(".yaml", yaml.dump, {
            "parameter_defaults": {
                "param1": "value1",
                "param2": "value2",
            }
        })

    def test_invalid_params_file(self):

        self.assertRaises(
            exceptions.InvalidConfiguration,
            self._test_set_parameters, ".invalid", yaml.dump, {})


class TestGenerateFencingParameters(utils.TestCommand):

    def setUp(self):
        super(TestGenerateFencingParameters, self).setUp()

        self.cmd = overcloud_parameters.GenerateFencingParameters(self.app,
                                                                  None)
        self.app.client_manager = mock.Mock()

    @mock.patch(
        'tripleoclient.workflows.parameters.generate_fencing_parameters',
        autospec=True)
    def test_generate_parameters(self, mock_gen_fence):
        mock_open_context = mock.mock_open(read_data="""
{
  "nodes": [
      {
        "name": "control-0",
        "pm_password": "control-0-password",
        "pm_type": "ipmi",
        "pm_user": "control-0-admin",
        "pm_addr": "0.1.2.3",
        "pm_port": "0123",
        "mac": [
          "00:11:22:33:44:55"
        ]
      },
      {
        "name": "control-1",
        "pm_password": "control-1-password",
        "pm_type": "ipmi",
        "pm_user": "control-1-admin",
        "pm_addr": "1.2.3.4",
        "mac": [
          "11:22:33:44:55:66"
        ]
      }
  ]
}
        """)

        arglist = ['node_file.json']
        verifylist = []

        mock_gen_fence.return_value = '{"result":[]}'

        with mock.patch('six.moves.builtins.open', mock_open_context):
            parsed_args = self.check_parser(self.cmd, arglist, verifylist)
            self.cmd.take_action(parsed_args)

        mock_gen_fence.assert_called_once_with(
            self.app.client_manager,
            **{
                'nodes_json': [
                    {
                        u'mac': [u'00:11:22:33:44:55'],
                        u'name': u'control-0',
                        u'pm_port': u'0123',
                        u'pm_addr': u'0.1.2.3',
                        u'pm_type': u'ipmi',
                        u'pm_password': u'control-0-password',
                        u'pm_user': u'control-0-admin'
                    },
                    {
                        u'name': u'control-1',
                        u'pm_addr': u'1.2.3.4',
                        u'pm_type': u'ipmi',
                        u'pm_user': u'control-1-admin',
                        u'pm_password': u'control-1-password',
                        u'mac': [u'11:22:33:44:55:66']
                    }],
                'delay': None,
                'ipmi_cipher': None,
                'ipmi_lanplus': True,
                'ipmi_level': None
            })
