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
from tripleoclient.v1 import overcloud_parameters


class TestSetParameters(utils.TestCommand):

    def setUp(self):
        super(TestSetParameters, self).setUp()

        self.cmd = overcloud_parameters.SetParameters(self.app, None)
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

        # Run
        self.cmd.take_action(parsed_args)

        # Verify
        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.parameters.update',
            {
                'container': 'overcast',
                'parameters': data.get('parameter_defaults', data)
            })

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
