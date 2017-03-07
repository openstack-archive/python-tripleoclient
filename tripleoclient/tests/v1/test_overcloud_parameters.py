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
            },
            run_sync=True, save_result=True)

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
        self.app.client_manager.workflow_engine = mock.Mock()

        self.workflow = self.app.client_manager.workflow_engine

    def test_generate_parameters(self):
        nodes_file = tempfile.NamedTemporaryFile(suffix='.json', delete=False,
                                                 mode="wt")
        self.addCleanup(os.unlink, nodes_file.name)
        nodes_file.write("""
{
  "nodes": [
      {
        "name": "control-0",
        "pm_password": "control-0-password",
        "pm_type": "pxe_ipmitool",
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
        "pm_type": "pxe_ssh",
        "pm_user": "control-1-admin",
        "pm_addr": "1.2.3.4",
        "mac": [
          "11:22:33:44:55:66"
        ]
      }
  ]
}
        """)
        nodes_file.close()

        os.environ["OS_USERNAME"] = "test_os_username"
        os.environ["OS_PASSWORD"] = "test_os_password"
        os.environ["OS_AUTH_URL"] = "test://auth.url"
        os.environ["OS_TENANT_NAME"] = "test_os_tenant_name"

        arglist = [nodes_file.name]
        verifylist = []

        self.workflow.action_executions.create.return_value = mock.MagicMock(
            output='{"result":[]}')
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.parameters.generate_fencing',
            {
                'fence_action': None,
                'nodes_json': [
                    {
                        u'mac': [u'00:11:22:33:44:55'],
                        u'name': u'control-0',
                        u'pm_port': u'0123',
                        u'pm_addr': u'0.1.2.3',
                        u'pm_type': u'pxe_ipmitool',
                        u'pm_password': u'control-0-password',
                        u'pm_user': u'control-0-admin'
                    },
                    {
                        u'name': u'control-1',
                        u'pm_addr': u'1.2.3.4',
                        u'pm_type': u'pxe_ssh',
                        u'pm_user': u'control-1-admin',
                        u'pm_password': u'control-1-password',
                        u'mac': [u'11:22:33:44:55:66']
                    }],
                'delay': None,
                'os_auth': {},
                'ipmi_cipher': None,
                'ipmi_lanplus': False,
                'ipmi_level': None
            },
            run_sync=True, save_result=True)
