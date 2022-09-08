# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock

from osc_lib.tests import utils

from tripleoclient.workflows import parameters


class TestStringCapture(object):
    def __init__(self):
        self.capture_string = ''

    def write(self, msg):
        self.capture_string = self.capture_string + msg

    def getvalue(self):
        return self.capture_string


class TestParameterWorkflows(utils.TestCommand):

    def setUp(self):
        super(TestParameterWorkflows, self).setUp()
        self.app.client_manager.baremetal = mock.Mock()

    @mock.patch(
        'tripleo_common.utils.stack_parameters.generate_fencing_parameters',
        return_value={})
    def test_generate_fencing_parameters(self, mock_params):
        mock_params.return_value = {"parameter_defaults": {}}

        workflow_input = {
            'nodes_json': [],
            'delay': 0,
            'ipmi_level': 'test',
            'ipmi_cipher': 'test',
            'ipmi_lanplus': True
        }
        params = parameters.generate_fencing_parameters(
            **workflow_input
        )
        self.assertEqual(params, {"parameter_defaults": {}})
