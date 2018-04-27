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

import mock

from tripleo_common.image import kolla_builder

from tripleoclient import exceptions
from tripleoclient.tests.v1.test_plugin import TestPluginV1

# Load the plugin init module for the plugin list and show commands
from tripleoclient.v1 import tripleo_deploy

# TODO(sbaker) Remove after a tripleo-common release contains this new function
if not hasattr(kolla_builder, 'container_images_prepare_multi'):
    setattr(kolla_builder, 'container_images_prepare_multi', mock.Mock())


class FakePluginV1Client(object):
    def __init__(self, **kwargs):
        self.auth_token = kwargs['token']
        self.management_url = kwargs['endpoint']


class TestDeployUndercloud(TestPluginV1):

    def setUp(self):
        super(TestDeployUndercloud, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_deploy.Deploy(self.app, None)

        tripleo_deploy.Deploy.heat_pid = mock.MagicMock(
            return_value=False)
        tripleo_deploy.Deploy.tht_render = '/twd/templates'
        tripleo_deploy.Deploy.tmp_env_dir = '/twd'
        tripleo_deploy.Deploy.tmp_env_file_name = 'tmp/foo'
        tripleo_deploy.Deploy.heat_launch = mock.MagicMock(
            side_effect=(lambda *x, **y: None))

        self.tc = self.app.client_manager.tripleoclient = mock.MagicMock()
        self.orc = self.tc.local_orchestration = mock.MagicMock()
        self.orc.stacks.create = mock.MagicMock(
            return_value={'stack': {'id': 'foo'}})

    def test_take_action_standalone(self):
        """This is currently handled by undercloud_deploy tests"""
        pass

    def test_take_action(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my'], [])
        self.assertRaises(exceptions.DeploymentError,
                          self.cmd.take_action, parsed_args)
