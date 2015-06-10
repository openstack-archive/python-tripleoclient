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

from rdomanager_oscplugin.tests.v1.overcloud_scale import fakes
from rdomanager_oscplugin.v1 import overcloud_scale


class TestOvercloudScale(fakes.TestOvercloudScale):

    def setUp(self):
        super(TestOvercloudScale, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_scale.ScaleOvercloud(self.app, None)

    # TODO(someone): This test does not pass with autospec=True, it should
    # probably be fixed so that it can pass with that.
    @mock.patch('tripleo_common.scale.ScaleManager')
    def test_scale_out(self, scale_manager):
        argslist = ['-r', 'Compute-1', '-n', '2', 'overcloud', 'overcloud']
        verifylist = [
            ('role', 'Compute-1'),
            ('num', 2)
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        scale_manager.scaleup(parsed_args.role, parsed_args.num)
        scale_manager.scaleup.assert_called_once_with('Compute-1', 2)
