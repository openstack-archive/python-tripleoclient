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

from rdomanager_oscplugin.tests.v1.overcloud_update import fakes
from rdomanager_oscplugin.v1 import overcloud_update


class TestOvercloudUpdate(fakes.TestOvercloudUpdate):

    def setUp(self):
        super(TestOvercloudUpdate, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_update.UpdateOvercloud(self.app, None)

    @mock.patch('tripleo_common.update.PackageUpdateManager')
    def test_update_out(self, update_manager):
        update_manager.return_value.get_status.return_value = (
            'UPDATE_COMPLETE', {})
        argslist = ['-i', '--plan', 'overcloud', 'overcloud']
        verifylist = [
            ('stack', 'overcloud'),
            ('plan', 'overcloud'),
            ('interactive', True),
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)
        update_manager.get_status.called_once()
        update_manager.update.called_once()
        update_manager.do_interactive_update.called_once()
