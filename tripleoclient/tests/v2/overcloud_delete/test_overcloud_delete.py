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
#

import mock
from osc_lib import exceptions

from tripleoclient import constants
from tripleoclient.tests import fakes
from tripleoclient.tests.v1.overcloud_deploy import fakes as deploy_fakes
from tripleoclient.v2 import overcloud_delete


class TestDeleteOvercloud(deploy_fakes.TestDeployOvercloud):

    def setUp(self):
        super(TestDeleteOvercloud, self).setUp()
        self.app = fakes.FakeApp()
        self.cmd = overcloud_delete.DeleteOvercloud(self.app, None)

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_plan_undeploy(self, mock_mkdir, mock_cd, mock_run_playbook):
        arglist = ["overcast", "-y"]
        verifylist = [
            ("stack", "overcast"),
            ("yes", True)
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_run_playbook.assert_called_once_with(
            ['cli-cleanup-ipa.yml', 'cli-overcloud-delete.yaml'],
            constants.ANSIBLE_INVENTORY,
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "stack_name": "overcast",
            },
            verbosity=3,
        )

    def test_no_confirmation(self):
        arglist = ["overcast", ]
        verifylist = [
            ("stack", "overcast"),
            ("yes", False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaises(exceptions.CommandError,
                          self.cmd.take_action, parsed_args)

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    def test_skip_ipa_cleanup(self, mock_run_playbook):
        arglist = ["overcast", "-y", "--skip-ipa-cleanup"]
        verifylist = [
            ("stack", "overcast"),
            ("yes", True),
            ("skip_ipa_cleanup", True)
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        mock_run_playbook.assert_called_once_with(
            ['cli-overcloud-delete.yaml'],
            constants.ANSIBLE_INVENTORY,
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "stack_name": "overcast",
            },
            verbosity=3,
        )
