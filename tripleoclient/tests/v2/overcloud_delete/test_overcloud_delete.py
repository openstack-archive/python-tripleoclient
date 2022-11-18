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
import tempfile

from unittest import mock

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
    def test_overcloud_delete(self, mock_mkdir, mock_cd, mock_run_playbook):
        arglist = ["overcast", "--heat-type", "native", "-y"]
        verifylist = [
            ("stack", "overcast"),
            ("heat_type", "native"),
            ("yes", True)
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_run_playbook.assert_called_once_with(
            ['cli-cleanup-ipa.yml', 'cli-overcloud-delete.yaml'],
            constants.ANSIBLE_INVENTORY.format('overcast'),
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "stack_name": "overcast",
            },
            verbosity=3,
        )

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_overcloud_delete_unprovision(self, mock_mkdir,
                                          mock_cd, mock_run_playbook):
        arglist = ["overcast", "-y",
                   '--network-ports']
        verifylist = [
            ("stack", "overcast"),
            ("yes", True),
            ("network_ports", True)
        ]

        with tempfile.NamedTemporaryFile() as inp:
            inp.write(b'- name: Compute\n- name: Controller\n')
            inp.flush()
            arglist.extend(['-b', inp.name])
            verifylist.append(('baremetal_deployment', inp.name))
            parsed_args = self.check_parser(self.cmd, arglist, verifylist)
            self.cmd.take_action(parsed_args)

            mock_run_playbook.assert_called_with(
                'cli-overcloud-node-unprovision.yaml',
                'localhost,',
                mock.ANY,
                constants.ANSIBLE_TRIPLEO_PLAYBOOKS.format('overcast'),
                extra_vars={
                    "stack_name": "overcast",
                    "baremetal_deployment": mock.ANY,
                    "all": True,
                    "prompt": False,
                    "manage_network_ports": True,
                },
                verbosity=3,
            )
            self.assertEqual(mock_run_playbook.call_count, 2)

    @mock.patch('tripleoclient.utils.TempDirs', autospec=True)
    @mock.patch('os.path.abspath', autospec=True)
    @mock.patch('os.path.exists', autospec=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook', autospec=True)
    def test_overcloud_delete_network_unprovision(self, mock_run_playbook,
                                                  mock_path_exists,
                                                  mock_abspath, mock_tempdirs):
        arglist = ["overcast", "-y",
                   "--networks-file", "network_data_v2.yaml"]
        verifylist = [
            ("stack", "overcast"),
            ("yes", True),
            ("networks_file", "network_data_v2.yaml")
        ]
        mock_abspath.side_effect = ['/test/network_data_v2.yaml',
                                    '/test/network_data_v2.yaml']
        mock_path_exists.side_effect = [True]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        mock_run_playbook.assert_called_with(
            workdir=mock.ANY,
            playbook='cli-overcloud-network-unprovision.yaml',
            inventory=mock.ANY,
            playbook_dir=mock.ANY,
            verbosity=3,
            extra_vars={
                "network_data_path": '/test/network_data_v2.yaml'
            }
        )
        self.assertEqual(mock_run_playbook.call_count, 2)

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
            constants.ANSIBLE_INVENTORY.format('overcast'),
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "stack_name": "overcast",
            },
            verbosity=3,
        )
