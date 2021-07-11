#   Copyright 2021 Red Hat, Inc.
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

from osc_lib import exceptions as osc_lib_exc

from tripleoclient.tests import fakes
from tripleoclient.v2 import overcloud_ceph


class TestOvercloudCephDeploy(fakes.FakePlaybookExecution):

    def setUp(self):
        super(TestOvercloudCephDeploy, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.options = fakes.FakeOptions()
        self.cmd = overcloud_ceph.OvercloudCephDeploy(self.app,
                                                      app_args)

    @mock.patch('tripleoclient.utils.TempDirs', autospect=True)
    @mock.patch('os.path.abspath', autospect=True)
    @mock.patch('os.path.exists', autospect=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook', autospec=True)
    def test_overcloud_deploy_ceph(self, mock_playbook, mock_abspath,
                                   mock_path_exists, mock_tempdirs):
        arglist = ['deployed-metal.yaml', '--yes',
                   '--stack', 'overcloud',
                   '--output', 'deployed-ceph.yaml',
                   '--container-namespace', 'quay.io/ceph',
                   '--container-image', 'ceph',
                   '--container-tag', 'latest']
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            playbook='cli-deployed-ceph.yaml',
            inventory=mock.ANY,
            workdir=mock.ANY,
            playbook_dir=mock.ANY,
            verbosity=3,
            extra_vars={
                "baremetal_deployed_path": mock.ANY,
                "deployed_ceph_tht_path": mock.ANY,
                "working_dir": mock.ANY,
                "stack_name": 'overcloud',
                'tripleo_roles_path': mock.ANY,
                'tripleo_cephadm_container_ns': 'quay.io/ceph',
                'tripleo_cephadm_container_image': 'ceph',
                'tripleo_cephadm_container_tag': 'latest',
            }
        )

    @mock.patch('os.path.abspath', autospect=True)
    @mock.patch('os.path.exists', autospect=True)
    def test_overcloud_deploy_ceph_no_overwrite(self, mock_abspath,
                                                mock_path_exists):
        arglist = ['deployed-metal.yaml',
                   '--stack', 'overcloud',
                   '--output', 'deployed-ceph.yaml']
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.assertRaises(osc_lib_exc.CommandError,
                          self.cmd.take_action, parsed_args)
