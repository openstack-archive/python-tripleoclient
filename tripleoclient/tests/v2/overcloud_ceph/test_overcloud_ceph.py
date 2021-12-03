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

    @mock.patch('tripleoclient.utils.get_ceph_networks', autospect=True)
    @mock.patch('tripleoclient.utils.TempDirs', autospect=True)
    @mock.patch('os.path.abspath', autospect=True)
    @mock.patch('os.path.exists', autospect=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook', autospec=True)
    def test_overcloud_deploy_ceph(self, mock_playbook, mock_abspath,
                                   mock_path_exists, mock_tempdirs,
                                   mock_get_ceph_networks):
        arglist = ['deployed-metal.yaml', '--yes',
                   '--stack', 'overcloud',
                   '--skip-user-create',
                   '--cephadm-ssh-user', 'jimmy',
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
            skip_tags='cephadm_ssh_user',
            reproduce_command=False,
            extra_vars={
                "baremetal_deployed_path": mock.ANY,
                "deployed_ceph_tht_path": mock.ANY,
                "working_dir": mock.ANY,
                "stack_name": 'overcloud',
                'tripleo_cephadm_ssh_user': 'jimmy',
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


class TestOvercloudCephUserDisable(fakes.FakePlaybookExecution):
    def setUp(self):
        super(TestOvercloudCephUserDisable, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.options = fakes.FakeOptions()
        self.cmd = overcloud_ceph.OvercloudCephUserDisable(self.app,
                                                           app_args)

    @mock.patch('tripleoclient.utils.parse_ansible_inventory',
                autospect=True, return_value=['ceph0', 'ceph1', 'compute0'])
    @mock.patch('tripleoclient.utils.get_host_groups_from_ceph_spec',
                autospect=True, return_value={'_admin': ['ceph0'],
                                              'non_admin': ['ceph1']})
    @mock.patch('tripleoclient.utils.TempDirs', autospect=True)
    @mock.patch('os.path.abspath', autospect=True)
    @mock.patch('os.path.exists', autospect=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook', autospec=True)
    def test_ceph_user_disable(self, mock_playbook, mock_abspath,
                               mock_path_exists, mock_tempdirs,
                               mock_get_host_groups_from_ceph_spec,
                               mock_parse_ansible_inventory):
        arglist = ['ceph_spec.yaml', '--yes',
                   '--cephadm-ssh-user', 'ceph-admin',
                   '--stack', 'overcloud',
                   '--fsid', '7bdfa1a6-d606-562c-bbf7-05f17c35763e']
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_any_call(
            playbook='disable_cephadm.yml',
            inventory=mock.ANY,
            limit_hosts=mock.ANY,
            workdir=mock.ANY,
            playbook_dir=mock.ANY,
            verbosity=3,
            reproduce_command=False,
            extra_vars={
                "tripleo_cephadm_fsid": '7bdfa1a6-d606-562c-bbf7-05f17c35763e',
                "tripleo_cephadm_action": 'disable'
            }
        )
        mock_playbook.assert_any_call(
            playbook='ceph-admin-user-disable.yml',
            inventory=mock.ANY,
            limit_hosts='ceph0,ceph1',
            workdir=mock.ANY,
            playbook_dir=mock.ANY,
            verbosity=3,
            reproduce_command=False,
            extra_vars={
                'tripleo_cephadm_ssh_user': 'ceph-admin',
            }
        )

    @mock.patch('os.path.abspath', autospect=True)
    @mock.patch('os.path.exists', autospect=True)
    def test_ceph_user_disable_no_yes(self, mock_abspath,
                                      mock_path_exists):
        arglist = ['ceph_spec.yaml',
                   '--cephadm-ssh-user', 'ceph-admin',
                   '--stack', 'overcloud',
                   '--fsid', '7bdfa1a6-d606-562c-bbf7-05f17c35763e']
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.assertRaises(osc_lib_exc.CommandError,
                          self.cmd.take_action, parsed_args)

    @mock.patch('os.path.abspath', autospect=True)
    @mock.patch('os.path.exists', autospect=True)
    def test_ceph_user_disable_invalid_fsid(self, mock_abspath,
                                            mock_path_exists):
        arglist = ['ceph_spec.yaml',
                   '--cephadm-ssh-user', 'ceph-admin',
                   '--stack', 'overcloud',
                   '--fsid', 'invalid_fsid']
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.assertRaises(osc_lib_exc.CommandError,
                          self.cmd.take_action, parsed_args)


class TestOvercloudCephUserEnable(fakes.FakePlaybookExecution):
    def setUp(self):
        super(TestOvercloudCephUserEnable, self).setUp()

        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.options = fakes.FakeOptions()
        self.cmd = overcloud_ceph.OvercloudCephUserEnable(self.app,
                                                          app_args)

    @mock.patch('tripleoclient.utils.parse_ansible_inventory',
                autospect=True, return_value=['ceph0', 'ceph1', 'compute0'])
    @mock.patch('tripleoclient.utils.get_host_groups_from_ceph_spec',
                autospect=True, return_value={'_admin': ['ceph0'],
                                              'non_admin': ['ceph1']})
    @mock.patch('tripleoclient.utils.TempDirs', autospect=True)
    @mock.patch('os.path.abspath', autospect=True)
    @mock.patch('os.path.exists', autospect=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook', autospec=True)
    def test_ceph_user_enable_no_fsid(self, mock_playbook, mock_abspath,
                                      mock_path_exists, mock_tempdirs,
                                      mock_get_host_groups_from_ceph_spec,
                                      mock_parse_ansible_inventory):
        arglist = ['ceph_spec.yaml',
                   '--cephadm-ssh-user', 'ceph-admin',
                   '--stack', 'overcloud']
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)
        # only passes if the call is the most recent one
        mock_playbook.assert_called_with(
            playbook='ceph-admin-user-playbook.yml',
            inventory=mock.ANY,
            limit_hosts='ceph1,undercloud',
            workdir=mock.ANY,
            playbook_dir=mock.ANY,
            verbosity=3,
            reproduce_command=False,
            extra_vars={
                "tripleo_admin_user": 'ceph-admin',
                "distribute_private_key": False,
            }
        )

    @mock.patch('tripleoclient.utils.parse_ansible_inventory',
                autospect=True)
    @mock.patch('tripleoclient.utils.get_host_groups_from_ceph_spec',
                autospect=True)
    @mock.patch('tripleoclient.utils.TempDirs', autospect=True)
    @mock.patch('os.path.abspath', autospect=True)
    @mock.patch('os.path.exists', autospect=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook', autospec=True)
    def test_ceph_user_enable_fsid(self, mock_playbook, mock_abspath,
                                   mock_path_exists, mock_tempdirs,
                                   mock_get_host_groups_from_ceph_spec,
                                   mock_parse_ansible_inventory):
        arglist = ['ceph_spec.yaml',
                   '--cephadm-ssh-user', 'ceph-admin',
                   '--stack', 'overcloud',
                   '--fsid', '7bdfa1a6-d606-562c-bbf7-05f17c35763e']
        parsed_args = self.check_parser(self.cmd, arglist, [])
        self.cmd.take_action(parsed_args)
        # ceph-admin-user-playbook.yml is not called when
        # get_host_groups_from_ceph_spec returns empty lists
        # that use case is covered in test_ceph_user_enable_no_fsid
        mock_playbook.assert_called_with(
            playbook='disable_cephadm.yml',
            inventory=mock.ANY,
            limit_hosts=mock.ANY,
            workdir=mock.ANY,
            playbook_dir=mock.ANY,
            verbosity=3,
            reproduce_command=False,
            extra_vars={
                "tripleo_cephadm_fsid": '7bdfa1a6-d606-562c-bbf7-05f17c35763e',
                "tripleo_cephadm_backend": 'cephadm',
                "tripleo_cephadm_action": 'enable'
            }
        )
