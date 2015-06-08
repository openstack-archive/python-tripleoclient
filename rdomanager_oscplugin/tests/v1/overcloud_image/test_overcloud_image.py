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

from rdomanager_oscplugin.tests.v1.test_plugin import TestPluginV1
from rdomanager_oscplugin.v1 import overcloud_image


class TestOvercloudImageBuild(TestPluginV1):

    def setUp(self):
        super(TestOvercloudImageBuild, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_image.BuildOvercloudImage(self.app, None)
        self.cmd._disk_image_create = mock.Mock()
        self.cmd._ramdisk_image_create = mock.Mock()

    @mock.patch.object(overcloud_image.BuildOvercloudImage,
                       '_build_image_fedora_user', autospec=True)
    def test_overcloud_image_build_all(self, mock_fedora_user):
        arglist = ['--all']
        verifylist = [('all', True)]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self.assertEqual(2, self.cmd._ramdisk_image_create.call_count)
        self.assertEqual(1, self.cmd._disk_image_create.call_count)
        self.assertEqual(1, mock_fedora_user.call_count)

    @mock.patch('subprocess.call', autospec=True)
    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('os.chmod')
    @mock.patch('requests.get', autospec=True)
    def test_overcloud_image_build_fedora_user_no_cache(
            self,
            mock_requests_get,
            mock_os_chmod,
            mock_os_path_isfile,
            mock_subprocess_call):
        arglist = ['--type', 'fedora-user']
        verifylist = [('image_types', ['fedora-user'])]

        def os_path_isfile_side_effect(arg):
            return {
                'fedora-user.qcow2': False,
                '~/.cache/image-create/fedora-21.x86_64.qcow2': False,
            }[arg]

        mock_os_path_isfile.side_effect = os_path_isfile_side_effect
        requests_get_response = mock.Mock(spec="content")
        requests_get_response.content = "FEDORAIMAGE".encode('utf-8')
        mock_requests_get.return_value = requests_get_response

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        mock_open_context = mock.mock_open()
        mock_open_context().readline.return_value = "Red Hat Enterprise Linux"

        with mock.patch('six.moves.builtins.open', mock_open_context):
            self.cmd.take_action(parsed_args)

        mock_requests_get.assert_called_once_with(
            'http://cloud.fedoraproject.org/fedora-21.x86_64.qcow2')
        self.assertEqual(2, mock_os_path_isfile.call_count)
        self.assertEqual(1, mock_os_chmod.call_count)
        mock_open_context.assert_has_calls(
            [mock.call('fedora-user.qcow2', 'wb')])

    @mock.patch('os.path.isfile', autospec=True)
    def test_overcloud_image_build_overcloud_full(
            self,
            mock_os_path_isfile):
        arglist = ['--type', 'overcloud-full']
        verifylist = [('image_types', ['overcloud-full'])]

        def os_path_isfile_side_effect(arg):
            return {
                'overcloud-full.qcow2': False,
            }[arg]

        mock_os_path_isfile.side_effect = os_path_isfile_side_effect

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        mock_open_context = mock.mock_open()
        mock_open_context().readline.return_value = "Red Hat Enterprise Linux"

        with mock.patch('six.moves.builtins.open', mock_open_context):
            self.cmd.take_action(parsed_args)

        self.cmd._disk_image_create.assert_called_once_with(
            "-a amd64 -o "
            "overcloud-full.qcow2 rhel7 overcloud-full overcloud-controller "
            "overcloud-compute overcloud-ceph-storage sysctl hosts baremetal "
            "dhcp-all-interfaces os-collect-config heat-config-puppet "
            "heat-config-script puppet-modules hiera os-net-config "
            "stable-interface-names grub2-deprecated "
            "-p python-psutil,python-debtcollector selinux-permissive "
            "element-manifest network-gateway epel rdo-release "
            "undercloud-package-install "
            "pip-and-virtualenv-override 2>&1 | tee dib-overcloud-full.log")

    @mock.patch('os.path.isfile', autospec=True)
    def test_overcloud_image_build_deploy_ramdisk(
            self,
            mock_os_path_isfile):
        arglist = ['--type', 'deploy-ramdisk']
        verifylist = [('image_types', ['deploy-ramdisk'])]

        def os_path_isfile_side_effect(arg):
            return {
                'deploy-ramdisk-ironic.initramfs': False,
                'deploy-ramdisk-ironic.kernel': False,
            }[arg]

        mock_os_path_isfile.side_effect = os_path_isfile_side_effect

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        mock_open_context = mock.mock_open()
        mock_open_context().readline.return_value = "Red Hat Enterprise Linux"

        with mock.patch('six.moves.builtins.open', mock_open_context):
            self.cmd.take_action(parsed_args)

        self.cmd._ramdisk_image_create.assert_called_once_with(
            "-a amd64 -o deploy-ramdisk-ironic --ramdisk-element "
            "dracut-ramdisk rhel7 deploy-ironic selinux-permissive "
            "element-manifest network-gateway epel rdo-release "
            "undercloud-package-install "
            "pip-and-virtualenv-override 2>&1 | tee dib-deploy.log")


class TestUploadOvercloudImage(TestPluginV1):
    def setUp(self):
        super(TestUploadOvercloudImage, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_image.UploadOvercloudImage(self.app, None)
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.image.images.create.return_value = \
            mock.Mock(id=10)
        self.cmd._read_image_file_pointer = mock.Mock(return_value=b'IMGDATA')
        self.cmd._check_file_exists = mock.Mock(return_value=True)

    @mock.patch('subprocess.call', autospec=True)
    def test_overcloud_create_images(self, mock_subprocess_call):
        parsed_args = self.check_parser(self.cmd, [], [])

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            2,
            self.app.client_manager.image.images.delete.call_count
        )
        self.assertEqual(
            5,
            self.app.client_manager.image.images.create.call_count
        )
        self.assertEqual(
            [mock.call(data=b'IMGDATA',
                       name='overcloud-full-vmlinuz',
                       disk_format='aki',
                       is_public=True),
             mock.call(data=b'IMGDATA',
                       name='overcloud-full-initrd',
                       disk_format='ari',
                       is_public=True),
             mock.call(properties={'kernel_id': 10, 'ramdisk_id': 10},
                       name='overcloud-full',
                       data=b'IMGDATA',
                       container_format='bare',
                       disk_format='qcow2',
                       is_public=True),
             mock.call(data=b'IMGDATA',
                       name='bm-deploy-kernel',
                       disk_format='aki',
                       is_public=True),
             mock.call(data=b'IMGDATA',
                       name='bm-deploy-ramdisk',
                       disk_format='ari',
                       is_public=True)
             ], self.app.client_manager.image.images.create.call_args_list
        )

        self.assertEqual(mock_subprocess_call.call_count, 2)
        self.assertEqual(
            mock_subprocess_call.call_args_list, [
                mock.call('sudo cp -f "./discovery-ramdisk.kernel" '
                          '"/httpboot/discovery.kernel"', shell=True),
                mock.call('sudo cp -f "./discovery-ramdisk.initramfs" '
                          '"/httpboot/discovery.ramdisk"', shell=True)
            ])
