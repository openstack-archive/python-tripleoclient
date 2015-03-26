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

# Load the plugin init module for the plugin list and show commands
from rdomanager_oscplugin.v1 import overcloud_image


class FakePluginV1Client(object):
    def __init__(self, **kwargs):
        self.auth_token = kwargs['token']
        self.management_url = kwargs['endpoint']


class TestOvercloudImageBuild(TestPluginV1):

    def setUp(self):
        super(TestOvercloudImageBuild, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_image.BuildPlugin(self.app, None)


class TestOvercloudImageCreate(TestPluginV1):
    def setUp(self):
        super(TestOvercloudImageCreate, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_image.CreateOvercloud(self.app, None)
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.image.images.create.return_value = \
            mock.Mock(id=10)
        self.cmd._read_image_file_pointer = mock.Mock(return_value=b'IMGDATA')
        self.cmd._check_file_exists = mock.Mock(return_value=True)

    @mock.patch('subprocess.call')
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
                          '"/tftpboot/discovery.kernel"', shell=True),
                mock.call('sudo cp -f "./discovery-ramdisk.initramfs" '
                          '"/tftpboot/discovery.ramdisk"', shell=True)
            ])
