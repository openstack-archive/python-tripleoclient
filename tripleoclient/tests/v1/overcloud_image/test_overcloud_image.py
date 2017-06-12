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

from osc_lib import exceptions
from tripleoclient.tests.v1.test_plugin import TestPluginV1
from tripleoclient.v1 import overcloud_image


class TestOvercloudImageBuild(TestPluginV1):

    def setUp(self):
        super(TestOvercloudImageBuild, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_image.BuildOvercloudImage(self.app, None)

    @mock.patch('tripleo_common.image.build.ImageBuildManager', autospec=True)
    def test_overcloud_image_build_default_yaml(self, mock_manager):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_manager.assert_called_once_with(
            ['/usr/share/openstack-tripleo-common/image-yaml/'
             'overcloud-images.yaml',
             '/usr/share/openstack-tripleo-common/image-yaml/'
             'overcloud-images-centos7.yaml'],
            output_directory='.',
            skip=True,
            images=None)

    @mock.patch('tripleo_common.image.build.ImageBuildManager', autospec=True)
    def test_overcloud_image_build_yaml(self, mock_manager):
        arglist = ['--config-file', 'config.yaml']
        verifylist = [('config_files', ['config.yaml'])]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_manager.assert_called_once_with(
            ['config.yaml'],
            output_directory='.',
            skip=True,
            images=None)

    @mock.patch('tripleo_common.image.build.ImageBuildManager', autospec=True)
    def test_overcloud_image_build_multi_yaml(self, mock_manager):
        arglist = ['--config-file', 'config1.yaml',
                   '--config-file', 'config2.yaml']
        verifylist = [('config_files', ['config1.yaml', 'config2.yaml'])]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_manager.assert_called_once_with(
            ['config1.yaml', 'config2.yaml'],
            output_directory='.',
            skip=True,
            images=None)

    @mock.patch('tripleo_common.image.build.ImageBuildManager', autospec=True)
    def test_overcloud_image_build_with_no_skip(self, mock_manager):
        arglist = ['--config-file', 'config.yaml', '--no-skip']
        verifylist = [('config_files', ['config.yaml']),
                      ('skip', False)]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_manager.assert_called_once_with(
            ['config.yaml'],
            output_directory='.',
            skip=False,
            images=None)

    @mock.patch('tripleo_common.image.build.ImageBuildManager', autospec=True)
    def test_overcloud_image_build_with_output_directory(self, mock_manager):
        arglist = ['--config-file', 'config.yaml',
                   '--output-directory', '/tmp/abc']
        verifylist = [('config_files', ['config.yaml']),
                      ('output_directory', '/tmp/abc')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_manager.assert_called_once_with(
            ['config.yaml'],
            output_directory='/tmp/abc',
            skip=True,
            images=None)


class TestUploadOvercloudImage(TestPluginV1):
    def setUp(self):
        super(TestUploadOvercloudImage, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_image.UploadOvercloudImage(self.app, None)
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.image.version = 2.0
        self.app.client_manager.image.images.create.return_value = (
            mock.Mock(id=10, name='imgname', properties={'kernel_id': 10,
                                                         'ramdisk_id': 10},
                      created_at='2015-07-31T14:37:22.000000'))
        self.cmd._read_image_file_pointer = mock.Mock(return_value=b'IMGDATA')
        self.cmd._check_file_exists = mock.Mock(return_value=True)

    @mock.patch('osc_lib.utils.find_resource')
    def test_get_image_exists(self, mock_find_resource):
        image_mock = mock.Mock(name='imagename')
        mock_find_resource.return_value = image_mock
        self.assertEqual(self.cmd._get_image('imagename'), image_mock)

    @mock.patch('osc_lib.utils.find_resource')
    def test_get_image_none(self, mock_find_resource):
        mock_find_resource.side_effect = exceptions.CommandError('')
        self.assertIsNone(self.cmd._get_image('noimagename'))

    def test_image_try_update_no_exist(self):
        self.cmd._get_image = mock.Mock(return_value=None)
        parsed_args = mock.Mock(update_existing=False)
        self.assertFalse(self.cmd._image_try_update('name', 'fn', parsed_args))

    def test_image_try_update_need_update(self):
        image_mock = mock.Mock(name='imagename')
        self.cmd._get_image = mock.Mock(return_value=image_mock)
        self.cmd._image_changed = mock.Mock(return_value=True)
        parsed_args = mock.Mock(update_existing=False)
        self.assertEqual(self.cmd._image_try_update('name', 'fn', parsed_args),
                         image_mock)
        self.assertEqual(
            0,
            self.app.client_manager.image.images.update.call_count
        )

    def test_image_try_update_do_update(self):
        image_mock = mock.Mock(name='imagename',
                               created_at='2015-07-31T14:37:22.000000')
        update_mock = mock.Mock(return_value=image_mock)
        self.app.client_manager.image.images.update = update_mock
        self.cmd._get_image = mock.Mock(return_value=image_mock)
        self.cmd._image_changed = mock.Mock(return_value=True)
        parsed_args = mock.Mock(update_existing=True)
        self.assertEqual(self.cmd._image_try_update('name', 'fn', parsed_args),
                         None)
        self.assertEqual(
            1,
            update_mock.call_count
        )

    @mock.patch('os.path.isfile', autospec=True)
    def test_file_try_update_need_update(self, mock_isfile):
        mock_isfile.return_value = True
        self.cmd._files_changed = mock.Mock(return_value=True)
        self.cmd._copy_file = mock.Mock()

        self.cmd._file_create_or_update('discimg', 'discimgprod', False)
        self.assertEqual(
            0,
            self.cmd._copy_file.call_count
        )

    def test_file_try_update_do_update(self):
        self.cmd._files_changed = mock.Mock(return_value=True)
        self.cmd._copy_file = mock.Mock()

        self.cmd._file_create_or_update('discimg', 'discimgprod', True)
        self.assertEqual(
            1,
            self.cmd._copy_file.call_count
        )

    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_overcloud_create_images_v2(self, mock_subprocess_call,
                                        mock_isfile):
        parsed_args = self.check_parser(self.cmd, [], [])
        mock_isfile.return_value = False

        self.cmd._get_image = mock.Mock(return_value=None)

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.images.delete.call_count
        )
        self.assertEqual(
            5,
            self.app.client_manager.image.images.create.call_count
        )
        self.assertEqual(
            [mock.call(name='overcloud-full-vmlinuz',
                       disk_format='aki',
                       container_format='bare',
                       visibility='public'),
             mock.call(name='overcloud-full-initrd',
                       disk_format='ari',
                       container_format='bare',
                       visibility='public'),
             mock.call(name='overcloud-full',
                       disk_format='qcow2',
                       container_format='bare',
                       visibility='public'),
             mock.call(name='bm-deploy-kernel',
                       disk_format='aki',
                       container_format='bare',
                       visibility='public'),
             mock.call(name='bm-deploy-ramdisk',
                       disk_format='ari',
                       container_format='bare',
                       visibility='public')
             ], self.app.client_manager.image.images.create.call_args_list
        )

        self.assertEqual(mock_subprocess_call.call_count, 2)
        self.assertEqual(
            mock_subprocess_call.call_args_list, [
                mock.call('sudo cp -f "./ironic-python-agent.kernel" '
                          '"/httpboot/agent.kernel"', shell=True),
                mock.call('sudo cp -f "./ironic-python-agent.initramfs" '
                          '"/httpboot/agent.ramdisk"', shell=True)
            ])

    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_overcloud_create_images_v1(self, mock_subprocess_call,
                                        mock_isfile):
        parsed_args = self.check_parser(self.cmd, [], [])
        mock_isfile.return_value = False

        self.cmd._get_image = mock.Mock(return_value=None)
        self.app.client_manager.image.version = 1.0

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
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
                mock.call('sudo cp -f "./ironic-python-agent.kernel" '
                          '"/httpboot/agent.kernel"', shell=True),
                mock.call('sudo cp -f "./ironic-python-agent.initramfs" '
                          '"/httpboot/agent.ramdisk"', shell=True)
            ])

    @mock.patch('os.path.isfile')
    @mock.patch('subprocess.check_call', autospec=True)
    def test_overcloud_create_images_image_path(self, mock_subprocess_call,
                                                mock_isfile):
        parsed_args = self.check_parser(self.cmd,
                                        ['--image-path', '/foo'],
                                        [])
        self.cmd._image_try_update = mock.Mock()
        mock_isfile.return_value = False

        self.cmd.take_action(parsed_args)

        expected = [
            mock.call('overcloud-full-vmlinuz', '/foo/overcloud-full.vmlinuz',
                      mock.ANY),
            mock.call('overcloud-full-initrd', '/foo/overcloud-full.initrd',
                      mock.ANY),
            mock.call('overcloud-full', '/foo/overcloud-full.qcow2',
                      mock.ANY),
            mock.call('bm-deploy-kernel', '/foo/ironic-python-agent.kernel',
                      mock.ANY),
            mock.call('bm-deploy-ramdisk',
                      '/foo/ironic-python-agent.initramfs',
                      mock.ANY),
            ]
        self.assertEqual(expected, self.cmd._image_try_update.mock_calls)

    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_overcloud_create_noupdate_images(self, mock_subprocess_call,
                                              mock_isfile):
        parsed_args = self.check_parser(self.cmd, [], [])
        mock_isfile.return_value = True
        self.cmd._files_changed = mock.Mock(return_value=True)

        existing_image = mock.Mock(id=10, name='imgname',
                                   properties={'kernel_id': 10,
                                               'ramdisk_id': 10})
        self.cmd._get_image = mock.Mock(return_value=existing_image)
        self.cmd._image_changed = mock.Mock(return_value=True)

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.images.delete.call_count
        )
        self.assertEqual(
            0,
            self.app.client_manager.image.images.create.call_count
        )
        self.assertEqual(
            0,
            self.app.client_manager.image.images.update.call_count
        )

        self.assertEqual(mock_subprocess_call.call_count, 0)

    @mock.patch('subprocess.check_call', autospec=True)
    def test_overcloud_create_update_images(self, mock_subprocess_call):
        parsed_args = self.check_parser(self.cmd, ['--update-existing'], [])
        self.cmd._files_changed = mock.Mock(return_value=True)

        existing_image = mock.Mock(id=10, name='imgname',
                                   properties={'kernel_id': 10,
                                               'ramdisk_id': 10},
                                   created_at='2015-07-31T14:37:22.000000')
        self.cmd._get_image = mock.Mock(return_value=existing_image)
        self.cmd._image_changed = mock.Mock(return_value=True)
        self.app.client_manager.image.images.update.return_value = (
            existing_image)

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.images.delete.call_count
        )
        self.assertEqual(
            5,
            self.app.client_manager.image.images.create.call_count
        )
        self.assertEqual(
            6,
            self.app.client_manager.image.images.update.call_count
        )
        self.assertEqual(mock_subprocess_call.call_count, 2)


class TestUploadOvercloudImageFull(TestPluginV1):
    def setUp(self):
        super(TestUploadOvercloudImageFull, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_image.UploadOvercloudImage(self.app, None)
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.image.version = 2.0
        self.app.client_manager.image.images.create.return_value = (
            mock.Mock(id=10, name='imgname', properties={},
                      created_at='2015-07-31T14:37:22.000000'))
        self.cmd._read_image_file_pointer = mock.Mock(return_value=b'IMGDATA')
        self.cmd._check_file_exists = mock.Mock(return_value=True)

    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_overcloud_create_images(self, mock_subprocess_call,
                                     mock_isfile):
        parsed_args = self.check_parser(self.cmd, ['--whole-disk'], [])
        mock_isfile.return_value = False

        self.cmd._get_image = mock.Mock(return_value=None)

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.images.delete.call_count
        )
        self.assertEqual(
            3,
            self.app.client_manager.image.images.create.call_count
        )

        self.assertEqual(
            [mock.call(name='overcloud-full',
                       disk_format='qcow2',
                       container_format='bare',
                       visibility='public'),
             mock.call(name='bm-deploy-kernel',
                       disk_format='aki',
                       container_format='bare',
                       visibility='public'),
             mock.call(name='bm-deploy-ramdisk',
                       disk_format='ari',
                       container_format='bare',
                       visibility='public')
             ], self.app.client_manager.image.images.create.call_args_list
        )

        self.assertEqual(mock_subprocess_call.call_count, 2)
        self.assertEqual(
            mock_subprocess_call.call_args_list, [
                mock.call('sudo cp -f "./ironic-python-agent.kernel" '
                          '"/httpboot/agent.kernel"', shell=True),
                mock.call('sudo cp -f "./ironic-python-agent.initramfs" '
                          '"/httpboot/agent.ramdisk"', shell=True)
            ])

    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_overcloud_create_noupdate_images(self, mock_subprocess_call,
                                              mock_isfile):
        parsed_args = self.check_parser(self.cmd, ['--whole-disk'], [])
        mock_isfile.return_value = True
        self.cmd._files_changed = mock.Mock(return_value=True)

        existing_image = mock.Mock(id=10, name='imgname',
                                   properties={})
        self.cmd._get_image = mock.Mock(return_value=existing_image)
        self.cmd._image_changed = mock.Mock(return_value=True)

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.images.delete.call_count
        )
        self.assertEqual(
            0,
            self.app.client_manager.image.images.create.call_count
        )
        self.assertEqual(
            0,
            self.app.client_manager.image.images.update.call_count
        )

        self.assertEqual(mock_subprocess_call.call_count, 0)

    @mock.patch('subprocess.check_call', autospec=True)
    def test_overcloud_create_update_images(self, mock_subprocess_call):
        parsed_args = self.check_parser(
            self.cmd, ['--update-existing', '--whole-disk'], [])
        self.cmd._files_changed = mock.Mock(return_value=True)

        existing_image = mock.Mock(id=10, name='imgname',
                                   properties={},
                                   created_at='2015-07-31T14:37:22.000000')
        self.cmd._get_image = mock.Mock(return_value=existing_image)
        self.cmd._image_changed = mock.Mock(return_value=True)
        self.app.client_manager.image.images.update.return_value = (
            existing_image)

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.images.delete.call_count
        )
        self.assertEqual(
            3,
            self.app.client_manager.image.images.create.call_count
        )
        self.assertEqual(
            3,
            self.app.client_manager.image.images.update.call_count
        )
        self.assertEqual(mock_subprocess_call.call_count, 2)
