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

from datetime import datetime
import mock
import os

from osc_lib import exceptions
import tripleo_common.arch
from tripleoclient.tests import base
from tripleoclient.tests.fakes import FakeHandle
from tripleoclient.tests.v1.test_plugin import TestPluginV1
from tripleoclient import utils as plugin_utils
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
             'overcloud-images-python3.yaml',
             '/usr/share/openstack-tripleo-common/image-yaml/'
             'overcloud-images-centos8.yaml'],
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


class TestBaseClientAdapter(base.TestCommand):

    def setUp(self):
        super(TestBaseClientAdapter, self).setUp()
        self.adapter = overcloud_image.BaseClientAdapter('/foo')

    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'BaseClientAdapter._files_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'BaseClientAdapter._copy_file', autospec=True)
    def test_file_try_update_need_update(self,
                                         mock_copy_file,
                                         mock_files_changed,
                                         mock_isfile):
        mock_isfile.return_value = True
        mock_files_changed.return_value = True

        self.adapter.file_create_or_update('discimg', 'discimgprod')
        mock_copy_file.assert_not_called()

    @mock.patch('tripleoclient.v1.overcloud_image.'
                'BaseClientAdapter._files_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'BaseClientAdapter._copy_file', autospec=True)
    def test_file_try_update_do_update(self,
                                       mock_copy_file,
                                       mock_files_changed):
        mock_files_changed.return_value = True

        self.update_existing = True
        self.adapter.file_create_or_update('discimg', 'discimgprod')
        mock_copy_file.assert_called_once_with(
            self.adapter, 'discimg', 'discimgprod')

    @mock.patch('subprocess.check_call', autospec=True)
    def test_copy_file(self, mock_subprocess_call):
        self.adapter._copy_file('/foo.qcow2', 'bar.qcow2')
        mock_subprocess_call.assert_called_once_with(
            'sudo cp -f "/foo.qcow2" "bar.qcow2"', shell=True)

    @mock.patch('subprocess.check_call', autospec=True)
    def test_move_file(self, mock_subprocess_call):
        self.adapter._move_file('/foo.qcow2', 'bar.qcow2')
        mock_subprocess_call.assert_called_once_with(
            'sudo mv "/foo.qcow2" "bar.qcow2"', shell=True)

    @mock.patch('subprocess.check_call', autospec=True)
    def test_make_dirs(self, mock_subprocess_call):
        self.adapter._make_dirs('/foo/bar/baz')
        mock_subprocess_call.assert_called_once_with(
            'sudo mkdir -m 0775 -p "/foo/bar/baz"', shell=True)


class TestFileImageClientAdapter(TestPluginV1):

    def setUp(self):
        super(TestFileImageClientAdapter, self).setUp()
        self.updated = []
        self.adapter = overcloud_image.FileImageClientAdapter(
            image_path='/home/foo',
            local_path='/my/images',
            updated=self.updated
        )
        self.image = mock.Mock()
        self.image.id = 'file:///my/images/x86_64/overcloud-full.qcow2'
        self.image.name = 'overcloud-full'
        self.image.checksum = 'asdf'
        self.image.created_at = '2019-11-14T01:33:39'
        self.image.size = 982802432

    @mock.patch('os.path.exists')
    def test_get_image_property(self, mock_exists):
        mock_exists.side_effect = [
            True, True, False, False
        ]
        image = mock.Mock()
        image.id = 'file:///my/images/x86_64/overcloud-full.qcow2'
        # file exists
        self.assertEqual(
            'file:///my/images/x86_64/overcloud-full.vmlinuz',
            self.adapter.get_image_property(image, 'kernel_id')
        )
        self.assertEqual(
            'file:///my/images/x86_64/overcloud-full.initrd',
            self.adapter.get_image_property(image, 'ramdisk_id')
        )
        # file doesn't exist
        self.assertIsNone(
            self.adapter.get_image_property(image, 'kernel_id')
        )
        self.assertIsNone(
            self.adapter.get_image_property(image, 'ramdisk_id')
        )
        self.assertRaises(ValueError, self.adapter.get_image_property,
                          image, 'foo')

    def test_paths(self):
        self.assertEqual(
            ('/my/images/x86_64',
             'overcloud-full.vmlinuz'),
            self.adapter._paths(
                'overcloud-full',
                plugin_utils.overcloud_kernel,
                'x86_64',
                None
            )
        )
        self.assertEqual(
            ('/my/images',
             'overcloud-full.qcow2'),
            self.adapter._paths(
                'overcloud-full',
                plugin_utils.overcloud_image,
                None,
                None
            )
        )
        self.assertEqual(
            ('/my/images/power9-ppc64le',
             'overcloud-full.initrd'),
            self.adapter._paths(
                'overcloud-full',
                plugin_utils.overcloud_ramdisk,
                'ppc64le',
                'power9'
            )
        )

    @mock.patch('os.path.exists')
    @mock.patch('os.stat')
    @mock.patch('tripleoclient.utils.file_checksum')
    def test_get_image(self, mock_checksum, mock_stat, mock_exists):
        st_mtime = 1573695219
        mock_exists.return_value = True
        mock_stat.return_value.st_size = 982802432
        mock_stat.return_value.st_mtime = st_mtime
        mock_checksum.return_value = 'asdf'

        image = self.adapter._get_image(
            '/my/images/x86_64/overcloud-full.qcow2')
        self.assertEqual(
            'file:///my/images/x86_64/overcloud-full.qcow2',
            image.id
        )
        self.assertEqual('overcloud-full', image.name)
        self.assertEqual('asdf', image.checksum)
        self.assertEqual(datetime.fromtimestamp(st_mtime).strftime("%M:%S"),
                         datetime.strptime(
            image.created_at, "%Y-%m-%dT%H:%M:%S").strftime("%M:%S"))
        self.assertEqual(982802432, image.size)

    @mock.patch('tripleoclient.utils.file_checksum')
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'FileImageClientAdapter._get_image', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'BaseClientAdapter._move_file', autospec=True)
    def test_image_try_update(self, mock_move, mock_get_image, mock_checksum):

        # existing image with identical checksum
        mock_checksum.return_value = 'asdf'
        mock_get_image.return_value = self.image
        self.assertEqual(
            self.image,
            self.adapter._image_try_update(
                '/home/foo/overcloud-full.qcow2',
                '/my/images/x86_64/overcloud-full.qcow2'
            )
        )
        self.assertEqual([], self.updated)

        # no image to update
        mock_get_image.return_value = None
        self.assertIsNone(
            self.adapter._image_try_update(
                '/home/foo/overcloud-full.qcow2',
                '/my/images/x86_64/overcloud-full.qcow2'
            )
        )
        self.assertEqual([], self.updated)

        # existing image with different checksum, but update_existing=False
        mock_checksum.return_value = 'fdsa'
        mock_get_image.return_value = self.image
        self.assertEqual(
            self.image,
            self.adapter._image_try_update(
                '/home/foo/overcloud-full.qcow2',
                '/my/images/x86_64/overcloud-full.qcow2'
            )
        )
        self.assertEqual([], self.updated)

        # existing image with different checksum, update_existing=True
        self.adapter.update_existing = True
        self.assertIsNone(
            self.adapter._image_try_update(
                '/home/foo/overcloud-full.qcow2',
                '/my/images/x86_64/overcloud-full.qcow2'
            )
        )
        self.assertEqual(
            ['/my/images/x86_64/overcloud-full.qcow2'],
            self.updated
        )
        mock_move.assert_called_once_with(
            self.adapter,
            '/my/images/x86_64/overcloud-full.qcow2',
            '/my/images/x86_64/overcloud-full_20191114T013339.qcow2'
        )

    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'FileImageClientAdapter._get_image', autospec=True)
    @mock.patch('os.path.isdir')
    def test_upload_image(self, mock_isdir, mock_get_image,
                          mock_subprocess_call):
        mock_isdir.return_value = False

        mock_get_image.return_value = self.image

        result = self.adapter._upload_image(
            '/home/foo/overcloud-full.qcow2',
            '/my/images/x86_64/overcloud-full.qcow2'
        )
        self.assertEqual(self.image, result)
        mock_subprocess_call.assert_has_calls([
            mock.call('sudo mkdir -m 0775 -p "/my/images/x86_64"', shell=True),
            mock.call('sudo cp -f "/home/foo/overcloud-full.qcow2" '
                      '"/my/images/x86_64/overcloud-full.qcow2"', shell=True)
        ])

    @mock.patch('tripleoclient.v1.overcloud_image.'
                'FileImageClientAdapter._upload_image', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'FileImageClientAdapter._image_try_update', autospec=True)
    def test_update_or_upload(self, mock_image_try_update, mock_upload_image):

        # image exists
        mock_image_try_update.return_value = self.image
        self.assertEqual(
            self.image,
            self.adapter.update_or_upload(
                image_name='overcloud-full',
                properties={},
                names_func=plugin_utils.overcloud_image,
                arch='x86_64'
            )
        )
        mock_upload_image.assert_not_called()

        # image needs uploading
        mock_image_try_update.return_value = None
        mock_upload_image.return_value = self.image
        self.assertEqual(
            self.image,
            self.adapter.update_or_upload(
                image_name='overcloud-full',
                properties={},
                names_func=plugin_utils.overcloud_image,
                arch='x86_64'
            )
        )
        mock_upload_image.assert_called_once_with(
            self.adapter,
            '/home/foo/overcloud-full.qcow2',
            '/my/images/x86_64/overcloud-full.qcow2'
        )
        mock_image_try_update.assert_has_calls([
            mock.call(self.adapter,
                      '/home/foo/overcloud-full.qcow2',
                      '/my/images/x86_64/overcloud-full.qcow2'),
            mock.call(self.adapter,
                      '/home/foo/overcloud-full.qcow2',
                      '/my/images/x86_64/overcloud-full.qcow2')
        ])


class TestGlanceClientAdapter(TestPluginV1):

    def setUp(self):
        super(TestGlanceClientAdapter, self).setUp()
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.image.version = 2.0
        self._arch = tripleo_common.arch.kernel_arch()
        self.app.client_manager.image.images.create.return_value = (
            mock.Mock(id=10, name='imgname',
                      properties={'kernel_id': 10, 'ramdisk_id': 10,
                                  'hw_architecture': self._arch},
                      created_at='2015-07-31T14:37:22.000000'))
        self.updated = []
        self.adapter = overcloud_image.GlanceClientAdapter(
            client=self.app.client_manager.image,
            image_path='/foo',
            updated=self.updated
        )

    def test_get_image_exists(self):
        image_mock = mock.Mock(name='imagename')
        self.app.client_manager.image.find_image.return_value = image_mock
        self.assertEqual(self.adapter._get_image('imagename'), image_mock)

    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._get_image', autospec=True)
    def test_image_try_update_no_exist(self, mock_get_image):
        mock_get_image.return_value = None
        self.assertFalse(self.adapter._image_try_update(
            'name', 'fn'))
        self.assertEqual([], self.updated)

    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._get_image', autospec=True)
    def test_image_try_update_need_update(self,
                                          mock_get_image,
                                          mock_image_changed):
        image_mock = mock.Mock(name='imagename')
        mock_get_image.return_value = image_mock
        mock_image_changed.return_value = True
        self.assertEqual(
            self.adapter._image_try_update('name', 'fn'),
            image_mock
        )
        self.assertEqual([], self.updated)
        self.app.client_manager.image.update_image.assert_not_called()

    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._get_image', autospec=True)
    def test_image_try_update_do_update(self,
                                        mock_get_image,
                                        mock_image_changed):
        image_mock = mock.Mock(name='imagename',
                               created_at='2015-07-31T14:37:22.000000')
        update_mock = mock.Mock(return_value=image_mock)
        self.app.client_manager.image.update_image = update_mock
        mock_get_image.return_value = image_mock
        mock_image_changed.return_value = True
        self.adapter.update_existing = True
        self.assertEqual(
            self.adapter._image_try_update('name', 'fn'),
            None
        )
        self.assertEqual([image_mock.id], self.updated)
        update_mock.assert_called_once()


class TestUploadOvercloudImage(TestPluginV1):

    def setUp(self):
        super(TestUploadOvercloudImage, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_image.UploadOvercloudImage(self.app, None)
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.image.version = 2.0
        self._arch = tripleo_common.arch.kernel_arch()
        self.app.client_manager.image.create_image.return_value = (
            mock.Mock(id=10, name='imgname',
                      properties={'kernel_id': 10, 'ramdisk_id': 10,
                                  'hw_architecture': self._arch},
                      created_at='2015-07-31T14:37:22.000000'))
        mock_cfe = mock.patch('tripleoclient.v1.overcloud_image.'
                              'BaseClientAdapter.check_file_exists',
                              autospec=True)
        mock_cfe.start()
        self.addCleanup(mock_cfe.stop)
        mock_cfe.return_value = True

        mock_rifp = mock.patch('tripleoclient.v1.overcloud_image.'
                               'BaseClientAdapter.read_image_file_pointer',
                               autospec=True)
        mock_rifp.start()
        self.addCleanup(mock_rifp.stop)
        self._file_handle = FakeHandle()
        mock_rifp.return_value = self._file_handle

    @mock.patch.dict(os.environ, {'KEY': 'VALUE', 'OLD_KEY': 'OLD_VALUE'})
    def test_get_environment_var(self):
        self.assertEqual('default-value',
                         self.cmd._get_environment_var('MISSING',
                                                       'default-value'))
        self.assertEqual('VALUE',
                         self.cmd._get_environment_var('KEY',
                                                       'default-value'))
        self.assertEqual('VALUE',
                         self.cmd._get_environment_var('KEY',
                                                       'default-value',
                                                       deprecated=['MISSING']))
        self.assertEqual('OLD_VALUE',
                         self.cmd._get_environment_var('KEY',
                                                       'default-value',
                                                       deprecated=['OLD_KEY']))

    def test_platform_without_architecture_fail(self):
        parsed_args = self.check_parser(self.cmd, ['--platform', 'SNB'], [])
        self.assertRaises(exceptions.CommandError,
                          self.cmd.take_action,
                          parsed_args)

    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._get_image', autospec=True)
    def test_overcloud_create_images_v2(self,
                                        mock_get_image,
                                        mock_subprocess_call,
                                        mock_isfile):
        parsed_args = self.check_parser(self.cmd, [], [])
        mock_isfile.return_value = False

        mock_get_image.return_value = None

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.images.delete.call_count
        )
        self.assertEqual(
            3,
            self.app.client_manager.image.create_image.call_count
        )
        self.app.client_manager.image.create_image.assert_has_calls([
            mock.call(name='overcloud-full-vmlinuz',
                      disk_format='aki',
                      container_format='bare',
                      data=mock.ANY,
                      validate_checksum=False,
                      visibility='public'),
            mock.call(name='overcloud-full-initrd',
                      disk_format='ari',
                      container_format='bare',
                      data=mock.ANY,
                      validate_checksum=False,
                      visibility='public'),
            mock.call(name='overcloud-full',
                      disk_format='qcow2',
                      container_format='bare',
                      data=mock.ANY,
                      validate_checksum=False,
                      visibility='public'),
        ])

        self.assertEqual(mock_subprocess_call.call_count, 2)
        mock_subprocess_call.assert_has_calls([
            mock.call('sudo cp -f "./ironic-python-agent.kernel" '
                      '"/var/lib/ironic/httpboot/agent.kernel"', shell=True),
            mock.call('sudo cp -f "./ironic-python-agent.initramfs" '
                      '"/var/lib/ironic/httpboot/agent.ramdisk"', shell=True)
        ])

    @mock.patch('os.path.isfile')
    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._get_image', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_try_update', autospec=True)
    def test_overcloud_create_images_image_path(self,
                                                mock_image_try_update,
                                                mock_get_image,
                                                mock_subprocess_call,
                                                mock_isfile):
        parsed_args = self.check_parser(self.cmd,
                                        ['--image-path', '/foo'],
                                        [])
        mock_get_image.return_value = None
        mock_image_try_update.return_value = None
        mock_isfile.return_value = False

        self.cmd.take_action(parsed_args)

        self.cmd.adapter._image_try_update.assert_has_calls([
            mock.call(self.cmd.adapter,
                      'overcloud-full-vmlinuz',
                      '/foo/overcloud-full.vmlinuz'),
            mock.call(self.cmd.adapter,
                      'overcloud-full-initrd',
                      '/foo/overcloud-full.initrd'),
            mock.call(self.cmd.adapter,
                      'overcloud-full',
                      '/foo/overcloud-full.qcow2'),
        ])
        mock_subprocess_call.assert_has_calls([
            mock.call('sudo cp -f "/foo/ironic-python-agent.kernel" '
                      '"/var/lib/ironic/httpboot/agent.kernel"', shell=True),
            mock.call('sudo cp -f "/foo/ironic-python-agent.initramfs" '
                      '"/var/lib/ironic/httpboot/agent.ramdisk"', shell=True)
        ])

    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._get_image', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'BaseClientAdapter._files_changed', autospec=True)
    def test_overcloud_create_noupdate_images(self,
                                              mock_files_changed,
                                              mock_image_changed,
                                              mock_get_image,
                                              mock_subprocess_call,
                                              mock_isfile):
        parsed_args = self.check_parser(self.cmd, [], [])
        mock_isfile.return_value = True
        mock_files_changed.return_value = True

        existing_image = mock.Mock(id=10, name='imgname',
                                   properties={'kernel_id': 10,
                                               'ramdisk_id': 10})
        mock_get_image.return_value = existing_image
        mock_image_changed.return_value = True

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.delete_image.call_count
        )
        self.assertEqual(
            0,
            self.app.client_manager.image.create_image.call_count
        )
        self.assertEqual(
            0,
            self.app.client_manager.image.image_update.call_count
        )

        self.assertEqual(mock_subprocess_call.call_count, 0)
        self.assertFalse(self.cmd.updated)

    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._get_image', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'BaseClientAdapter._files_changed', autospec=True)
    def test_overcloud_create_update_images(self,
                                            mock_files_changed,
                                            mock_image_changed,
                                            mock_get_image,
                                            mock_subprocess_call):
        parsed_args = self.check_parser(self.cmd, ['--update-existing'], [])
        mock_files_changed.return_value = True

        existing_image = mock.Mock(id=10, name='imgname',
                                   properties={'kernel_id': 10,
                                               'ramdisk_id': 10},
                                   created_at='2015-07-31T14:37:22.000000')
        mock_get_image.return_value = existing_image
        mock_image_changed.return_value = True
        self.app.client_manager.image.image_update.return_value = (
            existing_image)

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.delete_image.call_count
        )
        self.assertEqual(
            3,
            self.app.client_manager.image.create_image.call_count
        )
        self.assertEqual(
            6,  # 3 for new uploads, 3 updating the existsing
            self.app.client_manager.image.update_image.call_count
        )
        self.assertEqual(mock_subprocess_call.call_count, 2)
        self.assertTrue(self.cmd.updated)


class TestUploadOvercloudImageFull(TestPluginV1):

    def setUp(self):
        super(TestUploadOvercloudImageFull, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_image.UploadOvercloudImage(self.app, None)
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.image.version = 2.0
        self._arch = tripleo_common.arch.kernel_arch()
        self.app.client_manager.image.create_image.return_value = (
            mock.Mock(id=10, name='imgname',
                      properties={'hw_architecture': self._arch},
                      created_at='2015-07-31T14:37:22.000000'))
        mock_cfe = mock.patch('tripleoclient.v1.overcloud_image.'
                              'BaseClientAdapter.check_file_exists',
                              autospec=True)
        mock_cfe.start()
        self.addCleanup(mock_cfe.stop)
        mock_cfe.return_value = True

        mock_rifp = mock.patch('tripleoclient.v1.overcloud_image.'
                               'BaseClientAdapter.read_image_file_pointer',
                               autospec=True)
        mock_rifp.start()
        self.addCleanup(mock_rifp.stop)
        self._file_handle = FakeHandle()
        mock_rifp.return_value = self._file_handle

    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._get_image', autospec=True)
    def test_overcloud_create_images(self,
                                     mock_get_image,
                                     mock_subprocess_call,
                                     mock_isfile):
        parsed_args = self.check_parser(self.cmd, ['--whole-disk'], [])
        mock_isfile.return_value = False

        mock_get_image.return_value = None

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.delete_image.call_count
        )
        self.assertEqual(
            1,
            self.app.client_manager.image.create_image.call_count
        )

        self.app.client_manager.image.create_image.assert_has_calls([
            mock.call(name='overcloud-full',
                      disk_format='qcow2',
                      container_format='bare',
                      data=mock.ANY,
                      validate_checksum=False,
                      visibility='public',),
        ])
        # properties are set by updating the image
        self.app.client_manager.image.update_image.assert_has_calls([
            mock.call(mock.ANY, hw_architecture=self._arch),
        ])

        self.assertEqual(mock_subprocess_call.call_count, 2)
        mock_subprocess_call.assert_has_calls([
            mock.call('sudo cp -f "./ironic-python-agent.kernel" '
                      '"/var/lib/ironic/httpboot/agent.kernel"', shell=True),
            mock.call('sudo cp -f "./ironic-python-agent.initramfs" '
                      '"/var/lib/ironic/httpboot/agent.ramdisk"', shell=True)
        ])

    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._get_image', autospec=True)
    def test_overcloud_create_images_with_arch(self,
                                               mock_get_image,
                                               mock_subprocess_call,
                                               mock_isfile):
        parsed_args = self.check_parser(self.cmd,
                                        ['--whole-disk', '--arch', 'ppc64le'],
                                        [])
        mock_isfile.return_value = False

        mock_get_image.return_value = None

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.delete_image.call_count
        )
        self.assertEqual(
            1,
            self.app.client_manager.image.create_image.call_count
        )

        self.app.client_manager.image.create_image.assert_has_calls([
            mock.call(name='ppc64le-overcloud-full',
                      disk_format='qcow2',
                      container_format='bare',
                      data=mock.ANY,
                      validate_checksum=False,
                      visibility='public'),
        ])

        self.app.client_manager.image.update_image.assert_has_calls([
            mock.call(mock.ANY, hw_architecture='ppc64le'),
        ])
        self.assertEqual(mock_subprocess_call.call_count, 2)
        mock_subprocess_call.assert_has_calls([
            mock.call('sudo cp -f "./ironic-python-agent.kernel" '
                      '"/var/lib/ironic/httpboot/agent.kernel"', shell=True),
            mock.call('sudo cp -f "./ironic-python-agent.initramfs" '
                      '"/var/lib/ironic/httpboot/agent.ramdisk"', shell=True)
        ])

    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'BaseClientAdapter._files_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._get_image', autospec=True)
    def test_overcloud_create_noupdate_images(self, mock_get_image,
                                              mock_files_changed,
                                              mock_image_changed,
                                              mock_subprocess_call,
                                              mock_isfile):
        parsed_args = self.check_parser(self.cmd, ['--whole-disk'], [])
        mock_isfile.return_value = True
        mock_files_changed.return_value = True

        existing_image = mock.Mock(id=10, name='imgname',
                                   properties={'hw_architecture': self._arch})
        mock_get_image.return_value = existing_image
        self.cmd._image_changed = mock.Mock(return_value=True)
        mock_image_changed.return_value = True

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.delete_image.call_count
        )
        self.assertEqual(
            0,
            self.app.client_manager.image.create_image.call_count
        )
        self.assertEqual(
            0,
            self.app.client_manager.image.update_image.call_count
        )

        self.assertEqual(mock_subprocess_call.call_count, 0)

    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'BaseClientAdapter._files_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._get_image', autospec=True)
    def test_overcloud_create_update_images(self, mock_get_image,
                                            mock_files_changed,
                                            mock_image_changed,
                                            mock_subprocess_call):
        parsed_args = self.check_parser(
            self.cmd, ['--update-existing', '--whole-disk'], [])
        mock_files_changed.return_value = True

        existing_image = mock.Mock(id=10, name='imgname',
                                   properties={'hw_architecture': self._arch},
                                   created_at='2015-07-31T14:37:22.000000')
        mock_get_image.return_value = existing_image
        mock_image_changed.return_value = True
        self.app.client_manager.image.update_image.return_value = (
            existing_image)

        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.delete_image.call_count
        )
        self.assertEqual(
            1,
            self.app.client_manager.image.create_image.call_count
        )
        self.assertEqual(
            2,  # update 1 image *and* add properties to 1 image
            self.app.client_manager.image.update_image.call_count
        )
        self.assertEqual(mock_subprocess_call.call_count, 2)


class TestUploadOvercloudImageFullMultiArch(TestPluginV1):
    # NOTE(tonyb): Really only the id is important below, but the names make
    # reading logfiles a little nicer
    images = [
        mock.Mock(id=10, name='overcloud-full'),
        mock.Mock(id=11, name='ppc64le-overcloud-full'),
        mock.Mock(id=12, name='p9-ppc64le-overcloud-full'),
    ]

    def setUp(self):
        super(TestUploadOvercloudImageFullMultiArch, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_image.UploadOvercloudImage(self.app, None)
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.image.version = 2.0
        # NOTE(tonyb): This is a little fragile.  It works because
        # GlanceClientAdapter._upload_image() calls
        # self.client.images.create() and self.client.images.get() once each
        # call so this way we always create() and get() the same mocked "image"
        self.app.client_manager.image.create_image.side_effect = self.images
        self.app.client_manager.image.get_image.side_effect = self.images

        mock_cfe = mock.patch('tripleoclient.v1.overcloud_image.'
                              'BaseClientAdapter.check_file_exists',
                              autospec=True)
        mock_cfe.start()
        self.addCleanup(mock_cfe.stop)
        mock_cfe.return_value = True

        mock_rifp = mock.patch('tripleoclient.v1.overcloud_image.'
                               'BaseClientAdapter.read_image_file_pointer',
                               autospec=True)
        mock_rifp.start()
        self.addCleanup(mock_rifp.stop)
        self._file_handle = FakeHandle()
        mock_rifp.return_value = self._file_handle

    @mock.patch('tripleo_common.arch.kernel_arch', autospec=True,
                return_value='x86_64')
    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._get_image', autospec=True)
    def test_overcloud_create_images_with_arch(self, mock_get_image,
                                               mock_subprocess_call,
                                               mock_isfile, mock_arch):
        mock_isfile.return_value = False
        mock_get_image.return_value = None

        parsed_args = self.check_parser(self.cmd,
                                        ['--whole-disk'],
                                        [])
        self.cmd.take_action(parsed_args)
        parsed_args = self.check_parser(self.cmd,
                                        ['--whole-disk',
                                         '--http-boot', '/httpboot/ppc64le',
                                         '--arch', 'ppc64le'],
                                        [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.delete_image.call_count
        )
        self.assertEqual(
            2,
            self.app.client_manager.image.create_image.call_count
        )

        self.app.client_manager.image.create_image.assert_has_calls([
            mock.call(name='overcloud-full',
                      disk_format='qcow2',
                      container_format='bare',
                      data=mock.ANY,
                      validate_checksum=False,
                      visibility='public'),
            mock.call(name='ppc64le-overcloud-full',
                      disk_format='qcow2',
                      container_format='bare',
                      data=mock.ANY,
                      validate_checksum=False,
                      visibility='public'),
        ])

        self.app.client_manager.image.update_image.assert_has_calls([
            mock.call(10, hw_architecture='x86_64'),
            mock.call(11, hw_architecture='ppc64le'),
        ])
        self.assertEqual(mock_subprocess_call.call_count, 4)
        mock_subprocess_call.assert_has_calls([
            mock.call('sudo cp -f "./ironic-python-agent.kernel" '
                      '"/var/lib/ironic/httpboot/agent.kernel"', shell=True),
            mock.call('sudo cp -f "./ironic-python-agent.initramfs" '
                      '"/var/lib/ironic/httpboot/agent.ramdisk"', shell=True),
            mock.call('sudo cp -f "./ironic-python-agent.kernel" '
                      '"/httpboot/ppc64le/agent.kernel"', shell=True),
            mock.call('sudo cp -f "./ironic-python-agent.initramfs" '
                      '"/httpboot/ppc64le/agent.ramdisk"', shell=True),
        ])

    @mock.patch('tripleo_common.arch.kernel_arch', autospec=True,
                return_value='x86_64')
    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._get_image', autospec=True)
    def test_overcloud_create_images_with_arch_and_pltform(self,
                                                           mock_get_image,
                                                           mock_subprocess,
                                                           mock_isfile,
                                                           mock_arch):
        mock_isfile.return_value = False
        mock_get_image.return_value = None

        parsed_args = self.check_parser(self.cmd,
                                        ['--whole-disk'],
                                        [])
        self.cmd.take_action(parsed_args)
        parsed_args = self.check_parser(self.cmd,
                                        ['--whole-disk',
                                         '--http-boot', '/httpboot/ppc64le',
                                         '--architecture', 'ppc64le'],
                                        [])
        self.cmd.take_action(parsed_args)
        parsed_args = self.check_parser(self.cmd,
                                        ['--whole-disk',
                                         '--http-boot', '/httpboot/p9-ppc64le',
                                         '--architecture', 'ppc64le',
                                         '--platform', 'p9'],
                                        [])
        self.cmd.take_action(parsed_args)

        self.assertEqual(
            0,
            self.app.client_manager.image.delete_image.call_count
        )
        self.assertEqual(
            3,
            self.app.client_manager.image.create_image.call_count
        )

        self.app.client_manager.image.create_image.assert_has_calls([
            mock.call(name='overcloud-full',
                      disk_format='qcow2',
                      container_format='bare',
                      data=mock.ANY,
                      validate_checksum=False,
                      visibility='public'),
            mock.call(name='ppc64le-overcloud-full',
                      disk_format='qcow2',
                      container_format='bare',
                      data=mock.ANY,
                      validate_checksum=False,
                      visibility='public'),
            mock.call(name='p9-ppc64le-overcloud-full',
                      disk_format='qcow2',
                      container_format='bare',
                      data=mock.ANY,
                      validate_checksum=False,
                      visibility='public'),
        ])

        self.app.client_manager.image.update_image.assert_has_calls([
            mock.call(10, hw_architecture='x86_64'),
            mock.call(11, hw_architecture='ppc64le'),
            mock.call(12, hw_architecture='ppc64le', tripleo_platform='p9'),
        ])
        self.assertEqual(mock_subprocess.call_count, 6)
        mock_subprocess.assert_has_calls([
            mock.call('sudo cp -f "./ironic-python-agent.kernel" '
                      '"/var/lib/ironic/httpboot/agent.kernel"', shell=True),
            mock.call('sudo cp -f "./ironic-python-agent.initramfs" '
                      '"/var/lib/ironic/httpboot/agent.ramdisk"', shell=True),
            mock.call('sudo cp -f "./ironic-python-agent.kernel" '
                      '"/httpboot/ppc64le/agent.kernel"', shell=True),
            mock.call('sudo cp -f "./ironic-python-agent.initramfs" '
                      '"/httpboot/ppc64le/agent.ramdisk"', shell=True),
            mock.call('sudo cp -f "./ironic-python-agent.kernel" '
                      '"/httpboot/p9-ppc64le/agent.kernel"', shell=True),
            mock.call('sudo cp -f "./ironic-python-agent.initramfs" '
                      '"/httpboot/p9-ppc64le/agent.ramdisk"', shell=True),
        ])


class TestUploadOnlyExisting(TestPluginV1):

    def setUp(self):
        super(TestUploadOnlyExisting, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_image.UploadOvercloudImage(self.app, None)
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.image.version = 2.0
        self.app.client_manager.image.create_image.return_value = (
            mock.Mock(id=10, name='imgname', properties={},
                      created_at='2015-07-31T14:37:22.000000'))
        mock_cfe = mock.patch('tripleoclient.v1.overcloud_image.'
                              'BaseClientAdapter.check_file_exists',
                              autospec=True)
        mock_cfe.start()
        self.addCleanup(mock_cfe.stop)
        mock_cfe.return_value = True

        mock_rifp = mock.patch('tripleoclient.v1.overcloud_image.'
                               'BaseClientAdapter.read_image_file_pointer',
                               autospec=True)
        mock_rifp.start()
        self.addCleanup(mock_rifp.stop)
        self._file_handle = FakeHandle()
        mock_rifp.return_value = self._file_handle

    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_try_update', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'BaseClientAdapter._files_changed', autospec=True)
    def test_overcloud_upload_just_ipa_wholedisk(self,
                                                 mock_files_changed,
                                                 mock_image_changed,
                                                 mock_image_try_update,
                                                 mock_isfile_call,
                                                 mock_subprocess_call):
        mock_image_changed.return_value = True
        mock_image_try_update.return_value = None

        parsed_args = self.check_parser(
            self.cmd, ['--whole-disk', '--image-type=ironic-python-agent'], [])

        mock_files_changed.return_value = True
        self.cmd.take_action(parsed_args)

        # ensure check_file_exists has not been called
        self.assertItemsEqual(
            self.cmd.adapter.check_file_exists.call_args_list,
            [mock.call(self.cmd.adapter, './ironic-python-agent.initramfs'),
             mock.call(self.cmd.adapter, './ironic-python-agent.kernel')])

        self.assertFalse(mock_image_try_update.called)

    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_try_update', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'BaseClientAdapter._files_changed', autospec=True)
    def test_overcloud_upload_just_os_wholedisk(self,
                                                mock_files_changed,
                                                mock_image_changed,
                                                mock_image_try_update,
                                                mock_isfile_call,
                                                mock_subprocess_call):
        mock_image_changed.return_value = True
        mock_image_try_update.return_value = None

        parsed_args = self.check_parser(
            self.cmd, ['--whole-disk', '--image-type=os'], [])

        mock_files_changed.return_value = True
        self.cmd.take_action(parsed_args)

        # ensure check_file_exists has been called just with ipa
        self.cmd.adapter.check_file_exists.assert_called_once_with(
            self.cmd.adapter, './overcloud-full.qcow2')

        # ensure try_update has been called just with ipa
        mock_image_try_update.assert_called_once_with(
            self.cmd.adapter,
            'overcloud-full',
            './overcloud-full.qcow2'
        )

    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_try_update', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'BaseClientAdapter._files_changed', autospec=True)
    def test_overcloud_upload_just_ipa(self,
                                       mock_files_changed,
                                       mock_image_changed,
                                       mock_image_try_update,
                                       mock_isfile_call,
                                       mock_subprocess_call):
        mock_image_changed.return_value = True
        mock_image_try_update.return_value = None

        parsed_args = self.check_parser(
            self.cmd, ['--image-type=ironic-python-agent'], [])

        mock_files_changed.return_value = True
        self.cmd.take_action(parsed_args)

        # ensure check_file_exists has been called just with ipa
        self.assertItemsEqual(
            self.cmd.adapter.check_file_exists.call_args_list,
            [mock.call(self.cmd.adapter, './ironic-python-agent.initramfs'),
             mock.call(self.cmd.adapter, './ironic-python-agent.kernel')]
        )

        self.assertFalse(mock_image_try_update.called)

    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_try_update', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'GlanceClientAdapter._image_changed', autospec=True)
    @mock.patch('tripleoclient.v1.overcloud_image.'
                'BaseClientAdapter._files_changed', autospec=True)
    def test_overcloud_upload_just_os(self,
                                      mock_files_changed,
                                      mock_image_changed,
                                      mock_image_try_update,
                                      mock_isfile_call,
                                      mock_subprocess_call):
        mock_image_changed.return_value = True
        mock_image_try_update.return_value = None

        parsed_args = self.check_parser(
            self.cmd, ['--image-type=os'], [])

        mock_files_changed.return_value = True
        self.cmd.take_action(parsed_args)

        # ensure check_file_exists has been called just with ipa
        self.assertItemsEqual(
            self.cmd.adapter.check_file_exists.call_args_list,
            [mock.call(self.cmd.adapter, './overcloud-full.qcow2')])

        # ensure try_update has been called just with ipa
        mock_image_try_update.assert_has_calls([
            mock.call(self.cmd.adapter,
                      'overcloud-full-vmlinuz',
                      './overcloud-full.vmlinuz'),
            mock.call(self.cmd.adapter,
                      'overcloud-full-initrd',
                      './overcloud-full.initrd'),
            mock.call(self.cmd.adapter,
                      'overcloud-full',
                      './overcloud-full.qcow2'),
        ])
