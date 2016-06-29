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
import os

from osc_lib import exceptions
from tripleoclient.tests.v1.test_plugin import TestPluginV1
from tripleoclient.v1 import overcloud_image


class TestOvercloudImageBuild(TestPluginV1):

    def setUp(self):
        super(TestOvercloudImageBuild, self).setUp()

        def _force_builder(dummy):
            builder = overcloud_image.DibImageBuilder()
            builder._disk_image_create = mock.Mock()
            self.mock_disk_image_create = builder._disk_image_create
            builder._ramdisk_image_create = mock.Mock()
            self.mock_ramdisk_image_create = builder._ramdisk_image_create
            return builder

        # Get the command object to test
        self.cmd = overcloud_image.BuildOvercloudImage(self.app, None)
        self.cmd._create_builder = _force_builder

    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('platform.linux_distribution')
    @mock.patch.object(overcloud_image.BuildOvercloudImage,
                       '_build_image_fedora_user', autospec=True)
    def test_overcloud_image_build_all(self, mock_fedora_user,
                                       mock_linux_distribution,
                                       mock_os_path_isfile):
        arglist = ['--all']
        verifylist = [('all', True)]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        mock_linux_distribution.return_value = ['CentOS Fake Release']
        mock_os_path_isfile.side_effect = [False, True, True, False, True]
        self.cmd.take_action(parsed_args)

        self.assertEqual(2, self.mock_disk_image_create.call_count)

    @mock.patch('platform.linux_distribution')
    @mock.patch('subprocess.call', autospec=True)
    @mock.patch('os.path.isfile', autospec=True)
    @mock.patch('os.chmod')
    @mock.patch('requests.get', autospec=True)
    def test_overcloud_image_build_fedora_user_no_cache(
            self,
            mock_requests_get,
            mock_os_chmod,
            mock_os_path_isfile,
            mock_subprocess_call,
            mock_linux_distribution):
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
        mock_linux_distribution.return_value = [
            'Red Hat Enterprise Linux Server 7.1']

        with mock.patch('six.moves.builtins.open', mock_open_context):
            self.cmd.take_action(parsed_args)

        mock_requests_get.assert_called_once_with(
            'http://cloud.fedoraproject.org/fedora-21.x86_64.qcow2')
        self.assertEqual(2, mock_os_path_isfile.call_count)
        self.assertEqual(1, mock_os_chmod.call_count)
        mock_open_context.assert_has_calls(
            [mock.call('fedora-user.qcow2', 'wb')])

    @mock.patch('platform.linux_distribution')
    @mock.patch('os.path.isfile', autospec=True)
    def test_overcloud_image_build_overcloud_full(
            self,
            mock_os_path_isfile,
            mock_linux_distribution):
        arglist = ['--type', 'overcloud-full']
        verifylist = [('image_types', ['overcloud-full'])]

        mock_os_path_isfile.side_effect = [False, True]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        mock_linux_distribution.return_value = [
            'Red Hat Enterprise Linux Server 7.1']

        self.cmd.take_action(parsed_args)

        self.mock_disk_image_create.assert_called_once_with(
            "-a amd64 -o "
            "overcloud-full.qcow2 rhel7 overcloud-full overcloud-controller "
            "overcloud-compute overcloud-ceph-storage hosts "
            "baremetal dhcp-all-interfaces os-collect-config "
            "puppet-modules hiera "
            "os-net-config stable-interface-names grub2 "
            "-p python-psutil,python-debtcollector,plotnetcfg,sos,"
            "python-networking-cisco,python-UcsSdk,"
            "device-mapper-multipath,python-networking-bigswitch,"
            "openstack-neutron-bigswitch-lldp,"
            "openstack-neutron-bigswitch-agent,python-heat-agent-puppet "
            "dynamic-login element-manifest network-gateway "
            "enable-packages-install "
            "pip-and-virtualenv-override  --min-tmpfs 5 2>&1 | "
            "tee dib-overcloud-full.log")
        self.assertEqual([mock.call('overcloud-full.qcow2'),
                          mock.call('overcloud-full.qcow2')],
                         mock_os_path_isfile.mock_calls)

    @mock.patch('platform.linux_distribution')
    @mock.patch('os.path.isfile', autospec=True)
    def test_overcloud_image_build_overcloud_full_with_extra_args(
            self,
            mock_os_path_isfile,
            mock_linux_distribution):
        """Test the --builder-extra-args argument.

        Using the overcloud full as an example because it will be the
        most common case
        """
        arglist = ['--type', 'overcloud-full',
                   '--builder-extra-args', 'overcloud-network-midonet']
        verifylist = [('image_types', ['overcloud-full'])]

        mock_os_path_isfile.side_effect = [False, True]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        mock_linux_distribution.return_value = [
            'Red Hat Enterprise Linux Server 7.1']

        self.cmd.take_action(parsed_args)

        self.mock_disk_image_create.assert_called_once_with(
            "-a amd64 -o "
            "overcloud-full.qcow2 rhel7 overcloud-full overcloud-controller "
            "overcloud-compute overcloud-ceph-storage hosts "
            "baremetal dhcp-all-interfaces os-collect-config "
            "puppet-modules hiera "
            "os-net-config stable-interface-names grub2 "
            "-p python-psutil,python-debtcollector,plotnetcfg,sos,"
            "python-networking-cisco,python-UcsSdk,"
            "device-mapper-multipath,python-networking-bigswitch,"
            "openstack-neutron-bigswitch-lldp,"
            "openstack-neutron-bigswitch-agent,python-heat-agent-puppet "
            "dynamic-login element-manifest network-gateway "
            "enable-packages-install "
            "pip-and-virtualenv-override overcloud-network-midonet "
            "--min-tmpfs 5 2>&1 | tee dib-overcloud-full.log")
        self.assertEqual([mock.call('overcloud-full.qcow2'),
                          mock.call('overcloud-full.qcow2')],
                         mock_os_path_isfile.mock_calls)

    @mock.patch('time.sleep')
    @mock.patch('platform.linux_distribution')
    @mock.patch('os.path.isfile', autospec=True)
    def test_overcloud_image_build_deploy_ramdisk(
            self,
            mock_os_path_isfile,
            mock_linux_distribution,
            mock_sleep):
        arglist = ['--type', 'deploy-ramdisk']
        verifylist = [('image_types', ['deploy-ramdisk'])]

        # Short-circuit logic means this only gets called once the first time
        mock_os_path_isfile.side_effect = [False, True, True]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        mock_linux_distribution.return_value = [
            'Red Hat Enterprise Linux Server 7.1']

        self.cmd.take_action(parsed_args)

        self.mock_ramdisk_image_create.assert_called_once_with(
            "-a amd64 -o deploy-ramdisk-ironic --ramdisk-element "
            "dracut-ramdisk rhel7 deploy-ironic dynamic-login "
            "element-manifest network-gateway "
            "enable-packages-install "
            "pip-and-virtualenv-override  2>&1 | tee dib-deploy.log")
        self.assertEqual([mock.call('deploy-ramdisk-ironic.initramfs'),
                          mock.call('deploy-ramdisk-ironic.initramfs'),
                          mock.call('deploy-ramdisk-ironic.kernel')],
                         mock_os_path_isfile.mock_calls)

    @mock.patch('platform.linux_distribution')
    @mock.patch('os.path.isfile', autospec=True)
    def test_overcloud_image_build_deploy_ramdisk_agent(
            self,
            mock_os_path_isfile,
            mock_linux_distribution):
        arglist = ['--type', 'agent-ramdisk']
        verifylist = [('image_types', ['agent-ramdisk'])]

        # Short-circuit logic means this only gets called once the first time
        mock_os_path_isfile.side_effect = [False, True, True]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        mock_linux_distribution.return_value = [
            'Red Hat Enterprise Linux Server 7.1']

        self.cmd.take_action(parsed_args)

        self.mock_disk_image_create.assert_called_once_with(
            "-a amd64 -o ironic-python-agent "
            "rhel7 ironic-agent dynamic-login element-manifest "
            "network-gateway enable-packages-install "
            "pip-and-virtualenv-override  "
            "-p python-hardware-detect --min-tmpfs 5 "
            "2>&1 | tee dib-agent-ramdisk.log")
        self.assertEqual([mock.call('ironic-python-agent.initramfs'),
                          mock.call('ironic-python-agent.initramfs'),
                          mock.call('ironic-python-agent.kernel')],
                         mock_os_path_isfile.mock_calls)

    @mock.patch('platform.linux_distribution')
    @mock.patch('os.path.isfile', autospec=True)
    def test_overcloud_image_build_deploy_ramdisk_agent_fails(
            self,
            mock_os_path_isfile,
            mock_linux_distribution):
        arglist = ['--type', 'agent-ramdisk']
        verifylist = [('image_types', ['agent-ramdisk'])]

        # Short-circuit logic means this only gets called once the first time
        mock_os_path_isfile.side_effect = [False, False]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        mock_linux_distribution.return_value = [
            'Red Hat Enterprise Linux Server 7.1']

        self.assertRaises(overcloud_image.ImageBuildError,
                          self.cmd.take_action, parsed_args)

        self.mock_disk_image_create.assert_called_once_with(
            "-a amd64 -o ironic-python-agent "
            "rhel7 ironic-agent dynamic-login element-manifest "
            "network-gateway enable-packages-install "
            "pip-and-virtualenv-override  "
            "-p python-hardware-detect --min-tmpfs 5 "
            "2>&1 | tee dib-agent-ramdisk.log")
        self.assertEqual([mock.call('ironic-python-agent.initramfs'),
                          mock.call('ironic-python-agent.initramfs')],
                         mock_os_path_isfile.mock_calls)

    @mock.patch('platform.linux_distribution')
    def test_unsupported_distro(self, mock_linux_distribution):
        mock_linux_distribution.return_value = [
            'Some Random Distro Eleventy.Infinity']
        parsed_args = self.check_parser(self.cmd, ['--all'], [])
        self.assertRaises(RuntimeError, self.cmd.take_action, parsed_args)

    def test_pass_builder(self):
        argslist = ['--builder', 'foo', '--all']
        verifylist = [('builder', 'foo'), ('all', True)]
        # NOTE(bnemec): At this time there is only one allowed option for
        # --builder, so to verify that it actually parses we have to patch
        # another one in.
        with mock.patch.object(self.cmd, '_BUILDERS', ['dib', 'foo']):
            self.check_parser(self.cmd, argslist, verifylist)


class TestUploadOvercloudImage(TestPluginV1):
    def setUp(self):
        super(TestUploadOvercloudImage, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_image.UploadOvercloudImage(self.app, None)
        self.app.client_manager.image = mock.Mock()
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
        self.assertEqual(self.cmd._get_image('noimagename'), None)

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

    def test_file_try_update_need_update(self):
        os.path.isfile = mock.Mock(return_value=True)
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

    @mock.patch('subprocess.check_call', autospec=True)
    def test_overcloud_create_images(self, mock_subprocess_call):
        parsed_args = self.check_parser(self.cmd, [], [])
        os.path.isfile = mock.Mock(return_value=False)

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

    @mock.patch('subprocess.check_call', autospec=True)
    def test_overcloud_create_noupdate_images(self, mock_subprocess_call):
        parsed_args = self.check_parser(self.cmd, [], [])
        os.path.isfile = mock.Mock(return_value=True)
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
            5,
            self.app.client_manager.image.images.update.call_count
        )
        self.assertEqual(mock_subprocess_call.call_count, 2)
