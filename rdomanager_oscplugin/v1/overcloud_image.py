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

"""Plugin action implementation"""

import logging
import os
import subprocess

from cliff import command
from openstackclient.common import exceptions
from openstackclient.common import utils


class BuildPlugin(command.Command):
    """Overcloud Image Build plugin"""

    auth_required = False
    log = logging.getLogger(__name__ + ".BuildPlugin")

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        pass


class CreateOvercloud(command.Command):
    """Create overcloud glance images from existing image files."""
    auth_required = False
    log = logging.getLogger(__name__ + ".CreateOvercloud")

    def _env_variable_or_set(self, key_name, default_value):
        os.environ[key_name] = os.environ.get(key_name, default_value)

    def _delete_image_if_exists(self, image_client, name):
        try:
            image = utils.find_resource(image_client.images, name)
            image_client.images.delete(image.id)
        except exceptions.CommandError:
            self.log.debug('Image "%s" have already not existed, '
                           'no problem.' % name)

    def _check_file_exists(self, file_path):
        if not os.path.isfile(file_path):
            print('ERROR: Required file "%s" does not exist' % file_path)
            exit(1)

    def _read_image_file_pointer(self, dirname, filename):
        filepath = os.path.join(dirname, filename)
        self._check_file_exists(filepath)
        return open(filepath, 'rb')

    def _copy_file(self, src, dest):
        subprocess.call('sudo cp -f "{0}" "{1}"'.format(src, dest), shell=True)

    def _load_image(self, image_path, image_name, image_client):
        self.log.debug("uploading images to glance")

        kernel_id = image_client.images.create(
            name='%s-vmlinuz' % image_name,
            is_public=True,
            disk_format='aki',
            data=self._read_image_file_pointer(image_path,
                                               '%s.vmlinuz' % image_name)
        ).id

        ramdisk_id = image_client.images.create(
            name='%s-initrd' % image_name,
            is_public=True,
            disk_format='ari',
            data=self._read_image_file_pointer(image_path,
                                               '%s.initrd' % image_name)
        ).id

        image_client.images.create(
            name=image_name,
            is_public=True,
            disk_format='qcow2',
            container_format='bare',
            properties={'kernel_id': kernel_id, 'ramdisk_id': ramdisk_id},
            data=self._read_image_file_pointer(image_path,
                                               '%s.qcow2' % image_name)
        )

    def get_parser(self, prog_name):
        parser = super(CreateOvercloud, self).get_parser(prog_name)
        parser.add_argument(
            "--image-path",
            default='./',
            help="Path to directory containing image files",
        )
        parser.add_argument(
            "--os-image",
            default='overcloud-full.qcow2',
            help="OpenStack disk image filename",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        image_client = self.app.client_manager.image

        self._env_variable_or_set('DEPLOY_NAME', 'deploy-ramdisk-ironic')
        self._env_variable_or_set('DISCOVERY_NAME', 'discovery-ramdisk')
        self._env_variable_or_set('TFTP_ROOT', '/tftpboot')

        self.log.debug("check image files")

        image_files = [
            '%s.initramfs' % os.environ['DEPLOY_NAME'],
            '%s.kernel' % os.environ['DEPLOY_NAME'],
            '%s.initramfs' % os.environ['DISCOVERY_NAME'],
            '%s.kernel' % os.environ['DISCOVERY_NAME'],
            parsed_args.os_image
        ]

        for image in image_files:
            self._check_file_exists(os.path.join(parsed_args.image_path,
                                                 image))

        self.log.debug("prepare glance images")

        self._load_image(parsed_args.image_path,
                         parsed_args.os_image.split('.')[0],
                         image_client)

        self._delete_image_if_exists(image_client, 'bm_deploy_kernel')
        self._delete_image_if_exists(image_client, 'bm_deploy_ramdisk')

        image_client.images.create(
            name='bm-deploy-kernel',
            is_public=True,
            disk_format='aki',
            data=self._read_image_file_pointer(parsed_args.image_path,
                                               '%s.kernel' %
                                               os.environ['DEPLOY_NAME'])
        )

        image_client.images.create(
            name='bm-deploy-ramdisk',
            is_public=True,
            disk_format='ari',
            data=self._read_image_file_pointer(parsed_args.image_path,
                                               '%s.initramfs' %
                                               os.environ['DEPLOY_NAME'])
        )

        self.log.debug("copy discovery images to TFTP")

        self._copy_file(
            os.path.join(parsed_args.image_path,
                         '%s.kernel' % os.environ['DISCOVERY_NAME']),
            os.path.join(os.environ['TFTP_ROOT'], 'discovery.kernel')
        )

        self._copy_file(
            os.path.join(parsed_args.image_path,
                         '%s.initramfs' % os.environ['DISCOVERY_NAME']),
            os.path.join(os.environ['TFTP_ROOT'], 'discovery.ramdisk')
        )
