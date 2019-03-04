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

from __future__ import print_function

import logging
import os
import re
import subprocess
import sys

from glanceclient.common.progressbar import VerboseFileWrapper
from osc_lib import exceptions
from osc_lib.i18n import _
from osc_lib import utils
from prettytable import PrettyTable
import tripleo_common.arch
from tripleo_common.image import build

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as plugin_utils


class BuildOvercloudImage(command.Command):
    """Build images for the overcloud"""

    auth_required = False
    log = logging.getLogger(__name__ + ".BuildOvercloudImage")

    IMAGE_YAML_PATH = "/usr/share/openstack-tripleo-common/image-yaml"
    DEFAULT_YAML = ['overcloud-images.yaml', 'overcloud-images-centos7.yaml']

    def get_parser(self, prog_name):
        parser = super(BuildOvercloudImage, self).get_parser(prog_name)
        parser.add_argument(
            "--config-file",
            dest="config_files",
            metavar='<yaml config file>',
            default=[],
            action="append",
            help=_("YAML config file specifying the image build. May be "
                   "specified multiple times. Order is preserved, and later "
                   "files will override some options in previous files. "
                   "Other options will append."),
        )
        parser.add_argument(
            "--image-name",
            dest="image_names",
            metavar='<image name>',
            default=None,
            help=_("Name of image to build. May be specified multiple "
                   "times. If unspecified, will build all images in "
                   "given YAML files."),
        )
        parser.add_argument(
            "--no-skip",
            dest="skip",
            action="store_false",
            default=True,
            help=_("Skip build if cached image exists."),
        )
        parser.add_argument(
            "--output-directory",
            dest="output_directory",
            default=os.environ.get('TRIPLEO_ROOT', '.'),
            help=_("Output directory for images. Defaults to $TRIPLEO_ROOT,"
                   "or current directory if unset."),
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if not parsed_args.config_files:
            parsed_args.config_files = [os.path.join(self.IMAGE_YAML_PATH, f)
                                        for f in self.DEFAULT_YAML]
        manager = build.ImageBuildManager(
            parsed_args.config_files,
            output_directory=parsed_args.output_directory,
            skip=parsed_args.skip,
            images=parsed_args.image_names)
        manager.build()


class GlanceBaseClientAdapter(object):
    def __init__(self, client):
        self.client = client

    def print_image_info(self, image):
        table = PrettyTable(['ID', 'Name', 'Disk Format', 'Size', 'Status'])
        table.add_row([image.id, image.name, image.disk_format, image.size,
                       image.status])
        print(table, file=sys.stdout)


class GlanceV1ClientAdapter(GlanceBaseClientAdapter):
    def upload_image(self, *args, **kwargs):
        image = self.client.images.create(*args, **kwargs)

        print('Image "%s" was uploaded.' % image.name, file=sys.stdout)
        self.print_image_info(image)
        return image

    def get_image_property(self, image, prop):
        return image.properties[prop]


class GlanceV2ClientAdapter(GlanceBaseClientAdapter):
    def upload_image(self, *args, **kwargs):
        is_public = kwargs.pop('is_public')
        data = kwargs.pop('data')
        properties = kwargs.pop('properties', None)
        kwargs['visibility'] = 'public' if is_public else 'private'
        kwargs.setdefault('container_format', 'bare')

        image = self.client.images.create(*args, **kwargs)

        self.client.images.upload(image.id, image_data=data)
        if properties:
            self.client.images.update(image.id, **properties)
        # Refresh image info
        image = self.client.images.get(image.id)

        print('Image "%s" was uploaded.' % image.name, file=sys.stdout)
        self.print_image_info(image)
        return image

    def get_image_property(self, image, prop):
        return getattr(image, prop)


class UploadOvercloudImage(command.Command):
    """Create overcloud glance images from existing image files."""
    log = logging.getLogger(__name__ + ".UploadOvercloudImage")

    def _get_image(self, name):
        try:
            image = utils.find_resource(self.app.client_manager.image.images,
                                        name)
        except exceptions.CommandError as e:
            # TODO(maufart): enhance error detection, when python-glanceclient
            # starts provide it https://bugs.launchpad.net/glance/+bug/1480156
            if 'More than one image exists' in e.args[0]:
                raise exceptions.CommandError(
                    'Image "%s" already exists in glance more than once,'
                    ' delete all copies except the first one.' % name
                )
            else:
                self.log.debug('Image "%s" does not exists, no problem.'
                               % name)
                return None
        return image

    def _image_changed(self, name, filename):
        image = utils.find_resource(self.app.client_manager.image.images,
                                    name)
        return image.checksum != plugin_utils.file_checksum(filename)

    def _check_file_exists(self, file_path):
        if not os.path.isfile(file_path):
            raise exceptions.CommandError(
                'Required file "%s" does not exist.' % file_path
            )

    def _read_image_file_pointer(self, dirname, filename):
        filepath = os.path.join(dirname, filename)
        self._check_file_exists(filepath)
        file_descriptor = open(filepath, 'rb')

        if self._progress:
            file_descriptor = VerboseFileWrapper(file_descriptor)

        return file_descriptor

    def _copy_file(self, src, dest):
        subprocess.check_call('sudo cp -f "{0}" "{1}"'.format(src, dest),
                              shell=True)

    def _image_try_update(self, image_name, image_file, parsed_args):
        image = self._get_image(image_name)
        if image:
            if self._image_changed(image_name, image_file):
                if parsed_args.update_existing:
                    self.app.client_manager.image.images.update(
                        image.id,
                        name='%s_%s' % (image.name, re.sub(r'[\-:\.]|(0+$)',
                                                           '',
                                                           image.created_at))
                    )
                    self.updated = True
                    return None
                else:
                    print('Image "%s" already exists and can be updated'
                          ' with --update-existing.' % image_name)
                    return image
            else:
                print('Image "%s" is up-to-date, skipping.' % image_name)
                return image
        else:
            return None

    def _files_changed(self, filepath1, filepath2):
        return (plugin_utils.file_checksum(filepath1) !=
                plugin_utils.file_checksum(filepath2))

    def _file_create_or_update(self, src_file, dest_file, update_existing):
        if os.path.isfile(dest_file):
            if self._files_changed(src_file, dest_file):
                if update_existing:
                    self._copy_file(src_file, dest_file)
                else:
                    print('Image file "%s" already exists and can be updated'
                          ' with --update-existing.' % dest_file)
            else:
                print('Image file "%s" is up-to-date, skipping.' % dest_file)
        else:
            self._copy_file(src_file, dest_file)

    def _get_glance_client_adaptor(self):
        if self.app.client_manager.image.version >= 2.0:
            return GlanceV2ClientAdapter(self.app.client_manager.image)
        else:
            return GlanceV1ClientAdapter(self.app.client_manager.image)

    def _get_environment_var(self, envvar, default, deprecated=[]):
        for env_key in deprecated:
            if env_key in os.environ:
                self.log.warn(('Found deprecated environment var \'%s\', '
                               'please use \'%s\' instead' % (env_key,
                                                              envvar)))
                return os.environ.get(env_key)
        return os.environ.get(envvar, default)

    def get_parser(self, prog_name):
        parser = super(UploadOvercloudImage, self).get_parser(prog_name)
        parser.add_argument(
            "--image-path",
            default=self._get_environment_var('IMAGE_PATH', './'),
            help=_("Path to directory containing image files"),
        )
        parser.add_argument(
            "--os-image-name",
            default=self._get_environment_var('OS_IMAGE_NAME',
                                              'overcloud-full.qcow2'),
            help=_("OpenStack disk image filename"),
        )
        parser.add_argument(
            "--ironic-python-agent-name",
            dest='ipa_name',
            default=self._get_environment_var('IRONIC_PYTHON_AGENT_NAME',
                                              'ironic-python-agent',
                                              deprecated=['AGENT_NAME']),
            help=_("OpenStack ironic-python-agent (agent) image filename"),
        )
        parser.add_argument(
            "--http-boot",
            default=self._get_environment_var(
                'HTTP_BOOT',
                constants.IRONIC_HTTP_BOOT_BIND_MOUNT),
            help=_("Root directory for the introspection image")
        )
        parser.add_argument(
            "--update-existing",
            dest="update_existing",
            action="store_true",
            help=_("Update images if already exist"),
        )
        parser.add_argument(
            "--whole-disk",
            dest="whole_disk",
            action="store_true",
            default=False,
            help=_("When set, the overcloud-full image to be uploaded "
                   "will be considered as a whole disk one"),
        )
        parser.add_argument(
            "--architecture",
            help=_("Architecture type for these images, "
                   "\'x86_64\', \'i386\' and \'ppc64le\' "
                   "are common options.  This option should match at least "
                   "one \'arch\' value in instackenv.json"),
        )
        parser.add_argument(
            "--platform",
            help=_("Platform type for these images.  Platform is a "
                   "sub-category of architecture.  For example you may have "
                   "generic images for x86_64 but offer images specific to "
                   "SandyBridge (SNB)."),
        )
        parser.add_argument(
            "--image-type",
            dest="image_type",
            choices=["os", "ironic-python-agent"],
            help=_("If specified, allows to restrict the image type to upload "
                   "(os for the overcloud image or ironic-python-agent for "
                   "the ironic-python-agent one)"),
        )
        parser.add_argument(
            "--progress",
            dest="progress",
            action="store_true",
            default=False,
            help=_('Show progress bar for upload files action'))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        glance_client_adaptor = self._get_glance_client_adaptor()
        self.updated = False
        self._progress = parsed_args.progress

        if parsed_args.platform and not parsed_args.architecture:
            raise exceptions.CommandError('You supplied a platform (%s) '
                                          'without specifying the '
                                          'architecture')

        self.log.debug("checking if image files exist")

        image_files = []
        if parsed_args.image_type is None or \
                parsed_args.image_type == 'ironic-python-agent':
            image_files.append('%s.initramfs' % parsed_args.ipa_name)
            image_files.append('%s.kernel' % parsed_args.ipa_name)

        if parsed_args.image_type is None or parsed_args.image_type == 'os':
            image_files.append(parsed_args.os_image_name)

        if parsed_args.whole_disk:
            overcloud_image_type = 'whole disk'
        else:
            overcloud_image_type = 'partition'

        for image in image_files:
            self._check_file_exists(os.path.join(parsed_args.image_path,
                                                 image))

        image_name = parsed_args.os_image_name.split('.')[0]

        self.log.debug("uploading %s overcloud images to glance" %
                       overcloud_image_type)

        properties = {}
        arch = parsed_args.architecture
        if arch:
            properties['hw_architecture'] = arch
        else:
            properties['hw_architecture'] = tripleo_common.arch.kernel_arch()
        platform = parsed_args.platform
        if platform:
            properties['tripleo_platform'] = platform

        if parsed_args.image_type is None or parsed_args.image_type == 'os':
            # vmlinuz and initrd only need to be uploaded for a partition image
            if not parsed_args.whole_disk:
                (oc_vmlinuz_name,
                 oc_vmlinuz_extension) = plugin_utils.overcloud_kernel(
                     image_name, arch=arch, platform=platform)
                oc_vmlinuz_file = os.path.join(parsed_args.image_path,
                                               image_name +
                                               oc_vmlinuz_extension)
                kernel = (self._image_try_update(oc_vmlinuz_name,
                                                 oc_vmlinuz_file,
                                                 parsed_args) or
                          glance_client_adaptor.upload_image(
                              name=oc_vmlinuz_name,
                              is_public=True,
                              disk_format='aki',
                              properties=properties,
                              data=self._read_image_file_pointer(
                                  parsed_args.image_path, oc_vmlinuz_file)
                ))

                (oc_initrd_name,
                 oc_initrd_extension) = plugin_utils.overcloud_ramdisk(
                     image_name, arch=arch, platform=platform)
                oc_initrd_file = os.path.join(parsed_args.image_path,
                                              image_name +
                                              oc_initrd_extension)
                ramdisk = (self._image_try_update(oc_initrd_name,
                                                  oc_initrd_file,
                                                  parsed_args) or
                           glance_client_adaptor.upload_image(
                               name=oc_initrd_name,
                               is_public=True,
                               disk_format='ari',
                               properties=properties,
                               data=self._read_image_file_pointer(
                                   parsed_args.image_path, oc_initrd_file)
                ))

                (oc_name,
                 oc_extension) = plugin_utils.overcloud_image(
                     image_name, arch=arch, platform=platform)
                oc_file = os.path.join(parsed_args.image_path,
                                       image_name +
                                       oc_extension)
                overcloud_image = (self._image_try_update(oc_name, oc_file,
                                                          parsed_args) or
                                   glance_client_adaptor.upload_image(
                                       name=oc_name,
                                       is_public=True,
                                       disk_format='qcow2',
                                       container_format='bare',
                                       properties=dict(
                                           {'kernel_id': kernel.id,
                                            'ramdisk_id': ramdisk.id},
                                           **properties),
                                       data=self._read_image_file_pointer(
                                           parsed_args.image_path, oc_file)
                ))

                img_kernel_id = glance_client_adaptor.get_image_property(
                    overcloud_image, 'kernel_id')
                img_ramdisk_id = glance_client_adaptor.get_image_property(
                    overcloud_image, 'ramdisk_id')
                # check overcloud image links
                if (img_kernel_id != kernel.id or
                        img_ramdisk_id != ramdisk.id):
                    self.log.error('Link overcloud image to it\'s initrd and '
                                   'kernel images is MISSING OR leads to OLD '
                                   'image. You can keep it or fix it '
                                   'manually.')

            else:
                (oc_name,
                 oc_extension) = plugin_utils.overcloud_image(
                     image_name, arch=arch, platform=platform)
                oc_file = os.path.join(parsed_args.image_path,
                                       image_name +
                                       oc_extension)
                overcloud_image = (self._image_try_update(oc_name, oc_file,
                                                          parsed_args) or
                                   glance_client_adaptor.upload_image(
                                       name=oc_name,
                                       is_public=True,
                                       disk_format='qcow2',
                                       container_format='bare',
                                       properties=properties,
                                       data=self._read_image_file_pointer(
                                           parsed_args.image_path, oc_file)
                ))

            self.log.debug("uploading bm images to glance")

        if parsed_args.image_type is None or \
                parsed_args.image_type == 'ironic-python-agent':
            (deploy_kernel_name,
             deploy_kernel_extension) = plugin_utils.deploy_kernel(
                 arch=arch, platform=platform)
            deploy_kernel_file = os.path.join(parsed_args.image_path,
                                              parsed_args.ipa_name +
                                              deploy_kernel_extension)
            self._image_try_update(deploy_kernel_name, deploy_kernel_file,
                                   parsed_args) or \
                glance_client_adaptor.upload_image(
                    name=deploy_kernel_name,
                    is_public=True,
                    disk_format='aki',
                    properties=properties,
                    data=self._read_image_file_pointer(
                        parsed_args.image_path,
                        deploy_kernel_file))

            (deploy_ramdisk_name,
             deploy_ramdisk_extension) = plugin_utils.deploy_ramdisk(
                 arch=arch, platform=platform)
            deploy_ramdisk_file = os.path.join(parsed_args.image_path,
                                               parsed_args.ipa_name +
                                               deploy_ramdisk_extension)
            self._image_try_update(deploy_ramdisk_name, deploy_ramdisk_file,
                                   parsed_args) or \
                glance_client_adaptor.upload_image(
                    name=deploy_ramdisk_name,
                    is_public=True,
                    disk_format='ari',
                    properties=properties,
                    data=self._read_image_file_pointer(parsed_args.image_path,
                                                       deploy_ramdisk_file))

            self.log.debug("copy agent images to HTTP BOOT dir")

            # TODO(tonyb) Decide how to handle platform specific httpboot
            # files/names

            self._file_create_or_update(
                os.path.join(parsed_args.image_path,
                             '%s.kernel' % parsed_args.ipa_name),
                os.path.join(parsed_args.http_boot, 'agent.kernel'),
                parsed_args.update_existing
            )

            self._file_create_or_update(
                os.path.join(parsed_args.image_path,
                             '%s.initramfs' % parsed_args.ipa_name),
                os.path.join(parsed_args.http_boot, 'agent.ramdisk'),
                parsed_args.update_existing
            )

        if self.updated:
            print('Some images have been updated in Glance, make sure to '
                  'rerun\n\topenstack overcloud node configure\nto reflect '
                  'the changes on the nodes')
