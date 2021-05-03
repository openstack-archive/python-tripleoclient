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

import abc
import collections
from datetime import datetime
import logging
import os
import re
import subprocess
import sys

from glanceclient.common.progressbar import VerboseFileWrapper
from osc_lib import exceptions
from osc_lib.i18n import _
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
    DEFAULT_YAML = ['overcloud-images-python3.yaml',
                    'overcloud-images-centos8.yaml']

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
        parser.add_argument(
            "--temp-dir",
            dest="temp_dir",
            default=os.environ.get('TMPDIR', os.getcwd()),
            help=_("Temporary directory to use when building the images. "
                   "Defaults to $TMPDIR or current directory if unset."),
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if not parsed_args.config_files:
            parsed_args.config_files = [os.path.join(self.IMAGE_YAML_PATH, f)
                                        for f in self.DEFAULT_YAML]
        os.environ.update({'TMPDIR': parsed_args.temp_dir})
        manager = build.ImageBuildManager(
            parsed_args.config_files,
            output_directory=parsed_args.output_directory,
            skip=parsed_args.skip,
            images=parsed_args.image_names)
        manager.build()


class BaseClientAdapter(object):

    log = logging.getLogger(__name__ + ".BaseClientAdapter")

    def __init__(self, image_path, progress=False,
                 update_existing=False, updated=None):
        self.progress = progress
        self.image_path = image_path
        self.update_existing = update_existing
        self.updated = updated

    @abc.abstractmethod
    def get_image_property(self, image, prop):
        pass

    @abc.abstractmethod
    def update_or_upload(self, image_name, properties, names_func,
                         arch, platform=None,
                         disk_format='qcow2', container_format='bare'):
        pass

    def _copy_file(self, src, dest):
        cmd = 'sudo cp -f "{0}" "{1}"'.format(src, dest)
        self.log.debug(cmd)
        subprocess.check_call(cmd, shell=True)

    def _move_file(self, src, dest):
        cmd = 'sudo mv "{0}" "{1}"'.format(src, dest)
        self.log.debug(cmd)
        subprocess.check_call(cmd, shell=True)

    def _make_dirs(self, path):
        cmd = 'sudo mkdir -m 0775 -p "{0}"'.format(path)
        self.log.debug(cmd)
        subprocess.check_call(cmd, shell=True)

    def _files_changed(self, filepath1, filepath2):
        return (plugin_utils.file_checksum(filepath1) !=
                plugin_utils.file_checksum(filepath2))

    def file_create_or_update(self, src_file, dest_file):
        if os.path.isfile(dest_file):
            if self._files_changed(src_file, dest_file):
                if self.update_existing:
                    self._copy_file(src_file, dest_file)
                else:
                    print('Image file "%s" already exists and can be updated'
                          ' with --update-existing.' % dest_file)
            else:
                print('Image file "%s" is up-to-date, skipping.' % dest_file)
        else:
            self._copy_file(src_file, dest_file)

    def check_file_exists(self, file_path):
        if not os.path.isfile(file_path):
            raise exceptions.CommandError(
                'Required file "%s" does not exist.' % file_path
            )

    def read_image_file_pointer(self, filepath):
        self.check_file_exists(filepath)
        file_descriptor = open(filepath, 'rb')

        if self.progress:
            file_descriptor = VerboseFileWrapper(file_descriptor)

        return file_descriptor


class FileImageClientAdapter(BaseClientAdapter):

    def __init__(self, local_path, **kwargs):
        super(FileImageClientAdapter, self).__init__(**kwargs)
        self.local_path = local_path

    def get_image_property(self, image, prop):
        if prop == 'kernel_id':
            path = os.path.splitext(image.id)[0] + '.vmlinuz'
            if os.path.exists(path.replace("file://", "")):
                return path
            return None
        elif prop == 'ramdisk_id':
            path = os.path.splitext(image.id)[0] + '.initrd'
            if os.path.exists(path.replace("file://", "")):
                return path
            return None
        raise ValueError('Unsupported property %s' % prop)

    def _print_image_info(self, image):
        table = PrettyTable(['Path', 'Name', 'Size'])
        table.add_row([image.id, image.name, image.size])
        print(table, file=sys.stdout)

    def _paths(self, image_name, names_func, arch, platform):
        (arch_path, extension) = names_func(
            image_name, arch=arch, platform=platform, use_subdir=True)
        image_file = image_name + extension

        dest_dir = os.path.split(
            os.path.join(self.local_path, arch_path))[0]
        return (dest_dir, image_file)

    def _get_image(self, path):
        if not os.path.exists(path):
            return
        stat = os.stat(path)
        created_at = datetime.fromtimestamp(
            stat.st_mtime).isoformat()

        Image = collections.namedtuple(
            'Image',
            'id, name, checksum, created_at, size'
        )
        (dir_path, filename) = os.path.split(path)
        (name, extension) = os.path.splitext(filename)
        checksum = plugin_utils.file_checksum(path)

        return Image(
            id='file://%s' % path,
            name=name,
            checksum=checksum,
            created_at=created_at,
            size=stat.st_size
        )

    def _image_changed(self, image, filename):
        return image.checksum != plugin_utils.file_checksum(filename)

    def _image_try_update(self, src_path, dest_path):
        image = self._get_image(dest_path)
        if image:
            if self._image_changed(image, src_path):
                if self.update_existing:
                    dest_base, dest_ext = os.path.splitext(dest_path)
                    dest_datestamp = re.sub(
                        r'[\-:\.]|(0+$)', '', image.created_at)
                    dest_mv = dest_base + '_' + dest_datestamp + dest_ext
                    self._move_file(dest_path, dest_mv)

                    if self.updated is not None:
                        self.updated.append(dest_path)
                    return None
                else:
                    print('Image "%s" already exists and can be updated'
                          ' with --update-existing.' % dest_path)
                    return image
            else:
                print('Image "%s" is up-to-date, skipping.' % dest_path)
                return image
        else:
            return None

    def _upload_image(self, src_path, dest_path):
        dest_dir = os.path.split(dest_path)[0]
        if not os.path.isdir(dest_dir):
            self._make_dirs(dest_dir)

        self._copy_file(src_path, dest_path)
        image = self._get_image(dest_path)
        print('Image "%s" was copied.' % image.id, file=sys.stdout)
        self._print_image_info(image)
        return image

    def update_or_upload(self, image_name, properties, names_func,
                         arch, platform=None,
                         disk_format='qcow2', container_format='bare'):
        (dest_dir, image_file) = self._paths(
            image_name, names_func, arch, platform)

        src_path = os.path.join(self.image_path, image_file)
        dest_path = os.path.join(dest_dir, image_file)
        existing_image = self._image_try_update(src_path, dest_path)
        if existing_image:
            return existing_image

        return self._upload_image(src_path, dest_path)


class GlanceClientAdapter(BaseClientAdapter):

    def __init__(self, client, **kwargs):
        super(GlanceClientAdapter, self).__init__(**kwargs)
        self.client = client

    def _print_image_info(self, image):
        table = PrettyTable(['ID', 'Name', 'Disk Format', 'Size', 'Status'])
        table.add_row([image.id, image.name, image.disk_format, image.size,
                       image.status])
        print(table, file=sys.stdout)

    def _get_image(self, name):
        # This would return None by default for an non-existent resorurce
        # And DuplicateResource exception if there more than one.
        return self.client.find_image(name)

    def _image_changed(self, image, filename):
        return image.checksum != plugin_utils.file_checksum(filename)

    def _image_try_update(self, image_name, image_file):
        image = self._get_image(image_name)
        if image:
            if self._image_changed(image, image_file):
                if self.update_existing:
                    self.client.update_image(
                        image.id,
                        name='%s_%s' % (image.name, re.sub(r'[\-:\.]|(0+$)',
                                                           '',
                                                           image.created_at))
                    )
                    if self.updated is not None:
                        self.updated.append(image.id)
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

    def _upload_image(self, name, data, properties=None, visibility='public',
                      disk_format='qcow2', container_format='bare'):

        image = self.client.create_image(
            name=name,
            visibility=visibility,
            disk_format=disk_format,
            container_format=container_format,
            data=data,
            validate_checksum=False
        )

        if properties:
            self.client.update_image(image.id, **properties)
        # Refresh image info
        image = self.client.get_image(image.id)

        print('Image "%s" was uploaded.' % image.name, file=sys.stdout)
        self._print_image_info(image)
        return image

    def get_image_property(self, image, prop):
        return getattr(image, prop)

    def update_or_upload(self, image_name, properties, names_func,
                         arch, platform=None,
                         disk_format='qcow2', container_format='bare'):

        if arch == 'x86_64' and platform is None:
            arch = None

        (glance_name, extension) = names_func(
                image_name, arch=arch, platform=platform)

        file_path = os.path.join(self.image_path, image_name + extension)

        updated_image = self._image_try_update(glance_name, file_path)
        if updated_image:
            return updated_image

        with self.read_image_file_pointer(file_path) as data:
            return self._upload_image(
                    name=glance_name,
                    disk_format=disk_format,
                    container_format=container_format,
                    properties=properties,
                    data=data)


class UploadOvercloudImage(command.Command):
    """Make existing image files available for overcloud deployment."""
    log = logging.getLogger(__name__ + ".UploadOvercloudImage")

    def _get_client_adapter(self, parsed_args):
        kwargs = {
            'progress': parsed_args.progress,
            'image_path': parsed_args.image_path,
            'update_existing': parsed_args.update_existing,
            'updated': self.updated
        }
        if parsed_args.local:
            return FileImageClientAdapter(parsed_args.local_path, **kwargs)
        return GlanceClientAdapter(self.app.client_manager.image, **kwargs)

    def _get_environment_var(self, envvar, default, deprecated=[]):
        for env_key in deprecated:
            if env_key in os.environ:
                self.log.warning(('Found deprecated environment var \'%s\', '
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
            help=_("Root directory for the ironic-python-agent image. If "
                   "uploading images for multiple architectures/platforms, "
                   "vary this argument such that a distinct folder is "
                   "created for each architecture/platform.")
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
                   "are common options. This option should match at least "
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
        parser.add_argument(
            "--local",
            dest="local",
            action="store_true",
            default=False,
            help=_('Copy files locally, even if there is an image service '
                   'endpoint'))
        parser.add_argument(
            "--local-path",
            default=self._get_environment_var(
                'LOCAL_IMAGE_PATH',
                constants.IRONIC_LOCAL_IMAGE_PATH),
            help=_("Root directory for image file copy destination when there "
                   "is no image endpoint, or when --local is specified")
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        self.updated = []
        self.adapter = self._get_client_adapter(parsed_args)

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
            self.adapter.check_file_exists(
                os.path.join(parsed_args.image_path, image))

        image_name = parsed_args.os_image_name.split('.')[0]

        self.log.debug("uploading %s overcloud images " %
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
                kernel = self.adapter.update_or_upload(
                    image_name=image_name,
                    properties=properties,
                    names_func=plugin_utils.overcloud_kernel,
                    arch=arch,
                    platform=platform,
                    disk_format='aki'
                )

                ramdisk = self.adapter.update_or_upload(
                    image_name=image_name,
                    properties=properties,
                    names_func=plugin_utils.overcloud_ramdisk,
                    arch=arch,
                    platform=platform,
                    disk_format='ari'
                )

                overcloud_image = self.adapter.update_or_upload(
                    image_name=image_name,
                    properties=dict(
                        {'kernel_id': kernel.id,
                         'ramdisk_id': ramdisk.id},
                        **properties),
                    names_func=plugin_utils.overcloud_image,
                    arch=arch,
                    platform=platform
                )

                img_kernel_id = self.adapter.get_image_property(
                    overcloud_image, 'kernel_id')
                img_ramdisk_id = self.adapter.get_image_property(
                    overcloud_image, 'ramdisk_id')
                # check overcloud image links
                if (img_kernel_id != kernel.id or
                        img_ramdisk_id != ramdisk.id):
                    self.log.error('Link overcloud image to it\'s initrd and '
                                   'kernel images is MISSING OR leads to OLD '
                                   'image. You can keep it or fix it '
                                   'manually.')

            else:
                overcloud_image = self.adapter.update_or_upload(
                    image_name=image_name,
                    properties=properties,
                    names_func=plugin_utils.overcloud_image,
                    arch=arch,
                    platform=platform
                )

            self.log.debug("uploading bm images")

        if parsed_args.image_type is None or \
                parsed_args.image_type == 'ironic-python-agent':
            self.log.debug("copy agent images to HTTP BOOT dir")

            self.adapter.file_create_or_update(
                os.path.join(parsed_args.image_path,
                             '%s.kernel' % parsed_args.ipa_name),
                os.path.join(parsed_args.http_boot, 'agent.kernel')
            )

            self.adapter.file_create_or_update(
                os.path.join(parsed_args.image_path,
                             '%s.initramfs' % parsed_args.ipa_name),
                os.path.join(parsed_args.http_boot, 'agent.ramdisk')
            )

        if self.updated:
            print('%s images have been updated, make sure to '
                  'rerun\n\topenstack overcloud node configure\nto reflect '
                  'the changes on the nodes' % len(self.updated))
