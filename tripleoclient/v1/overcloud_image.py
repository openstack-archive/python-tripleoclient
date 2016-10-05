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
import logging
import os
import platform
import re
import requests
import shutil
import six
import stat
import subprocess
import sys
import time
import warnings

from osc_lib.command import command
from osc_lib import exceptions
from osc_lib.i18n import _
from osc_lib import utils
from prettytable import PrettyTable

from tripleoclient import utils as plugin_utils


class ImageBuildError(Exception):
    def __init__(self, image_name):
        msg = 'Failed to build image "%s"' % image_name
        super(ImageBuildError, self).__init__(msg)


@six.add_metaclass(abc.ABCMeta)
class ImageBuilder(object):
    """Base representation of an image building method"""

    @abc.abstractmethod
    def build_ramdisk(self, parsed_args, ramdisk_type):
        """Build a ramdisk

        DEPRECATED: Use build_ramdisk_agent instead.
        """
        pass

    @abc.abstractmethod
    def build_ramdisk_agent(self, parsed_args):
        """Build a ramdisk agent"""
        pass

    @abc.abstractmethod
    def build_image(self, parsed_args, node_type):
        """Build a disk image"""
        pass

    def preprocess_parsed_args(self, parsed_args):
        """Eventually preprocess the parsed arguments"""
        pass


class DibImageBuilder(ImageBuilder):
    """Build images using diskimage-builder"""

    _min_tmpfs = 5

    def _disk_image_create(self, args):
        subprocess.check_call('disk-image-create {0}'.format(args), shell=True)

    def _ramdisk_image_create(self, args):
        subprocess.check_call('ramdisk-image-create {0}'.format(args),
                              shell=True)

    def build_ramdisk(self, parsed_args, ramdisk_type):
        deprecation_message = (
            'DEPRECATED: The old bash-based ramdisks are no longer '
            'supported.  You should move to the agent-based ramdisk as '
            'soon as possible.'
        )
        print(deprecation_message)
        # Give users time to see this message before we spam the console
        # with image build output.
        time.sleep(10)
        image_name = vars(parsed_args)["%s_name" % ramdisk_type]
        args = ("-a %(arch)s -o %(name)s "
                "--ramdisk-element dracut-ramdisk %(node_dist)s "
                "%(image_element)s %(dib_common_elements)s "
                "%(builder_extra_args)s "
                "2>&1 | tee dib-%(ramdisk_type)s.log" %
                {
                    'arch': parsed_args.node_arch,
                    'name': image_name,
                    'node_dist': parsed_args.node_dist,
                    'image_element':
                        vars(parsed_args)["%s_image_element" %
                                          ramdisk_type],
                    'dib_common_elements':
                        parsed_args.dib_common_elements,
                    'builder_extra_args': parsed_args.builder_extra_args,
                    'ramdisk_type': ramdisk_type,
                })
        os.environ.update(parsed_args.dib_env_vars)
        self._ramdisk_image_create(args)
        # Print it again so users have another chance to see it.
        print(deprecation_message)

    def build_ramdisk_agent(self, parsed_args):
        # The ironic-agent element builds the ramdisk internally,
        # so we use disk image create instead of ramdisk image create.
        image_name = vars(parsed_args)["agent_name"]
        args = ("-a %(arch)s -o %(name)s "
                "%(node_dist)s %(image_element)s %(dib_common_elements)s "
                "%(builder_extra_args)s %(agent_dib_extra_args)s "
                "--min-tmpfs %(min_tmpfs)d 2>&1 | tee dib-agent-ramdisk.log" %
                {
                    'arch': parsed_args.node_arch,
                    'name': image_name,
                    'node_dist': parsed_args.node_dist,
                    'image_element':
                        vars(parsed_args)["agent_image_element"],
                    'dib_common_elements':
                        parsed_args.dib_common_elements,
                    'builder_extra_args': parsed_args.builder_extra_args,
                    'agent_dib_extra_args': parsed_args.agent_dib_extra_args,
                    'min_tmpfs': self._min_tmpfs,
                })
        os.environ.update(parsed_args.dib_env_vars)
        self._disk_image_create(args)

    def build_image(self, parsed_args, node_type):
        image_name = "%s.qcow2" % vars(parsed_args)['overcloud_%s_name' %
                                                    node_type]
        extra_args = vars(parsed_args)["overcloud_%s_dib_extra_args" %
                                       node_type]
        args = ("-a %(arch)s -o %(name)s "
                "%(node_dist)s %(overcloud_dib_extra_args)s "
                "%(dib_common_elements)s %(builder_extra_args)s "
                "--min-tmpfs %(min_tmpfs)d 2>&1 | "
                "tee dib-overcloud-%(image_type)s.log" %
                {
                    'arch': parsed_args.node_arch,
                    'name': image_name,
                    'node_dist': parsed_args.node_dist,
                    'overcloud_dib_extra_args': extra_args,
                    'dib_common_elements':
                        parsed_args.dib_common_elements,
                    'builder_extra_args': parsed_args.builder_extra_args,
                    'image_type': node_type,
                    'min_tmpfs': self._min_tmpfs,
                })
        os.environ.update(parsed_args.dib_env_vars)
        self._disk_image_create(args)


class BuildOvercloudImage(command.Command):
    """Build images for the overcloud"""

    auth_required = False
    log = logging.getLogger(__name__ + ".BuildOvercloudImage")

    TRIPLEOPUPPETELEMENTS = "/usr/share/tripleo-puppet-elements"
    INSTACKUNDERCLOUDELEMENTS = "/usr/share/instack-undercloud"
    PUPPET_COMMON_ELEMENTS = [
        'hosts',
        'baremetal',
        'dhcp-all-interfaces',
        'os-collect-config',
        'puppet-modules',
        'hiera',
        'os-net-config',
        'stable-interface-names',
        'grub2',
        '-p python-psutil,python-debtcollector,plotnetcfg,sos,'
        'python-networking-cisco,python-UcsSdk,device-mapper-multipath,'
        'python-networking-bigswitch,openstack-neutron-bigswitch-lldp,'
        'openstack-neutron-bigswitch-agent,python-heat-agent-puppet'
    ]

    OVERCLOUD_FULL_DIB_EXTRA_ARGS = [
        'overcloud-full',
        'overcloud-controller',
        'overcloud-compute',
        'overcloud-ceph-storage',
    ] + PUPPET_COMMON_ELEMENTS

    AGENT_DIB_EXTRA_ARGS = [
        '-p python-hardware-detect'
    ]

    AGENT_IMAGE_ELEMENT = [
        'ironic-agent',
    ]

    DEPLOY_IMAGE_ELEMENT = [
        'deploy-ironic'
    ]

    # TODO(bnemec): Remove fedora-user in Ocata
    IMAGE_TYPES = [
        'agent-ramdisk',
        'deploy-ramdisk',
        'fedora-user',
        'overcloud-full',
    ]

    _BUILDERS = [
        'dib',
    ]

    def get_parser(self, prog_name):
        parser = super(BuildOvercloudImage, self).get_parser(prog_name)
        image_group = parser.add_mutually_exclusive_group(required=True)
        image_group.add_argument(
            "--all",
            dest="all",
            action="store_true",
            help=_("Build all images"),
        )
        image_group.add_argument(
            "--type",
            dest="image_types",
            metavar='<image type>',
            choices=self.IMAGE_TYPES,
            action="append",
            help=_("Build image by name. One of "
                   "%s. fedora-user is DEPRECATED. Download the latest Fedora "
                   "cloud image directly from "
                   "https://getfedora.org/en/cloud/download/ instead.") %
                 ", ".join(self.IMAGE_TYPES),
        )
        parser.add_argument(
            "--base-image",
            help=_("Image file to use as a base for new images"),
        )
        parser.add_argument(
            "--instack-undercloud-elements",
            dest="instack_undercloud_elements",
            default=os.environ.get(
                "INSTACKUNDERCLOUDELEMENTS", self.INSTACKUNDERCLOUDELEMENTS),
            help=_("Path to Instack Undercloud elements"),
        )
        parser.add_argument(
            "--tripleo-puppet-elements",
            dest="tripleo_puppet_elements",
            default=os.environ.get(
                "TRIPLEOPUPPETELEMENTS", self.TRIPLEOPUPPETELEMENTS),
            help=_("Path to TripleO Puppet elements"),
        )
        parser.add_argument(
            "--elements-path",
            dest="elements_path",
            default=os.environ.get(
                "ELEMENTS_PATH",
                os.pathsep.join([
                    self.TRIPLEOPUPPETELEMENTS,
                    self.INSTACKUNDERCLOUDELEMENTS,
                    '/usr/share/tripleo-image-elements',
                ])),
            help=_("Full elements path, separated by %s") % os.pathsep,
        )
        parser.add_argument(
            "--tmp-dir",
            dest="tmp_dir",
            default=os.environ.get("TMP_DIR", "/var/tmp"),
            help=_("Path to a temporary directory for creating images"),
        )
        parser.add_argument(
            "--node-arch",
            dest="node_arch",
            default=os.environ.get("NODE_ARCH", "amd64"),
            help=_("Architecture of image to build"),
        )
        parser.add_argument(
            "--node-dist",
            dest="node_dist",
            default=os.environ.get("NODE_DIST", ""),
            help=_("Distribution of image to build"),
        )
        parser.add_argument(
            "--registration-method",
            dest="reg_method",
            default=os.environ.get("REG_METHOD", "disable"),
            help=_("Registration method"),
        )
        parser.add_argument(
            "--use-delorean-trunk",
            dest="use_delorean_trunk",
            action='store_true',
            default=(os.environ.get('USE_DELOREAN_TRUNK', '0') == '1'),
            help=_("Use Delorean trunk repo"),
        )
        parser.add_argument(
            "--delorean-trunk-repo",
            dest="delorean_trunk_repo",
            default=os.environ.get(
                'DELOREAN_TRUNK_REPO',
                'http://trunk.rdoproject.org/kilo/centos7/latest-RDO-kilo-CI/'
            ),
            help=_("URL to Delorean trunk repo"),
        )
        parser.add_argument(
            "--delorean-repo-file",
            dest="delorean_repo_file",
            default=os.environ.get('DELOREAN_REPO_FILE', 'delorean-kilo.repo'),
            help=_("Filename for delorean repo config file"),
        )
        parser.add_argument(
            "--overcloud-full-dib-extra-args",
            dest="overcloud_full_dib_extra_args",
            default=os.environ.get(
                "OVERCLOUD_FULL_DIB_EXTRA_ARGS",
                " ".join(self.OVERCLOUD_FULL_DIB_EXTRA_ARGS)),
            help=_("Extra args for Overcloud Full"),
        )
        parser.add_argument(
            "--agent-dib-extra-args",
            dest="agent_dib_extra_args",
            default=os.environ.get(
                "AGENT_DIB_EXTRA_ARGS",
                " ".join(self.AGENT_DIB_EXTRA_ARGS)),
            help=_("Extra args for the IPA image"),
        )
        parser.add_argument(
            "--overcloud-full-name",
            dest="overcloud_full_name",
            default=os.environ.get('OVERCLOUD_FULL_NAME', 'overcloud-full'),
            help=_("Name of overcloud full image"),
        )
        parser.add_argument(
            "--fedora-user-name",
            dest="fedora_user_name",
            default=os.environ.get('FEDORA_USER_NAME', 'fedora-user'),
            help=_("DEPRECATED: Downloading the Fedora image through "
                   "tripleoclient is deprecated in favor of downloading the "
                   "latest Fedora image directly from getfedora.org."),
        )
        parser.add_argument(
            "--agent-name",
            dest="agent_name",
            default=os.environ.get('AGENT_NAME', 'ironic-python-agent'),
            help=_("Name of the IPA ramdisk image"),
        )
        parser.add_argument(
            "--deploy-name",
            dest="deploy_name",
            default=os.environ.get('DEPLOY_NAME', 'deploy-ramdisk-ironic'),
            help=_("DEPRECATED: Name of deployment ramdisk image.  This image "
                   "has been replaced by the Ironic Python Agent ramdisk, so "
                   "you should switch to that as soon as possible."),
        )
        parser.add_argument(
            "--agent-image-element",
            dest="agent_image_element",
            default=os.environ.get(
                'AGENT_IMAGE_ELEMENT',
                " ".join(self.AGENT_IMAGE_ELEMENT)),
            help=_("DIB elements for the IPA image"),
        )
        parser.add_argument(
            "--deploy-image-element",
            dest="deploy_image_element",
            default=os.environ.get(
                'DEPLOY_IMAGE_ELEMENT',
                " ".join(self.DEPLOY_IMAGE_ELEMENT)),
            help=_("DIB elements for deploy image"),
        )
        parser.add_argument(
            "--builder-extra-args",
            dest="builder_extra_args",
            default='',
            help=_("Extra arguments for the image builder"),
        )
        parser.add_argument(
            "--builder",
            dest="builder",
            metavar='<builder>',
            choices=self._BUILDERS,
            default='dib',
            help=_("Image builder. One of "
                   "%s") % ", ".join(self._BUILDERS),
        )
        return parser

    def _set_env_var(self, dest_dict, key_name, default_value):
        dest_dict[key_name] = os.environ.get(key_name, default_value)

    def _prepare_env_variables(self, parsed_args):
        env_vars = {}

        self._set_env_var(
            env_vars, 'ELEMENTS_PATH', parsed_args.elements_path)
        self._set_env_var(env_vars, 'TMP_DIR', parsed_args.tmp_dir)
        self._set_env_var(env_vars, 'DIB_DEFAULT_INSTALLTYPE', 'package')
        self._set_env_var(
            env_vars, 'DELOREAN_TRUNK_REPO', parsed_args.delorean_trunk_repo)
        self._set_env_var(
            env_vars, 'DELOREAN_REPO_FILE', parsed_args.delorean_repo_file)

        # Needed for corosync to be able to use hostnames
        # https://bugs.launchpad.net/tripleo/+bug/1447497
        env_vars['DIB_CLOUD_INIT_ETC_HOSTS'] = ''

        # Attempt to detect host distribution if not specified
        if not parsed_args.node_dist:
            distro = platform.linux_distribution()[0]
            if distro.startswith('Red Hat Enterprise Linux'):
                parsed_args.node_dist = 'rhel7'
            elif distro.startswith('CentOS'):
                parsed_args.node_dist = 'centos7'
            elif distro.startswith('Fedora'):
                parsed_args.node_dist = 'fedora'
            else:
                raise RuntimeError(
                    "Unsupported host distribution detected.")

        dib_common_elements = ['dynamic-login']
        if re.match('rhel7', parsed_args.node_dist):
            env_vars['REG_METHOD'] = parsed_args.reg_method

            env_vars['DELOREAN_REPO_URL'] = parsed_args.delorean_trunk_repo
        elif re.match('centos7', parsed_args.node_dist):
            env_vars['DELOREAN_REPO_URL'] = parsed_args.delorean_trunk_repo
            dib_common_elements.extend([
                'selinux-permissive',
            ])

        dib_common_elements.extend([
            'element-manifest',
            'network-gateway',
        ])

        if parsed_args.node_dist in ['rhel7', 'centos7']:
            self._set_env_var(env_vars, 'FS_TYPE', 'xfs')

        self._set_env_var(env_vars, 'PACKAGES', '1')
        if env_vars.get('PACKAGES') == '1':
            dib_common_elements.extend([
                'enable-packages-install',
                'pip-and-virtualenv-override',
            ])

        if parsed_args.use_delorean_trunk:
            dib_common_elements.append('delorean-repo')

        parsed_args.dib_common_elements = " ".join(dib_common_elements)
        parsed_args.dib_env_vars = env_vars

    def _image_files_exist(self, image_name):
        return (os.path.isfile("%s.initramfs" % image_name) and
                os.path.isfile("%s.kernel" % image_name))

    def _build_image_ramdisk(self, parsed_args, ramdisk_type):
        image_name = vars(parsed_args)["%s_name" % ramdisk_type]
        if not self._image_files_exist(image_name):
            parsed_args._builder.build_ramdisk(parsed_args, ramdisk_type)
        if not self._image_files_exist(image_name):
            raise ImageBuildError(image_name)

    def _build_image_ramdisk_agent(self, parsed_args):
        image_name = vars(parsed_args)["agent_name"]
        if not self._image_files_exist(image_name):
            parsed_args._builder.build_ramdisk_agent(parsed_args)
        if not self._image_files_exist(image_name):
            raise ImageBuildError(image_name)

    def _build_image_ramdisk_deploy(self, parsed_args):
        self._build_image_ramdisk(parsed_args, 'deploy')

    def _build_image_overcloud(self, parsed_args, node_type):
        image_name = "%s.qcow2" % vars(parsed_args)['overcloud_%s_name' %
                                                    node_type]
        if not os.path.isfile(image_name):
            parsed_args._builder.build_image(parsed_args, node_type)
        if not os.path.isfile(image_name):
            raise ImageBuildError(image_name)

    def _build_image_overcloud_full(self, parsed_args):
        self._build_image_overcloud(parsed_args, 'full')

    def _build_image_fedora_user(self, parsed_args):
        warnings.warn('Downloading a Fedora user image with tripleoclient is '
                      'deprecated. Get the latest Fedora cloud image from '
                      'https://getfedora.org/en/cloud/download/ instead.')
        image_name = "%s.qcow2" % parsed_args.fedora_user_name
        if not os.path.isfile(image_name):
            if os.path.isfile('~/.cache/image-create/fedora-21.x86_64.qcow2'):
                # Just copy the already downloaded Fedora cloud image as
                # fedora-user.qcow2
                shutil.copy2(
                    '~/.cache/image-create/fedora-21.x86_64.qcow2',
                    image_name)
            else:
                # Download the image
                r = requests.get(
                    'http://cloud.fedoraproject.org/fedora-21.x86_64.qcow2')
                with open(image_name, 'wb') as f:
                    f.write(r.content)
            # The perms always seem to be wrong when copying out of the cache,
            # so fix them
            os.chmod(
                image_name,
                stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    def _create_builder(self, builder):
        if builder == 'dib':
            return DibImageBuilder()
        # Assert here, as the command line handling should have ensured
        # that the builder is one among a limited choice
        assert False, "unhandled builder in _create_builder"

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        parsed_args._builder = self._create_builder(parsed_args.builder)

        self._prepare_env_variables(parsed_args)
        parsed_args._builder.preprocess_parsed_args(parsed_args)
        self.log.debug("Environment: %s" % parsed_args.dib_env_vars)

        if parsed_args.all:
            self._build_image_ramdisk_agent(parsed_args)
            self._build_image_overcloud_full(parsed_args)
        else:
            for image_type in parsed_args.image_types:
                {
                    'agent-ramdisk': self._build_image_ramdisk_agent,
                    'deploy-ramdisk': self._build_image_ramdisk_deploy,
                    'fedora-user': self._build_image_fedora_user,
                    'overcloud-full': self._build_image_overcloud_full,
                }[image_type](parsed_args)
        print('Successfully built all requested images')


class UploadOvercloudImage(command.Command):
    """Create overcloud glance images from existing image files."""
    log = logging.getLogger(__name__ + ".UploadOvercloudImage")

    def _env_variable_or_set(self, key_name, default_value):
        os.environ[key_name] = os.environ.get(key_name, default_value)

    def _delete_image_if_exists(self, image_client, name):
        try:
            image = utils.find_resource(image_client.images, name)
            image_client.images.delete(image.id)
        except exceptions.CommandError:
            self.log.debug('Image "%s" have already not existed, '
                           'no problem.' % name)

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
        return open(filepath, 'rb')

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

    def _print_image_info(self, image):
        table = PrettyTable(['ID', 'Name', 'Disk Format', 'Size', 'Status'])
        table.add_row([image.id, image.name, image.disk_format, image.size,
                       image.status])
        print(table, file=sys.stdout)

    def _upload_image(self, *args, **kwargs):
        image = self.app.client_manager.image.images.create(*args, **kwargs)
        print('Image "%s" was uploaded.' % image.name, file=sys.stdout)
        self._print_image_info(image)
        return image

    def get_parser(self, prog_name):
        parser = super(UploadOvercloudImage, self).get_parser(prog_name)
        parser.add_argument(
            "--image-path",
            default=os.environ.get('IMAGE_PATH', './'),
            help=_("Path to directory containing image files"),
        )
        parser.add_argument(
            "--os-image",
            default=os.environ.get('OS_IMAGE', 'overcloud-full.qcow2'),
            help=_("OpenStack disk image filename"),
        )
        parser.add_argument(
            "--http-boot",
            default=os.environ.get('HTTP_BOOT', '/httpboot'),
            help=_("Root directory for the introspection image")
        )
        parser.add_argument(
            "--update-existing",
            dest="update_existing",
            action="store_true",
            help=_("Update images if already exist"),
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        self._env_variable_or_set('AGENT_NAME', 'ironic-python-agent')

        self.log.debug("checking if image files exist")

        image_files = [
            '%s.initramfs' % os.environ['AGENT_NAME'],
            '%s.kernel' % os.environ['AGENT_NAME'],
            parsed_args.os_image
        ]

        for image in image_files:
            self._check_file_exists(os.path.join(parsed_args.image_path,
                                                 image))

        image_name = parsed_args.os_image.split('.')[0]

        self.log.debug("uploading overcloud images to glance")

        oc_vmlinuz_name = '%s-vmlinuz' % image_name
        oc_vmlinuz_file = '%s.vmlinuz' % image_name
        kernel = (self._image_try_update(oc_vmlinuz_name,
                                         oc_vmlinuz_file,
                                         parsed_args) or
                  self._upload_image(
                      name=oc_vmlinuz_name,
                      is_public=True,
                      disk_format='aki',
                      data=self._read_image_file_pointer(
                          parsed_args.image_path, oc_vmlinuz_file)
        ))

        oc_initrd_name = '%s-initrd' % image_name
        oc_initrd_file = '%s.initrd' % image_name
        ramdisk = (self._image_try_update(oc_initrd_name,
                                          oc_initrd_file,
                                          parsed_args) or
                   self._upload_image(
                       name=oc_initrd_name,
                       is_public=True,
                       disk_format='ari',
                       data=self._read_image_file_pointer(
                           parsed_args.image_path, oc_initrd_file)
        ))

        oc_name = image_name
        oc_file = '%s.qcow2' % image_name
        overcloud_image = (self._image_try_update(oc_name, oc_file,
                                                  parsed_args) or
                           self._upload_image(
                               name=oc_name,
                               is_public=True,
                               disk_format='qcow2',
                               container_format='bare',
                               properties={'kernel_id': kernel.id,
                                           'ramdisk_id': ramdisk.id},
                               data=self._read_image_file_pointer(
                                   parsed_args.image_path, oc_file)
        ))

        # check overcloud image links
        if (overcloud_image.properties['kernel_id'] != kernel.id or
                overcloud_image.properties['ramdisk_id'] != ramdisk.id):
            self.log.error('Link overcloud image to it\'s initrd and kernel'
                           ' images is MISSING OR leads to OLD image.'
                           ' You can keep it or fix it manually.')

        self.log.debug("uploading bm images to glance")

        deploy_kernel_name = 'bm-deploy-kernel'
        deploy_kernel_file = '%s.kernel' % os.environ['AGENT_NAME']
        self._image_try_update(deploy_kernel_name, deploy_kernel_file,
                               parsed_args) or self._upload_image(
            name=deploy_kernel_name,
            is_public=True,
            disk_format='aki',
            data=self._read_image_file_pointer(
                parsed_args.image_path,
                deploy_kernel_file)
        )

        deploy_ramdisk_name = 'bm-deploy-ramdisk'
        deploy_ramdisk_file = '%s.initramfs' % os.environ['AGENT_NAME']
        self._image_try_update(deploy_ramdisk_name, deploy_ramdisk_file,
                               parsed_args) or self._upload_image(
            name=deploy_ramdisk_name,
            is_public=True,
            disk_format='ari',
            data=self._read_image_file_pointer(parsed_args.image_path,
                                               deploy_ramdisk_file)
        )

        self.log.debug("copy agent images to HTTP BOOT dir")

        self._file_create_or_update(
            os.path.join(parsed_args.image_path,
                         '%s.kernel' % os.environ['AGENT_NAME']),
            os.path.join(parsed_args.http_boot, 'agent.kernel'),
            parsed_args.update_existing
        )

        self._file_create_or_update(
            os.path.join(parsed_args.image_path,
                         '%s.initramfs' % os.environ['AGENT_NAME']),
            os.path.join(parsed_args.http_boot, 'agent.ramdisk'),
            parsed_args.update_existing
        )
