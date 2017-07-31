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

import datetime
import json
import logging
import os
import re
import sys
import tempfile

from heatclient.common import template_utils
from osc_lib.command import command
from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
import yaml

from tripleo_common.image import image_uploader
from tripleo_common.image import kolla_builder

from tripleoclient import constants


class UploadImage(command.Command):
    """Push overcloud container images to registries."""

    auth_required = False
    log = logging.getLogger(__name__ + ".UploadImage")

    def get_parser(self, prog_name):
        parser = super(UploadImage, self).get_parser(prog_name)
        parser.add_argument(
            "--config-file",
            dest="config_files",
            metavar='<yaml config file>',
            default=[],
            action="append",
            required=True,
            help=_("YAML config file specifying the image build. May be "
                   "specified multiple times. Order is preserved, and later "
                   "files will override some options in previous files. "
                   "Other options will append."),
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        uploader = image_uploader.ImageUploadManager(
            parsed_args.config_files)
        uploader.upload()


class BuildImage(command.Command):
    """Build overcloud container images with kolla-build."""

    auth_required = False
    log = logging.getLogger(__name__ + ".BuildImage")

    @staticmethod
    def images_from_deps(images, dep):
        '''Builds a list from the dependencies depth-first. '''
        if isinstance(dep, list):
            for v in dep:
                BuildImage.images_from_deps(images, v)
        elif isinstance(dep, dict):
            for k, v in dep.items():
                images.append(k)
                BuildImage.images_from_deps(images, v)
        else:
            images.append(dep)

    def get_parser(self, prog_name):
        parser = super(BuildImage, self).get_parser(prog_name)
        parser.add_argument(
            "--config-file",
            dest="config_files",
            metavar='<yaml config file>',
            default=[],
            action="append",
            required=True,
            help=_("YAML config file specifying the images to build. May be "
                   "specified multiple times. Order is preserved, and later "
                   "files will override some options in previous files. "
                   "Other options will append."),
        )
        parser.add_argument(
            "--kolla-config-file",
            dest="kolla_config_files",
            metavar='<config file>',
            default=[],
            action="append",
            required=True,
            help=_("Path to a Kolla config file to use. Multiple config files "
                   "can be specified, with values in later files taking "
                   "precedence."),
        )
        parser.add_argument(
            '--list-images',
            dest='list_images',
            action='store_true',
            default=False,
            help=_('Show the images which would be built instead of '
                   'building them.')
        )
        parser.add_argument(
            '--list-dependencies',
            dest='list_dependencies',
            action='store_true',
            default=False,
            help=_('Show the image build dependencies instead of '
                   'building them.')
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        fd, path = tempfile.mkstemp(prefix='kolla_conf_')
        with os.fdopen(fd, 'w') as tmp:
            tmp.write('[DEFAULT]\n')
            if parsed_args.list_images or parsed_args.list_dependencies:
                tmp.write('list_dependencies=true')
        kolla_config_files = list(parsed_args.kolla_config_files)
        kolla_config_files.append(path)

        try:
            builder = kolla_builder.KollaImageBuilder(parsed_args.config_files)
            result = builder.build_images(kolla_config_files)
            if parsed_args.list_dependencies:
                deps = json.loads(result)
                yaml.safe_dump(deps, self.app.stdout, indent=2,
                               default_flow_style=False)
            elif parsed_args.list_images:
                deps = json.loads(result)
                images = []
                BuildImage.images_from_deps(images, deps)
                yaml.safe_dump(images, self.app.stdout,
                               default_flow_style=False)
            elif result:
                self.app.stdout.write(result)
        finally:
            os.remove(path)


class PrepareImageFiles(command.Command):
    """Generate files defining the images, tags and registry."""

    auth_required = False
    log = logging.getLogger(__name__ + ".PrepareImageFiles")

    def get_parser(self, prog_name):
        parser = super(PrepareImageFiles, self).get_parser(prog_name)
        template_file = os.path.join(sys.prefix, 'share', 'tripleo-common',
                                     'container-images',
                                     'overcloud_containers.yaml.j2')
        roles_file = os.path.join(constants.TRIPLEO_HEAT_TEMPLATES,
                                  constants.OVERCLOUD_ROLES_FILE)
        parser.add_argument(
            "--template-file",
            dest="template_file",
            default=template_file,
            metavar='<yaml template file>',
            help=_("YAML template file which the images config file will be "
                   "built from.\n"
                   "Default: %s") % template_file,
        )
        parser.add_argument(
            "--pull-source",
            dest="pull_source",
            metavar='<location>',
            help=_("Location of image registry to pull images from. "
                   "If specified, a pull_source will be set for every image "
                   "entry."),
        )
        parser.add_argument(
            "--push-destination",
            dest="push_destination",
            metavar='<location>',
            help=_("Location of image registry to push images to. "
                   "If specified, a push_destination will be set for every "
                   "image entry."),
        )
        parser.add_argument(
            "--tag",
            dest="tag",
            default="latest",
            metavar='<tag>',
            help=_("Override the default tag substitution.\n"
                   "Default: latest"),
        )
        parser.add_argument(
            "--namespace",
            dest="namespace",
            default="tripleoupstream",
            metavar='<namespace>',
            help=_("Override the default namespace substitution.\n"
                   "Default: tripleoupstream"),
        )
        parser.add_argument(
            "--prefix",
            dest="prefix",
            default="centos-binary-",
            metavar='<prefix>',
            help=_("Override the default name prefix substitution.\n"
                   "Default: centos-binary-"),
        )
        parser.add_argument(
            "--suffix",
            dest="suffix",
            default="",
            metavar='<suffix>',
            help=_("Override the default name suffix substitution.\n"
                   "Default is empty."),
        )
        parser.add_argument(
            '--set',
            metavar='<variable=value>',
            action='append',
            help=_('Set the value of a variable in the template, even if it '
                   'has no dedicated argument such as "--suffix".')
        )
        parser.add_argument(
            "--exclude",
            dest="excludes",
            metavar='<regex>',
            default=[],
            action="append",
            help=_("Pattern to match against resulting imagename entries to "
                   "exclude from the final output. Can be specified multiple "
                   "times."),
        )
        parser.add_argument(
            "--images-file",
            dest="images_file",
            metavar='<file path>',
            help=_("File to write resulting image entries to, as well as "
                   "stdout. Any existing file will be overwritten."),
        )
        parser.add_argument(
            '--service-environment-file', '-e', metavar='<file path>',
            action='append', dest='environment_files',
            help=_('Environment files specifying which services are '
                   'containerized. Entries will be filtered to only contain '
                   'images used by containerized services. (Can be specified '
                   'more than once.)')
        )
        parser.add_argument(
            "--env-file",
            dest="env_file",
            metavar='<file path>',
            help=_("File to write heat environment file which specifies all "
                   "image parameters. Any existing file will be overwritten."),
        )
        parser.add_argument(
            '--roles-file', '-r', dest='roles_file',
            default=roles_file,
            help=_('Roles file, overrides the default %s'
                   ) % constants.OVERCLOUD_ROLES_FILE
        )
        return parser

    def parse_set_values(self, subs, set_values):
        if not set_values:
            return
        for s in set_values:
            try:
                (n, v) = s.split(('='), 1)
                subs[n] = v
            except ValueError:
                msg = _('Malformed --set(%s). '
                        'Use the variable=value format.') % s
                raise oscexc.CommandError(msg)

    def write_env_file(self, params, env_file):

        with os.fdopen(os.open(env_file,
                       os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o666),
                       'w') as f:
            f.write('# Generated with the following on %s\n#\n' %
                    datetime.datetime.now().isoformat())
            f.write('#   openstack %s\n#\n\n' %
                    ' '.join(self.app.command_options))

            yaml.safe_dump({'parameter_defaults': params}, f,
                           default_flow_style=False)

    def get_enabled_services(self, environment, roles_file):
        enabled_services = set()
        try:
            roles_data = yaml.safe_load(open(roles_file).read())
        except IOError:
            return enabled_services

        parameter_defaults = environment.get('parameter_defaults', {})

        for role in roles_data:
            count = parameter_defaults.get('%sCount' % role['name'],
                                           role.get('CountDefault', 0))
            if count > 0:
                enabled_services.update(
                    parameter_defaults.get('%sServices' % role['name'],
                                           role.get('ServicesDefault', [])))

        return enabled_services

    def build_service_filter(self, environment_files, roles_file):
        # Do not filter unless asked for it
        if not environment_files:
            return None

        env_files, env = (
            template_utils.process_multiple_environments_and_files(
                environment_files))
        enabled_services = self.get_enabled_services(env, roles_file)
        containerized_services = set()
        for service, env_path in env.get('resource_registry', {}).items():
            # Use the template path to determine if it represents a
            # containerized service
            if '/docker/services/' in env_path:
                containerized_services.add(service)

        return containerized_services.intersection(enabled_services)

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        service_filter = self.build_service_filter(
            parsed_args.environment_files,  parsed_args.roles_file)

        neutron_driver = None
        if service_filter:
            if 'OS::TripleO::Services::OpenDaylightApi' in service_filter:
                neutron_driver = 'odl'
            elif 'OS::TripleO::Services::OVNController' in service_filter:
                neutron_driver = 'ovn'

        subs = {
            'tag': parsed_args.tag,
            'namespace': parsed_args.namespace,
            'name_prefix': parsed_args.prefix,
            'name_suffix': parsed_args.suffix,
            'neutron_driver': neutron_driver,
        }
        self.parse_set_values(subs, parsed_args.set)

        def ffunc(entry):
            imagename = entry.get('imagename', '')
            for p in parsed_args.excludes:
                if re.search(p, imagename):
                    return None
            if service_filter is not None:
                # check the entry is for a service being deployed
                image_services = set(entry.get('services', []))
                if not service_filter.intersection(image_services):
                    return None
            if parsed_args.pull_source:
                entry['pull_source'] = parsed_args.pull_source
            if parsed_args.push_destination:
                entry['push_destination'] = parsed_args.push_destination
            return entry

        builder = kolla_builder.KollaImageBuilder([parsed_args.template_file])
        result = builder.container_images_from_template(filter=ffunc, **subs)

        params = {}
        for entry in result:
            imagename = entry.get('imagename', '')
            if 'params' in entry:
                for p in entry.pop('params'):
                    params[p] = imagename
            if 'services' in entry:
                del(entry['services'])

        if parsed_args.env_file:
            self.write_env_file(params, parsed_args.env_file)

        result_str = yaml.safe_dump({'container_images': result},
                                    default_flow_style=False)
        sys.stdout.write(result_str)

        if parsed_args.images_file:
            with os.fdopen(os.open(parsed_args.images_file,
                           os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o666),
                           'w') as f:
                f.write(result_str)
