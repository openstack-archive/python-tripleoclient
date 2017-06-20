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
import logging
import os
import re
import sys

from osc_lib.command import command
from osc_lib.i18n import _
import yaml

from tripleo_common.image import image_uploader
from tripleo_common.image import kolla_builder


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
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        builder = kolla_builder.KollaImageBuilder(parsed_args.config_files)
        builder.build_images(parsed_args.kolla_config_files)


class PrepareImageFiles(command.Command):
    """Generate files defining the images, tags and registry."""

    auth_required = False
    log = logging.getLogger(__name__ + ".PrepareImageFiles")

    def get_parser(self, prog_name):
        parser = super(PrepareImageFiles, self).get_parser(prog_name)
        template_file = os.path.join(sys.prefix, 'share', 'tripleo-common',
                                     'container-images',
                                     'overcloud_containers.yaml.j2')
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
            "--env-file",
            dest="env_file",
            metavar='<file path>',
            help=_("File to write heat environment file which specifies all "
                   "image parameters. Any existing file will be overwritten."),
        )
        return parser

    def write_env_file(self, result, env_file):
        params = {}
        for entry in result:
            imagename = entry.get('imagename', '')
            if 'params' in entry:
                for p in entry.pop('params'):
                    params[p] = imagename

        with os.fdopen(os.open(env_file,
                       os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o666),
                       'w') as f:
            f.write('# Generated with the following on %s\n#\n' %
                    datetime.datetime.now().isoformat())
            f.write('#   %s\n#\n\n' % ' '.join(self.app.command_options))

            yaml.safe_dump({'parameter_defaults': params}, f,
                           default_flow_style=False)

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        subs = {
            'tag': parsed_args.tag,
            'namespace': parsed_args.namespace,
            'name_prefix': parsed_args.prefix,
            'name_suffix': parsed_args.suffix,
        }

        def ffunc(entry):
            imagename = entry.get('imagename', '')
            for p in parsed_args.excludes:
                if re.search(p, imagename):
                    return None
            if parsed_args.pull_source:
                entry['pull_source'] = parsed_args.pull_source
            if parsed_args.push_destination:
                entry['push_destination'] = parsed_args.push_destination
            return entry

        builder = kolla_builder.KollaImageBuilder([parsed_args.template_file])
        result = builder.container_images_from_template(filter=ffunc, **subs)

        if parsed_args.env_file:
            self.write_env_file(result, parsed_args.env_file)

        result_str = yaml.safe_dump({'container_images': result},
                                    default_flow_style=False)
        sys.stdout.write(result_str)

        if parsed_args.images_file:
            with os.fdopen(os.open(parsed_args.images_file,
                           os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o666),
                           'w') as f:
                f.write(result_str)
