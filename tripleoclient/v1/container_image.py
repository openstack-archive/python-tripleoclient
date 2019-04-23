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

import copy
import datetime
import json
import logging
import os
import shutil
import sys
import tempfile
import time

from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
import six
import yaml

from tripleo_common.image.builder import buildah
from tripleo_common.image import image_uploader
from tripleo_common.image import kolla_builder

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils


def build_env_file(params, command_options):

    f = six.StringIO()
    f.write('# Generated with the following on %s\n#\n' %
            datetime.datetime.now().isoformat())
    f.write('#   openstack %s\n#\n\n' %
            ' '.join(command_options))

    yaml.safe_dump({'parameter_defaults': params}, f,
                   default_flow_style=False)
    return f.getvalue()


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
        parser.add_argument(
            "--cleanup",
            dest="cleanup",
            metavar='<full, partial, none>',
            default=image_uploader.CLEANUP_FULL,
            help=_("Cleanup behavior for local images left after upload. "
                   "The default 'full' will attempt to delete all local "
                   "images. 'partial' will leave images required for "
                   "deployment on this host. 'none' will do no cleanup.")
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        if parsed_args.cleanup not in image_uploader.CLEANUP:
            raise oscexc.CommandError('--cleanup must be one of: %s' %
                                      ', '.join(image_uploader.CLEANUP))
        uploader = image_uploader.ImageUploadManager(
            parsed_args.config_files, cleanup=parsed_args.cleanup)
        try:
            uploader.upload()
        except KeyboardInterrupt:  # ctrl-c
            self.log.warning('Upload was interrupted by ctrl-c.')


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
        default_kolla_conf = os.path.join(
            sys.prefix, 'share', 'tripleo-common', 'container-images',
            'tripleo_kolla_config_overrides.conf')
        parser = super(BuildImage, self).get_parser(prog_name)
        parser.add_argument(
            "--config-file",
            dest="config_files",
            metavar='<yaml config file>',
            default=[],
            action="append",
            help=_("YAML config file specifying the images to build. May be "
                   "specified multiple times. Order is preserved, and later "
                   "files will override some options in previous files. "
                   "Other options will append. If not specified, the default "
                   "set of containers will be built."),
        )
        parser.add_argument(
            "--kolla-config-file",
            dest="kolla_config_files",
            metavar='<config file>',
            default=[default_kolla_conf],
            action="append",
            required=True,
            help=_("Path to a Kolla config file to use. Multiple config files "
                   "can be specified, with values in later files taking "
                   "precedence. By default, tripleo kolla conf file {conf} "
                   "is added.").format(conf=default_kolla_conf),
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
        parser.add_argument(
            "--exclude",
            dest="excludes",
            metavar='<container-name>',
            default=[],
            action="append",
            help=_("Name of a container to match against the list of "
                   "containers to be built to skip. Can be specified multiple "
                   "times."),
        )
        parser.add_argument(
            '--use-buildah',
            dest='use_buildah',
            action='store_true',
            default=False,
            help=_('Use Buildah instead of Docker to build the images '
                   'with Kolla.')
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
        kolla_tmp_dir = None
        if parsed_args.use_buildah:
            # A temporary directory is needed to let Kolla generates the
            # Dockerfiles that will be used by Buildah to build the images.
            kolla_tmp_dir = tempfile.mkdtemp(prefix='kolla-')

        try:
            builder = kolla_builder.KollaImageBuilder(parsed_args.config_files)
            result = builder.build_images(kolla_config_files,
                                          parsed_args.excludes,
                                          parsed_args.use_buildah,
                                          kolla_tmp_dir)

            if parsed_args.use_buildah:
                deps = json.loads(result)
                kolla_cfg = utils.get_read_config(kolla_config_files)
                bb = buildah.BuildahBuilder(
                    kolla_tmp_dir, deps,
                    utils.get_from_cfg(kolla_cfg, "base"),
                    utils.get_from_cfg(kolla_cfg, "type"),
                    utils.get_from_cfg(kolla_cfg, "tag"),
                    utils.get_from_cfg(kolla_cfg, "namespace"),
                    utils.get_from_cfg(kolla_cfg, "registry"),
                    utils.getboolean_from_cfg(kolla_cfg, "push"))
                bb.build_all()
            elif parsed_args.list_dependencies:
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
        try:
            roles_file = utils.rel_or_abs_path(
                constants.OVERCLOUD_ROLES_FILE,
                constants.TRIPLEO_HEAT_TEMPLATES)
        except exceptions.DeploymentError:
            roles_file = None
        defaults = kolla_builder.container_images_prepare_defaults()

        parser.add_argument(
            "--template-file",
            dest="template_file",
            default=kolla_builder.DEFAULT_TEMPLATE_FILE,
            metavar='<yaml template file>',
            help=_("YAML template file which the images config file will be "
                   "built from.\n"
                   "Default: %s") % kolla_builder.DEFAULT_TEMPLATE_FILE,
        )
        parser.add_argument(
            "--pull-source",
            dest="pull_source",
            metavar='<location>',
            help=_("Location of image registry to pull images from. "
                   "(DEPRECATED. Include the registry in --namespace)"),
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
            default=defaults['tag'],
            metavar='<tag>',
            help=_("Override the default tag substitution. "
                   "If --tag-from-label is specified, "
                   "start discovery with this tag.\n"
                   "Default: %s") % defaults['tag'],
        )
        parser.add_argument(
            "--tag-from-label",
            dest="tag_from_label",
            metavar='<image label>',
            help=_("Use the value of the specified label(s) to discover the "
                   "tag. Labels can be combined in a template format, "
                   "for example: {version}-{release}"),
        )
        parser.add_argument(
            "--namespace",
            dest="namespace",
            default=defaults['namespace'],
            metavar='<namespace>',
            help=_("Override the default namespace substitution.\n"
                   "Default: %s") % defaults['namespace'],
        )
        parser.add_argument(
            "--prefix",
            dest="prefix",
            default=defaults['name_prefix'],
            metavar='<prefix>',
            help=_("Override the default name prefix substitution.\n"
                   "Default: %s") % defaults['name_prefix'],
        )
        parser.add_argument(
            "--suffix",
            dest="suffix",
            default=defaults['name_suffix'],
            metavar='<suffix>',
            help=_("Override the default name suffix substitution.\n"
                   "Default: %s") % defaults['name_suffix'],
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
            "--include",
            dest="includes",
            metavar='<regex>',
            default=[],
            action="append",
            help=_("Pattern to match against resulting imagename entries to "
                   "include in final output. Can be specified multiple "
                   "times, entries not matching any --include will be "
                   "excluded. --exclude is ignored if --include is used."),
        )
        parser.add_argument(
            "--output-images-file",
            dest="output_images_file",
            metavar='<file path>',
            help=_("File to write resulting image entries to, as well as "
                   "stdout. Any existing file will be overwritten."),
        )
        parser.add_argument(
            '--environment-file', '-e', metavar='<file path>',
            action='append', dest='environment_files',
            help=_('Environment files specifying which services are '
                   'containerized. Entries will be filtered to only contain '
                   'images used by containerized services. (Can be specified '
                   'more than once.)')
        )
        parser.add_argument(
            '--environment-directory', metavar='<HEAT ENVIRONMENT DIRECTORY>',
            action='append', dest='environment_directories',
            default=[os.path.expanduser(constants.DEFAULT_ENV_DIRECTORY)],
            help=_('Environment file directories that are automatically '
                   'added to the update command. Entries will be filtered '
                   'to only contain images used by containerized services. '
                   'Can be specified more than once. Files in directories are '
                   'loaded in ascending sort order.')
        )
        parser.add_argument(
            "--output-env-file",
            dest="output_env_file",
            metavar='<file path>',
            help=_("File to write heat environment file which specifies all "
                   "image parameters. Any existing file will be overwritten."),
        )
        parser.add_argument(
            '--roles-file', '-r', dest='roles_file',
            default=roles_file,
            help=_(
                'Roles file, overrides the default %s in the t-h-t templates '
                'directory used for deployment. May be an '
                'absolute path or the path relative to the templates dir.'
                ) % constants.OVERCLOUD_ROLES_FILE
        )
        parser.add_argument(
            '--modify-role',
            dest='modify_role',
            help=_('Name of ansible role to run between every image upload '
                   'pull and push.')
        )
        parser.add_argument(
            '--modify-vars',
            dest='modify_vars',
            help=_('Ansible variable file containing variables to use when '
                   'invoking the role --modify-role.')
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

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        roles_data = utils.fetch_roles_file(parsed_args.roles_file) or set()

        env = utils.build_prepare_env(
            parsed_args.environment_files,
            parsed_args.environment_directories
        )

        if roles_data:
            service_filter = kolla_builder.build_service_filter(
                env, roles_data)
        else:
            service_filter = None
        mapping_args = {
            'tag': parsed_args.tag,
            'namespace': parsed_args.namespace,
            'name_prefix': parsed_args.prefix,
            'name_suffix': parsed_args.suffix,
        }
        self.parse_set_values(mapping_args, parsed_args.set)
        pd = env.get('parameter_defaults', {})
        kolla_builder.set_neutron_driver(pd, mapping_args)

        output_images_file = (parsed_args.output_images_file
                              or 'container_images.yaml')
        modify_role = None
        modify_vars = None
        append_tag = None
        if parsed_args.modify_role:
            modify_role = parsed_args.modify_role
            append_tag = time.strftime('-modified-%Y%m%d%H%M%S')
        if parsed_args.modify_vars:
            modify_vars = yaml.safe_load(open(parsed_args.modify_vars).read())

        prepare_data = kolla_builder.container_images_prepare(
            excludes=parsed_args.excludes,
            includes=parsed_args.includes,
            service_filter=service_filter,
            pull_source=parsed_args.pull_source,
            push_destination=parsed_args.push_destination,
            mapping_args=mapping_args,
            output_env_file=parsed_args.output_env_file,
            output_images_file=output_images_file,
            tag_from_label=parsed_args.tag_from_label,
            modify_role=modify_role,
            modify_vars=modify_vars,
            append_tag=append_tag,
            template_file=parsed_args.template_file
        )
        if parsed_args.output_env_file:
            params = prepare_data[parsed_args.output_env_file]
            if os.path.exists(parsed_args.output_env_file):
                self.log.warn("Output env file exists, moving it to backup.")
                shutil.move(parsed_args.output_env_file,
                            parsed_args.output_env_file + ".backup")
            with os.fdopen(os.open(parsed_args.output_env_file,
                           os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o666),
                           'w') as f:
                f.write(build_env_file(params, self.app.command_options))

        result = prepare_data[output_images_file]
        result_str = yaml.safe_dump({'container_images': result},
                                    default_flow_style=False)
        sys.stdout.write(result_str)

        if parsed_args.output_images_file:
            with os.fdopen(os.open(parsed_args.output_images_file,
                           os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o666),
                           'w') as f:
                f.write(result_str)


class DiscoverImageTag(command.Command):
    """Discover the versioned tag for an image."""

    auth_required = False
    log = logging.getLogger(__name__ + ".DiscoverImageTag")

    def get_parser(self, prog_name):
        parser = super(DiscoverImageTag, self).get_parser(prog_name)
        parser.add_argument(
            "--image",
            dest="image",
            metavar='<container image>',
            required=True,
            help=_("Fully qualified name of the image to discover the tag for "
                   "(Including registry and stable tag)."),
        )
        parser.add_argument(
            "--tag-from-label",
            dest="tag_from_label",
            metavar='<image label>',
            help=_("Use the value of the specified label(s) to discover the "
                   "tag. Labels can be combined in a template format, "
                   "for example: {version}-{release}"),
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        uploader = image_uploader.ImageUploadManager([])
        print(uploader.discover_image_tag(
            image=parsed_args.image,
            tag_from_label=parsed_args.tag_from_label
        ))


class TripleOImagePrepareDefault(command.Command):
    """Generate a default ContainerImagePrepare parameter."""

    auth_required = False
    log = logging.getLogger(__name__ + ".TripleoImagePrepare")

    def get_parser(self, prog_name):
        parser = super(TripleOImagePrepareDefault, self).get_parser(prog_name)
        parser.add_argument(
            "--output-env-file",
            dest="output_env_file",
            metavar='<file path>',
            help=_("File to write environment file containing default "
                   "ContainerImagePrepare value."),
        )
        parser.add_argument(
            '--local-push-destination',
            dest='push_destination',
            action='store_true',
            default=False,
            help=_('Include a push_destination to trigger upload to a local '
                   'registry.')
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        cip = copy.deepcopy(kolla_builder.CONTAINER_IMAGE_PREPARE_PARAM)
        if parsed_args.push_destination:
            for entry in cip:
                entry['push_destination'] = True
        params = {
            'ContainerImagePrepare': cip
        }
        env_data = build_env_file(params, self.app.command_options)
        self.app.stdout.write(env_data)
        if parsed_args.output_env_file:
            if os.path.exists(parsed_args.output_env_file):
                self.log.warn("Output env file exists, moving it to backup.")
                shutil.move(parsed_args.output_env_file,
                            parsed_args.output_env_file + ".backup")
            with os.fdopen(os.open(parsed_args.output_env_file,
                           os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o666),
                           'w') as f:
                f.write(build_env_file(params, self.app.command_options))


class TripleOImagePrepare(command.Command):
    """Prepare and upload containers from a single command."""

    auth_required = False
    log = logging.getLogger(__name__ + ".TripleoImagePrepare")

    def get_parser(self, prog_name):
        parser = super(TripleOImagePrepare, self).get_parser(prog_name)
        try:
            roles_file = utils.rel_or_abs_path(
                constants.OVERCLOUD_ROLES_FILE,
                constants.TRIPLEO_HEAT_TEMPLATES)
        except exceptions.DeploymentError:
            roles_file = None
        parser.add_argument(
            '--environment-file', '-e', metavar='<file path>',
            action='append', dest='environment_files',
            help=_('Environment file containing the ContainerImagePrepare '
                   'parameter which specifies all prepare actions. '
                   'Also, environment files specifying which services are '
                   'containerized. Entries will be filtered to only contain '
                   'images used by containerized services. (Can be specified '
                   'more than once.)')
        )
        parser.add_argument(
            '--environment-directory', metavar='<HEAT ENVIRONMENT DIRECTORY>',
            action='append', dest='environment_directories',
            default=[os.path.expanduser(constants.DEFAULT_ENV_DIRECTORY)],
            help=_('Environment file directories that are automatically '
                   'added to the environment. '
                   'Can be specified more than once. Files in directories are '
                   'loaded in ascending sort order.')
        )
        parser.add_argument(
            '--roles-file', '-r', dest='roles_file',
            default=roles_file,
            help=_(
                'Roles file, overrides the default %s in the t-h-t templates '
                'directory used for deployment. May be an '
                'absolute path or the path relative to the templates dir.'
                ) % constants.OVERCLOUD_ROLES_FILE
        )
        parser.add_argument(
            "--output-env-file",
            dest="output_env_file",
            metavar='<file path>',
            help=_("File to write heat environment file which specifies all "
                   "image parameters. Any existing file will be overwritten."),
        )
        parser.add_argument(
            '--dry-run',
            dest='dry_run',
            action='store_true',
            default=False,
            help=_('Do not perform any pull, modify, or push operations. '
                   'The environment file will still be populated as if these '
                   'operations were performed.')
        )
        parser.add_argument(
            "--cleanup",
            dest="cleanup",
            metavar='<full, partial, none>',
            default=image_uploader.CLEANUP_FULL,
            help=_("Cleanup behavior for local images left after upload. "
                   "The default 'full' will attempt to delete all local "
                   "images. 'partial' will leave images required for "
                   "deployment on this host. 'none' will do no cleanup.")
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if parsed_args.cleanup not in image_uploader.CLEANUP:
            raise oscexc.CommandError('--cleanup must be one of: %s' %
                                      ', '.join(image_uploader.CLEANUP))

        roles_data = utils.fetch_roles_file(parsed_args.roles_file)

        env = utils.build_prepare_env(
            parsed_args.environment_files,
            parsed_args.environment_directories
        )

        params = kolla_builder.container_images_prepare_multi(
            env, roles_data, dry_run=parsed_args.dry_run,
            cleanup=parsed_args.cleanup)
        env_data = build_env_file(params, self.app.command_options)
        if parsed_args.output_env_file:
            if os.path.exists(parsed_args.output_env_file):
                self.log.warn("Output env file exists, moving it to backup.")
                shutil.move(parsed_args.output_env_file,
                            parsed_args.output_env_file + ".backup")
            with os.fdopen(os.open(parsed_args.output_env_file,
                           os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o666),
                           'w') as f:
                f.write(build_env_file(params, self.app.command_options))
        else:
            self.app.stdout.write(env_data)
