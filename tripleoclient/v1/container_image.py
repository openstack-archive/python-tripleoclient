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
import errno
import json
import logging
import os
import shutil
import sys
import tempfile
import time
import uuid

from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
import six
from six.moves.urllib import parse
import yaml

from tripleo_common.image.builder import buildah
from tripleo_common.image import image_uploader
from tripleo_common.image import kolla_builder
from tripleo_common.utils.locks import processlock

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
        lock = processlock.ProcessLock()
        uploader = image_uploader.ImageUploadManager(
            parsed_args.config_files, cleanup=parsed_args.cleanup, lock=lock)
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
        parser.add_argument(
            "--work-dir",
            dest="work_dir",
            default='/tmp/container-builds',
            metavar='<container builds directory>',
            help=_("TripleO container builds directory, storing configs and "
                   "logs for each image and its dependencies.")
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
        # Generate an unique work directory so we can keep configs and logs
        # each time we run the command; they'll be stored in work_dir.
        kolla_work_dir = os.path.join(parsed_args.work_dir, str(uuid.uuid4()))

        # Make sure the unique work directory exists
        if not os.path.exists(kolla_work_dir):
            self.log.debug("Creating container builds "
                           "workspace in: %s" % kolla_work_dir)
            os.makedirs(kolla_work_dir)

        builder = kolla_builder.KollaImageBuilder(parsed_args.config_files)
        result = builder.build_images(kolla_config_files,
                                      parsed_args.excludes,
                                      parsed_args.use_buildah,
                                      kolla_work_dir)

        if parsed_args.use_buildah:
            deps = json.loads(result)
            kolla_cfg = utils.get_read_config(kolla_config_files)
            bb = buildah.BuildahBuilder(
                kolla_work_dir, deps,
                utils.get_from_cfg(kolla_cfg, "base"),
                utils.get_from_cfg(kolla_cfg, "type"),
                utils.get_from_cfg(kolla_cfg, "tag"),
                utils.get_from_cfg(kolla_cfg, "namespace"),
                utils.get_from_cfg(kolla_cfg, "registry"),
                utils.getboolean_from_cfg(kolla_cfg, "push"))
            bb.build_all()
        elif parsed_args.list_dependencies:
            deps = json.loads(result)
            yaml.safe_dump(
                deps,
                self.app.stdout,
                indent=2,
                default_flow_style=False
            )
        elif parsed_args.list_images:
            deps = json.loads(result)
            images = []
            BuildImage.images_from_deps(images, deps)
            yaml.safe_dump(
                images,
                self.app.stdout,
                default_flow_style=False
            )
        elif result:
            self.app.stdout.write(result)


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
        self.log.warning("[DEPRECATED] This command has been deprecated and "
                         "replaced by the 'openstack tripleo container image "
                         "prepare' command.")

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
            with open(parsed_args.modify_vars) as m:
                modify_vars = yaml.safe_load(m.read())

        prepare_data = kolla_builder.container_images_prepare(
            excludes=parsed_args.excludes,
            includes=parsed_args.includes,
            service_filter=service_filter,
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
            output_env_file_expanded = os.path.expanduser(
                parsed_args.output_env_file)
            if os.path.exists(output_env_file_expanded):
                self.log.warning("Output env file exists, "
                                 "moving it to backup.")
                shutil.move(output_env_file_expanded,
                            output_env_file_expanded + ".backup")
            utils.safe_write(output_env_file_expanded,
                             build_env_file(params, self.app.command_options))

        result = prepare_data[output_images_file]
        result_str = yaml.safe_dump({'container_images': result},
                                    default_flow_style=False)
        sys.stdout.write(result_str)

        if parsed_args.output_images_file:
            utils.safe_write(parsed_args.output_images_file, result_str)


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
        self.log.warning("[DEPRECATED] This command has been deprecated and "
                         "replaced by the 'openstack tripleo container image "
                         "prepare' command.")

        lock = processlock.ProcessLock()
        uploader = image_uploader.ImageUploadManager([], lock=lock)
        print(uploader.discover_image_tag(
            image=parsed_args.image,
            tag_from_label=parsed_args.tag_from_label
        ))


class TripleOContainerImagePush(command.Command):
    """Push specified image to registry."""

    auth_required = False
    log = logging.getLogger(__name__ + ".TripleoContainerImagePush")

    def get_parser(self, prog_name):
        parser = super(TripleOContainerImagePush, self).get_parser(prog_name)
        parser.add_argument(
            "--local",
            dest="local",
            default=False,
            action="store_true",
            help=_("Use this flag if the container image is already on the "
                   "current system and does not need to be pulled from a "
                   "remote registry.")
        )
        parser.add_argument(
            "--registry-url",
            dest="registry_url",
            metavar='<registry url>',
            default=None,
            help=_("URL of the destination registry in the form "
                   "<fqdn>:<port>.")
        )
        parser.add_argument(
            "--append-tag",
            dest="append_tag",
            default='',
            help=_("Tag to append to the existing tag when pushing the "
                   "container. ")
        )
        parser.add_argument(
            "--username",
            dest="username",
            metavar='<username>',
            help=_("Username for the destination image registry.")
        )
        parser.add_argument(
            "--password",
            dest="password",
            metavar='<password>',
            help=_("Password for the destination image registry.")
        )
        parser.add_argument(
            "--source-username",
            dest="source_username",
            metavar='<source_username>',
            help=_("Username for the source image registry.")
        )
        parser.add_argument(
            "--source-password",
            dest="source_password",
            metavar='<source_password>',
            help=_("Password for the source image registry.")
        )

        parser.add_argument(
            "--dry-run",
            dest="dry_run",
            action="store_true",
            help=_("Perform a dry run upload. The upload action is not "
                   "performed, but the authentication process is attempted.")
        )
        parser.add_argument(
            "--multi-arch",
            dest="multi_arch",
            action="store_true",
            help=_("Enable multi arch support for the upload.")
        )
        parser.add_argument(
            "--cleanup",
            dest="cleanup",
            action="store_true",
            default=False,
            help=_("Remove local copy of the image after uploading")
        )
        parser.add_argument(
            dest="image_to_push",
            metavar='<image to push>',
            help=_("Container image to upload. Should be in the form of "
                   "<registry>/<namespace>/<name>:<tag>. If tag is "
                   "not provided, then latest will be used.")
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        lock = processlock.ProcessLock()
        manager = image_uploader.ImageUploadManager(lock=lock)
        uploader = manager.uploader('python')

        source_image = parsed_args.image_to_push

        if parsed_args.local or source_image.startswith('containers-storage:'):
            storage = 'containers-storage:'
            if not source_image.startswith(storage):
                source_image = storage + source_image.replace('docker://', '')
            elif not parsed_args.local:
                self.log.warning('Assuming local container based on provided '
                                 'container path. (e.g. starts with '
                                 'containers-storage:)')
            source_url = parse.urlparse(source_image)
            image_name = source_url.geturl()
            image_source = None
            if parsed_args.source_username or parsed_args.source_password:
                self.log.warning('Source credentials ignored for local images')
        else:
            storage = 'docker://'
            if not source_image.startswith(storage):
                source_image = storage + source_image
            source_url = parse.urlparse(source_image)
            image_source = source_url.netloc
            image_name = source_url.path[1:]
            if len(image_name.split('/')) != 2:
                raise exceptions.DownloadError('Invalid container. Provided '
                                               'container image should be '
                                               '<registry>/<namespace>/<name>:'
                                               '<tag>')
            if parsed_args.source_username or parsed_args.source_password:
                if not parsed_args.source_username:
                    self.log.warning('Skipping authentication - missing source'
                                     ' username')
                elif not parsed_args.source_password:
                    self.log.warning('Skipping authentication - missing source'
                                     ' password')
                else:
                    uploader.authenticate(source_url,
                                          parsed_args.source_username,
                                          parsed_args.source_password)

        registry_url_arg = parsed_args.registry_url
        if registry_url_arg is None:
            registry_url_arg = image_uploader.get_undercloud_registry()
        if not registry_url_arg.startswith('docker://'):
            registry_url = 'docker://%s' % registry_url_arg
        else:
            registry_url = registry_url_arg
        reg_url = parse.urlparse(registry_url)

        session = uploader.authenticate(reg_url,
                                        parsed_args.username,
                                        parsed_args.password)
        try:
            if not parsed_args.dry_run:
                task = image_uploader.UploadTask(
                    image_name=image_name,
                    pull_source=image_source,
                    push_destination=registry_url_arg,
                    append_tag=parsed_args.append_tag,
                    modify_role=None,
                    modify_vars=None,
                    cleanup=parsed_args.cleanup,
                    multi_arch=parsed_args.multi_arch)

                uploader.add_upload_task(task)
                uploader.run_tasks()
        except OSError as e:
            if e.errno == errno.EACCES:
                self.log.error("Unable to upload due to permissions. "
                               "Please prefix command with sudo.")
            raise oscexc.CommandError(e)
        finally:
            session.close()


class TripleOContainerImageDelete(command.Command):
    """Delete specified image from registry."""

    auth_required = False
    log = logging.getLogger(__name__ + ".TripleoContainerImageDelete")

    def get_parser(self, prog_name):
        parser = super(TripleOContainerImageDelete, self).get_parser(prog_name)
        parser.add_argument(
            "--registry-url",
            dest="registry_url",
            metavar='<registry url>',
            default=None,
            help=_("URL of registry images are to be listed from in the "
                   "form <fqdn>:<port>.")
        )
        parser.add_argument(
            dest="image_to_delete",
            metavar='<image to delete>',
            help=_("Full URL of image to be deleted in the "
                   "form <fqdn>:<port>/path/to/image")
        )
        parser.add_argument(
            "--username",
            dest="username",
            metavar='<username>',
            help=_("Username for image registry.")
        )
        parser.add_argument(
            "--password",
            dest="password",
            metavar='<password>',
            help=_("Password for image registry.")
        )
        parser.add_argument(
            '-y', '--yes',
            help=_('Skip yes/no prompt (assume yes).'),
            default=False,
            action="store_true")
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if not parsed_args.yes:
            confirm = utils.prompt_user_for_confirmation(
                    message=_("Are you sure you want to delete this image "
                              "[y/N]? "),
                    logger=self.log)
            if not confirm:
                raise oscexc.CommandError("Action not confirmed, exiting.")

        lock = processlock.ProcessLock()
        manager = image_uploader.ImageUploadManager(lock=lock)
        uploader = manager.uploader('python')
        registry_url_arg = parsed_args.registry_url
        if registry_url_arg is None:
            registry_url_arg = image_uploader.get_undercloud_registry()
        url = uploader._image_to_url(registry_url_arg)
        session = uploader.authenticate(url, parsed_args.username,
                                        parsed_args.password)

        try:
            uploader.delete(parsed_args.image_to_delete, session=session)
        except OSError as e:
            if e.errno == errno.EACCES:
                self.log.error("Unable to remove due to permissions. "
                               "Please prefix command with sudo.")
            raise oscexc.CommandError(e)
        finally:
            session.close()


class TripleOContainerImageList(command.Lister):
    """List images discovered in registry."""

    auth_required = False
    log = logging.getLogger(__name__ + ".TripleoContainerImageList")

    def get_parser(self, prog_name):
        parser = super(TripleOContainerImageList, self).get_parser(prog_name)
        parser.add_argument(
            "--registry-url",
            dest="registry_url",
            metavar='<registry url>',
            default=None,
            help=_("URL of registry images are to be listed from in the "
                   "form <fqdn>:<port>.")
        )
        parser.add_argument(
            "--username",
            dest="username",
            metavar='<username>',
            help=_("Username for image registry.")
        )
        parser.add_argument(
            "--password",
            dest="password",
            metavar='<password>',
            help=_("Password for image registry.")
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        lock = processlock.ProcessLock()
        manager = image_uploader.ImageUploadManager(lock=lock)
        uploader = manager.uploader('python')
        registry_url_arg = parsed_args.registry_url
        if registry_url_arg is None:
            registry_url_arg = image_uploader.get_undercloud_registry()
        url = uploader._image_to_url(registry_url_arg)
        session = uploader.authenticate(url, parsed_args.username,
                                        parsed_args.password)
        try:
            results = uploader.list(url.geturl(), session=session)
        finally:
            session.close()

        cliff_results = []
        for r in results:
            cliff_results.append((r,))
        return (("Image Name",), cliff_results)


class TripleOContainerImageShow(command.ShowOne):
    """Show image selected from the registry."""

    auth_required = False
    log = logging.getLogger(__name__ + ".TripleoContainerImageShow")

    @property
    def formatter_default(self):
        return 'json'

    def get_parser(self, prog_name):
        parser = super(TripleOContainerImageShow, self).get_parser(prog_name)
        parser.add_argument(
            "--username",
            dest="username",
            metavar='<username>',
            help=_("Username for image registry.")
        )
        parser.add_argument(
            "--password",
            dest="password",
            metavar='<password>',
            help=_("Password for image registry.")
        )
        parser.add_argument(
            dest="image_to_inspect",
            metavar='<image to inspect>',
            help=_(
                "Image to be inspected, for example: "
                "docker.io/library/centos:7 or "
                "docker://docker.io/library/centos:7")
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        lock = processlock.ProcessLock()
        manager = image_uploader.ImageUploadManager(lock=lock)
        uploader = manager.uploader('python')
        url = uploader._image_to_url(parsed_args.image_to_inspect)
        session = uploader.authenticate(url, parsed_args.username,
                                        parsed_args.password)
        try:
            image_inspect_result = uploader.inspect(
                parsed_args.image_to_inspect,
                session=session)
        finally:
            session.close()

        return self.format_image_inspect(image_inspect_result)

    def format_image_inspect(self, image_inspect_result):
        column_names = ['Name']
        data = [image_inspect_result.pop('Name')]

        result_fields = list(image_inspect_result.keys())
        result_fields.sort()
        for field in result_fields:
            column_names.append(field)
            data.append(image_inspect_result[field])

        return column_names, data


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
        parser.add_argument(
            '--enable-registry-login',
            dest='registry_login',
            action='store_true',
            default=False,
            help=_('Use this flag to enable the flag to have systems attempt '
                   'to login to a remote registry prior to pulling their '
                   'containers. This flag should be used when '
                   '--local-push-destination is *NOT* used and the target '
                   'systems will have network connectivity to the remote '
                   'registries. Do not use this for an overcloud that '
                   'may not have network connectivity to a remote registry.')
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
        if parsed_args.registry_login:
            if parsed_args.push_destination:
                self.log.warning('[WARNING] --local-push-destination was used '
                                 'with --enable-registry-login. Please make '
                                 'sure you understand the use of these '
                                 'parameters together as they can cause '
                                 'deployment failures.')
            self.log.warning('[NOTE] Make sure to update the paramter_defaults'
                             ' with ContainerImageRegistryCredentials for the '
                             'registries requiring authentication.')
            params['ContainerImageRegistryLogin'] = True

        env_data = build_env_file(params, self.app.command_options)
        self.app.stdout.write(env_data)
        if parsed_args.output_env_file:
            if os.path.exists(parsed_args.output_env_file):
                self.log.warning("Output env file exists, "
                                 "moving it to backup.")
                shutil.move(parsed_args.output_env_file,
                            parsed_args.output_env_file + ".backup")
            utils.safe_write(parsed_args.output_env_file, env_data)


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

        lock = processlock.ProcessLock()
        params = kolla_builder.container_images_prepare_multi(
            env, roles_data, dry_run=parsed_args.dry_run,
            cleanup=parsed_args.cleanup, lock=lock)
        env_data = build_env_file(params, self.app.command_options)
        if parsed_args.output_env_file:
            if os.path.exists(parsed_args.output_env_file):
                self.log.warning("Output env file exists, "
                                 "moving it to backup.")
                shutil.move(parsed_args.output_env_file,
                            parsed_args.output_env_file + ".backup")
            utils.safe_write(parsed_args.output_env_file, env_data)
        else:
            self.app.stdout.write(env_data)
