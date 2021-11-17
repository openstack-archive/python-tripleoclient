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
from io import StringIO
import logging
import os
import shutil

from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from urllib import parse
import yaml

from tripleo_common.image import image_uploader
from tripleo_common.image import kolla_builder
from tripleo_common.utils.locks import processlock
from tripleoclient import utils as oooutils

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils


def build_env_file(params, command_options):

    f = StringIO()
    f.write('# Generated with the following on %s\n#\n' %
            datetime.datetime.now().isoformat())
    f.write('#   openstack %s\n#\n\n' %
            ' '.join(command_options))

    yaml.safe_dump({'parameter_defaults': params}, f,
                   default_flow_style=False)
    return f.getvalue()


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
        parser.add_argument(
            "--log-file",
            dest="log_file",
            default=constants.CONTAINER_IMAGE_PREPARE_LOG_FILE,
            help=_("Log file to be used for python logging. "
                   "By default it would be logged to "
                   "$HOME/container_image_prepare.log.")
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if parsed_args.cleanup not in image_uploader.CLEANUP:
            raise oscexc.CommandError('--cleanup must be one of: %s' %
                                      ', '.join(image_uploader.CLEANUP))

        role_file = None
        if parsed_args.roles_file:
            role_file = utils.rel_or_abs_path(parsed_args.roles_file,
                                              constants.TRIPLEO_HEAT_TEMPLATES)
        env_dirs = [os.path.abspath(x)
                    for x in parsed_args.environment_directories]
        env_files = [os.path.abspath(x)
                     for x in parsed_args.environment_files]
        extra_vars = {
            "roles_file": role_file,
            "environment_directories": env_dirs,
            "environment_files": env_files,
            "cleanup": parsed_args.cleanup,
            "dry_run": parsed_args.dry_run,
            "log_file": parsed_args.log_file}

        if self.app_args.verbose_level >= 3:
            extra_vars["debug"] = True

        if parsed_args.output_env_file:
            extra_vars["output_env_file"] = os.path.abspath(
                parsed_args.output_env_file)

        with oooutils.TempDirs() as tmp:
            oooutils.run_ansible_playbook(
                playbook='cli-container-image-prepare.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=oooutils.playbook_verbosity(self=self),
                extra_vars=extra_vars)
