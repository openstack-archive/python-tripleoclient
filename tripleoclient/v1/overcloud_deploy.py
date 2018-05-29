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

import argparse
import json
import logging
import os
import os.path
from prettytable import PrettyTable
import re
import shutil
import six
import tempfile
import yaml

from heatclient.common import template_utils
from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from swiftclient.exceptions import ClientException
from tripleo_common import update

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils
from tripleoclient.workflows import deployment
from tripleoclient.workflows import parameters as workflow_params
from tripleoclient.workflows import plan_management


class DeployOvercloud(command.Command):
    """Deploy Overcloud"""

    log = logging.getLogger(__name__ + ".DeployOvercloud")
    predeploy_errors = 0
    predeploy_warnings = 0
    _password_cache = None

    # This may be switched on by default in the future, but for now
    # we'll want this behavior only in `overcloud update stack` and
    # `overcloud upgrade stack`, as enabling it here by default might
    # mean e.g. it might mean never deleting files under user-files/
    # directory in the plan.
    _keep_env_on_update = False

    def _setup_clients(self, parsed_args):
        self.clients = self.app.client_manager
        self.object_client = self.clients.tripleoclient.object_store
        self.workflow_client = self.clients.workflow_engine
        self.orchestration_client = self.clients.orchestration
        if not parsed_args.deployed_server:
            self.compute_client = self.clients.compute
            self.baremetal_client = self.clients.baremetal

    def _update_parameters(self, args, stack):
        parameters = {}

        stack_is_new = stack is None

        # *Identifier will be update to timestamp value during the deploy
        # workflow, but till then for all heat stack validations, we need
        # and entry for starting the deploy action.
        parameters['DeployIdentifier'] = ''
        parameters['UpdateIdentifier'] = ''
        parameters['StackAction'] = 'CREATE' if stack_is_new else 'UPDATE'

        # Update parameters from answers file:
        if args.answers_file is not None:
            with open(args.answers_file, 'r') as answers_file:
                answers = yaml.safe_load(answers_file)

            if args.templates is None:
                args.templates = answers['templates']
            if 'environments' in answers:
                if args.environment_files is not None:
                    answers['environments'].extend(args.environment_files)
                args.environment_files = answers['environments']

        param_args = (
            ('NtpServer', 'ntp_server'),
            ('ControllerCount', 'control_scale'),
            ('ComputeCount', 'compute_scale'),
            ('ObjectStorageCount', 'swift_storage_scale'),
            ('BlockStorageCount', 'block_storage_scale'),
            ('CephStorageCount', 'ceph_storage_scale'),
            ('OvercloudControlFlavor', 'control_flavor'),
            ('OvercloudControllerFlavor', 'control_flavor'),
            ('OvercloudComputeFlavor', 'compute_flavor'),
            ('OvercloudBlockStorageFlavor', 'block_storage_flavor'),
            ('OvercloudObjectStorageFlavor', 'swift_storage_flavor'),
            ('OvercloudSwiftStorageFlavor', 'swift_storage_flavor'),
            ('OvercloudCephStorageFlavor', 'ceph_storage_flavor'),
        )

        if stack_is_new:
            new_stack_args = (
                ('NovaComputeLibvirtType', 'libvirt_type'),
            )
            param_args = param_args + new_stack_args

        # Update parameters from commandline
        for param, arg in param_args:
            if getattr(args, arg, None) is not None:
                parameters[param] = getattr(args, arg)

        return parameters

    def _create_breakpoint_cleanup_env(self, tht_root, container_name):
        bp_env = {}
        update.add_breakpoints_cleanup_into_env(bp_env)
        env_path, swift_path = self._write_user_environment(
            bp_env,
            'tripleoclient-breakpoint-cleanup.yaml',
            tht_root,
            container_name)
        return bp_env

    def _create_registration_env(self, args, tht_root):
        user_tht_root = args.templates
        registry = os.path.join(
            user_tht_root,
            constants.RHEL_REGISTRATION_EXTRACONFIG_NAME,
            'rhel-registration-resource-registry.yaml')
        user_env = {'rhel_reg_method': args.reg_method,
                    'rhel_reg_org': args.reg_org,
                    'rhel_reg_force': args.reg_force,
                    'rhel_reg_sat_url': args.reg_sat_url,
                    'rhel_reg_activation_key': args.reg_activation_key}
        parameter_defaults = {"parameter_defaults": user_env}
        env_path, swift_path = self._write_user_environment(
            parameter_defaults,
            'tripleoclient-registration-parameters.yaml',
            tht_root,
            args.stack)
        return [registry], {"parameter_defaults": user_env}

    def _create_parameters_env(self, parameters, tht_root, container_name):
        parameter_defaults = {"parameter_defaults": parameters}
        env_path, swift_path = self._write_user_environment(
            parameter_defaults,
            'tripleoclient-parameters.yaml',
            tht_root,
            container_name)
        return parameter_defaults

    def _write_user_environment(self, env_map, abs_env_path, tht_root,
                                container_name):
        # We write the env_map to the local /tmp tht_root and also
        # to the swift plan container.
        contents = yaml.safe_dump(env_map, default_flow_style=False)
        env_dirname = os.path.dirname(abs_env_path)
        user_env_dir = os.path.join(
            tht_root, 'user-environments', env_dirname[1:])
        user_env_path = os.path.join(
            user_env_dir, os.path.basename(abs_env_path))
        self.log.debug("user_env_path=%s" % user_env_path)
        if not os.path.exists(user_env_dir):
            os.makedirs(user_env_dir)
        with open(user_env_path, 'w') as f:
            self.log.debug("Writing user environment %s" % user_env_path)
            f.write(contents)

        # Upload to swift
        if abs_env_path.startswith("/"):
            swift_path = "user-environments/{}".format(abs_env_path[1:])
        else:
            swift_path = "user-environments/{}".format(abs_env_path)
        contents = yaml.safe_dump(env_map, default_flow_style=False)
        self.log.debug("Uploading %s to swift at %s"
                       % (abs_env_path, swift_path))
        self.object_client.put_object(container_name, swift_path, contents)

        return user_env_path, swift_path

    def _heat_deploy(self, stack, stack_name, template_path, parameters,
                     env_files, timeout, tht_root, env, update_plan_only,
                     run_validations, skip_deploy_identifier, plan_env_file):
        """Verify the Baremetal nodes are available and do a stack update"""

        self.log.debug("Getting template contents from plan %s" % stack_name)
        # We need to reference the plan here, not the local
        # tht root, as we need template_object to refer to
        # the rendered overcloud.yaml, not the tht_root overcloud.j2.yaml
        # FIXME(shardy) we need to move more of this into mistral actions
        plan_yaml_path = os.path.relpath(template_path, tht_root)

        # heatclient template_utils needs a function that can
        # retrieve objects from a container by name/path
        def do_object_request(method='GET', object_path=None):
            obj = self.object_client.get_object(stack_name, object_path)
            return obj and obj[1]

        template_files, template = template_utils.get_template_contents(
            template_object=plan_yaml_path,
            object_request=do_object_request)

        files = dict(list(template_files.items()) + list(env_files.items()))

        moved_files = self._upload_missing_files(
            stack_name, files, tht_root)
        self._process_and_upload_environment(
            stack_name, env, moved_files, tht_root)

        # Invokes the workflows specified in plan environment file
        if plan_env_file:
            workflow_params.invoke_plan_env_workflows(self.clients,
                                                      stack_name,
                                                      plan_env_file)

        workflow_params.check_deprecated_parameters(self.clients, stack_name)

        if not update_plan_only:
            print("Deploying templates in the directory {0}".format(
                os.path.abspath(tht_root)))
            deployment.deploy_and_wait(
                self.log, self.clients, stack,
                stack_name, self.app_args.verbose_level,
                timeout=timeout,
                run_validations=run_validations,
                skip_deploy_identifier=skip_deploy_identifier)

    def _process_and_upload_environment(self, container_name,
                                        env, moved_files, tht_root):
        """Process the environment and upload to Swift

        The environment at this point should be the result of the merged
        custom user environments. We need to look at the paths in the
        environment and update any that changed when they were uploaded to
        swift.
        """

        file_prefix = "file://"

        if env.get('resource_registry'):
            for name, path in env['resource_registry'].items():
                if not isinstance(path, six.string_types):
                    continue
                if path in moved_files:
                    new_path = moved_files[path]
                    env['resource_registry'][name] = new_path
                elif path.startswith(file_prefix):
                    path = path[len(file_prefix):]
                    if path.startswith(tht_root):
                        path = path[len(tht_root):]
                    # We want to make sure all the paths are relative.
                    if path.startswith("/"):
                        path = path[1:]
                    env['resource_registry'][name] = path

        # Parameters are removed from the environment
        params = env.pop('parameter_defaults', None)

        contents = yaml.safe_dump(env, default_flow_style=False)

        # Until we have a well defined plan update workflow in tripleo-common
        # we need to manually add an environment in swift and for users
        # custom environments passed to the deploy command.
        # See bug: https://bugs.launchpad.net/tripleo/+bug/1623431
        # Update plan env.
        swift_path = "user-environment.yaml"
        self.object_client.put_object(container_name, swift_path, contents)

        env = yaml.safe_load(self.object_client.get_object(
            container_name, constants.PLAN_ENVIRONMENT)[1])

        user_env = {'path': swift_path}
        if user_env not in env['environments']:
            env['environments'].append(user_env)
            yaml_string = yaml.safe_dump(env, default_flow_style=False)
            self.object_client.put_object(
                container_name, constants.PLAN_ENVIRONMENT, yaml_string)

        # Parameters are sent to the update parameters action, this stores them
        # in the plan environment and means the UI can find them.
        if params:
            workflow_params.update_parameters(
                self.workflow_client, container=container_name,
                parameters=params)

    def _upload_missing_files(self, container_name, files_dict, tht_root):
        """Find the files referenced in custom environments and upload them

        Heat environments can be passed to be included in the deployment, these
        files can include references to other files anywhere on the local
        file system. These need to be discovered and uploaded to Swift. When
        they have been uploaded to Swift the path to them will be different,
        the new paths are store din the file_relocation dict, which is returned
        and used by _process_and_upload_environment which will merge the
        environment and update paths to the relative Swift path.
        """

        file_relocation = {}
        file_prefix = "file://"

        # select files files for relocation & upload
        for fullpath in files_dict.keys():

            if not fullpath.startswith(file_prefix):
                continue

            path = fullpath[len(file_prefix):]

            if path.startswith(tht_root):
                # This should already be uploaded.
                continue

            file_relocation[fullpath] = "user-files/{}".format(
                os.path.normpath(path[1:]))

        # make sure links within files point to new locations, and upload them
        for orig_path, reloc_path in file_relocation.items():
            link_replacement = utils.relative_link_replacement(
                file_relocation, os.path.dirname(reloc_path))
            contents = utils.replace_links_in_template_contents(
                files_dict[orig_path], link_replacement)
            self.object_client.put_object(container_name, reloc_path, contents)

        return file_relocation

    def _download_missing_files_from_plan(self, tht_dir, plan_name):
        # get and download missing files into tmp directory
        plan_list = self.object_client.get_container(plan_name)
        plan_filenames = [f['name'] for f in plan_list[1]]
        for pf in plan_filenames:
            file_path = os.path.join(tht_dir, pf)
            if not os.path.isfile(file_path):
                self.log.debug("Missing in templates directory, downloading \
                               %s from swift into %s" % (pf, file_path))
                if not os.path.exists(os.path.dirname(file_path)):
                    os.makedirs(os.path.dirname(file_path))
                with open(file_path, 'w') as f:
                    f.write(self.object_client.get_object(plan_name, pf)[1])

    def _deploy_tripleo_heat_templates_tmpdir(self, stack, parsed_args):
        # copy tht_root to temporary directory because we need to
        # download any missing (e.g j2 rendered) files from the plan
        tht_root = os.path.abspath(parsed_args.templates)
        tht_tmp = tempfile.mkdtemp(prefix='tripleoclient-')
        new_tht_root = "%s/tripleo-heat-templates" % tht_tmp
        self.log.debug("Creating temporary templates tree in %s"
                       % new_tht_root)
        try:
            shutil.copytree(tht_root, new_tht_root, symlinks=True)
            self._deploy_tripleo_heat_templates(stack, parsed_args,
                                                new_tht_root, tht_root)
        finally:
            if parsed_args.no_cleanup:
                self.log.warning("Not cleaning temporary directory %s"
                                 % tht_tmp)
            else:
                shutil.rmtree(tht_tmp)

    def _deploy_tripleo_heat_templates(self, stack, parsed_args,
                                       tht_root, user_tht_root):
        """Deploy the fixed templates in TripleO Heat Templates"""

        plans = plan_management.list_deployment_plans(self.clients)
        generate_passwords = not parsed_args.disable_password_generation

        # TODO(d0ugal): We need to put a more robust strategy in place here to
        #               handle updating plans.
        if parsed_args.stack in plans:
            # Upload the new plan templates to swift to replace the existing
            # templates.
            plan_management.update_plan_from_templates(
                self.clients, parsed_args.stack, tht_root,
                parsed_args.roles_file, generate_passwords,
                parsed_args.plan_environment_file,
                parsed_args.networks_file,
                type(self)._keep_env_on_update)
        else:
            plan_management.create_plan_from_templates(
                self.clients, parsed_args.stack, tht_root,
                parsed_args.roles_file, generate_passwords,
                parsed_args.plan_environment_file,
                parsed_args.networks_file)

        # Get any missing (e.g j2 rendered) files from the plan to tht_root
        self._download_missing_files_from_plan(
            tht_root, parsed_args.stack)

        print("Processing templates in the directory {0}".format(
            os.path.abspath(tht_root)))

        self.log.debug("Creating Environment files")
        env = {}
        created_env_files = []

        if parsed_args.environment_directories:
            created_env_files.extend(utils.load_environment_directories(
                parsed_args.environment_directories))
        parameters = {}
        if stack:
            try:
                # If user environment already exist then keep it
                user_env = yaml.safe_load(self.object_client.get_object(
                    parsed_args.stack, constants.USER_ENVIRONMENT)[1])
                template_utils.deep_update(env, user_env)
            except ClientException:
                pass
        parameters.update(self._update_parameters(parsed_args, stack))
        template_utils.deep_update(env, self._create_parameters_env(
            parameters, tht_root, parsed_args.stack))

        if parsed_args.rhel_reg:
            reg_env_files, reg_env = self._create_registration_env(
                parsed_args, tht_root)
            created_env_files.extend(reg_env_files)
            template_utils.deep_update(env, reg_env)
        if parsed_args.environment_files:
            created_env_files.extend(parsed_args.environment_files)

        self.log.debug("Processing environment files %s" % created_env_files)
        env_files, localenv = utils.process_multiple_environments(
            created_env_files, tht_root, user_tht_root,
            cleanup=not parsed_args.no_cleanup)
        template_utils.deep_update(env, localenv)

        if stack:
            bp_cleanup = self._create_breakpoint_cleanup_env(
                tht_root, parsed_args.stack)
            template_utils.deep_update(env, bp_cleanup)

        # FIXME(shardy) It'd be better to validate this via mistral
        # e.g part of the plan create/update workflow
        number_controllers = int(parameters.get('ControllerCount', 0))
        if number_controllers > 1:
            if not env.get('parameter_defaults').get('NtpServer'):
                raise exceptions.InvalidConfiguration(
                    'Specify --ntp-server as parameter or NtpServer in '
                    'environments when using multiple controllers '
                    '(with HA).')

        self._try_overcloud_deploy_with_compat_yaml(
            tht_root, stack, parsed_args.stack, parameters, env_files,
            parsed_args.timeout, env, parsed_args.update_plan_only,
            parsed_args.run_validations, parsed_args.skip_deploy_identifier,
            parsed_args.plan_environment_file)

    def _try_overcloud_deploy_with_compat_yaml(self, tht_root, stack,
                                               stack_name, parameters,
                                               env_files, timeout,
                                               env, update_plan_only,
                                               run_validations,
                                               skip_deploy_identifier,
                                               plan_env_file):
        overcloud_yaml = os.path.join(tht_root, constants.OVERCLOUD_YAML_NAME)
        try:
            self._heat_deploy(stack, stack_name, overcloud_yaml,
                              parameters, env_files, timeout,
                              tht_root, env, update_plan_only,
                              run_validations, skip_deploy_identifier,
                              plan_env_file)
        except ClientException as e:
            messages = 'Failed to deploy: %s' % str(e)
            raise ValueError(messages)

    def _format_endpoint_name(self, service, interface):
        return re.sub('v[0-9]+', '',
                      service.capitalize() + interface.capitalize())

    def _deploy_postconfig(self, stack, parsed_args):
        self.log.debug("_deploy_postconfig(%s)" % parsed_args)

        overcloud_endpoint = utils.get_overcloud_endpoint(stack)
        # NOTE(jaosorior): The overcloud endpoint can contain an IP address or
        # an FQDN depending on how what it's configured to output in the
        # tripleo-heat-templates. Such a configuration can be done by
        # overriding the EndpointMap through parameter_defaults.
        overcloud_ip_or_fqdn = six.moves.urllib.parse.urlparse(
            overcloud_endpoint).hostname

        keystone_admin_ip = utils.get_endpoint('KeystoneAdmin', stack)
        no_proxy = os.environ.get('no_proxy', overcloud_ip_or_fqdn)
        no_proxy_list = map(utils.bracket_ipv6,
                            [no_proxy, overcloud_ip_or_fqdn,
                             keystone_admin_ip])
        os.environ['no_proxy'] = ','.join(
            [x for x in no_proxy_list if x is not None])

        utils.remove_known_hosts(overcloud_ip_or_fqdn)

    def _validate_args(self, parsed_args):
        if parsed_args.templates is None and parsed_args.answers_file is None:
            raise oscexc.CommandError(
                "You must specify either --templates or --answers-file")

        if parsed_args.environment_files:
            nonexisting_envs = []
            jinja2_envs = []
            for env_file in parsed_args.environment_files:

                if env_file.endswith(".j2.yaml"):
                    jinja2_envs.append(env_file)
                elif not os.path.isfile(env_file):
                    # Tolerate missing file if there's a j2.yaml file that will
                    # be rendered in the plan but not available locally (yet)
                    if not os.path.isfile(env_file.replace(".yaml",
                                                           ".j2.yaml")):
                        nonexisting_envs.append(env_file)
            if jinja2_envs:
                rewritten_paths = [e.replace(".j2.yaml", ".yaml")
                                   for e in jinja2_envs]
                raise oscexc.CommandError(
                    "Error: The following jinja2 files were provided: -e "
                    "{}. Did you mean -e {}?".format(
                        ' -e '.join(jinja2_envs),
                        ' -e '.join(rewritten_paths)))
            if nonexisting_envs:
                raise oscexc.CommandError(
                    "Error: The following files were not found: {0}".format(
                        ", ".join(nonexisting_envs)))

        if parsed_args.deployed_server and (parsed_args.run_validations
           or not parsed_args.disable_validations):
                raise oscexc.CommandError(
                    "Error: The --deployed-server cannot be used without "
                    "the --disable-validations")

        if parsed_args.environment_directories:
            self._validate_args_environment_directory(
                parsed_args.environment_directories)

    def _validate_args_environment_directory(self, directories):
        default = os.path.expanduser(constants.DEFAULT_ENV_DIRECTORY)
        nonexisting_dirs = []

        for d in directories:
            if not os.path.isdir(d) and d != default:
                nonexisting_dirs.append(d)

        if nonexisting_dirs:
            raise oscexc.CommandError(
                "Error: The following environment directories were not found"
                ": {0}".format(", ".join(nonexisting_dirs)))

    def _get_default_role_counts(self, parsed_args):

        if parsed_args.roles_file:
            roles_data = utils.fetch_roles_file(parsed_args.roles_file,
                                                parsed_args.templates)
        else:
            # Assume default role counts
            return {
                'ControllerCount': 1,
                'ComputeCount': 1,
                'ObjectStorageCount': 0,
                'BlockStorageCount': 0,
                'CephStorageCount': 0
            }

        default_role_counts = {}
        for r in roles_data:
            count_default = r.get('CountDefault', 0)
            default_role_counts.setdefault(
                "%sCount" % r['name'],
                count_default)

        return default_role_counts

    def get_parser(self, prog_name):
        # add_help doesn't work properly, set it to False:
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False
        )
        parser.add_argument(
            '--templates', nargs='?', const=constants.TRIPLEO_HEAT_TEMPLATES,
            help=_("The directory containing the Heat templates to deploy"),
        )
        parser.add_argument('--stack',
                            help=_("Stack name to create or update"),
                            default='overcloud')
        parser.add_argument('--timeout', '-t', metavar='<TIMEOUT>',
                            type=int, default=240,
                            help=_('Deployment timeout in minutes.'))
        utils.add_deployment_plan_arguments(parser, mark_as_depr=True)
        parser.add_argument('--libvirt-type',
                            choices=['kvm', 'qemu'],
                            help=_('Libvirt domain type.'))
        parser.add_argument('--ntp-server',
                            help=_('The NTP for overcloud nodes. '))
        parser.add_argument(
            '--no-proxy',
            default=os.environ.get('no_proxy', ''),
            help=_('A comma separated list of hosts that should not be '
                   'proxied.')
        )
        parser.add_argument(
            '--overcloud-ssh-user',
            default='heat-admin',
            help=_('User for ssh access to overcloud nodes')
        )
        parser.add_argument(
            '--overcloud-ssh-key',
            default=os.path.join(
                os.path.expanduser('~'), '.ssh', 'id_rsa'),
            help=_('Key path for ssh access to overcloud nodes.')
        )
        parser.add_argument(
            '--overcloud-ssh-network',
            help=_('Network name to use for ssh access to overcloud nodes.'),
            default='ctlplane'
        )
        parser.add_argument(
            '--environment-file', '-e', metavar='<HEAT ENVIRONMENT FILE>',
            action='append', dest='environment_files',
            help=_('Environment files to be passed to the heat stack-create '
                   'or heat stack-update command. (Can be specified more than '
                   'once.)')
        )
        parser.add_argument(
            '--environment-directory', metavar='<HEAT ENVIRONMENT DIRECTORY>',
            action='append', dest='environment_directories',
            default=[os.path.expanduser(constants.DEFAULT_ENV_DIRECTORY)],
            help=_('Environment file directories that are automatically '
                   ' added to the heat stack-create or heat stack-update'
                   ' commands. Can be specified more than once. Files in'
                   ' directories are loaded in ascending sort order.')
        )
        parser.add_argument(
            '--roles-file', '-r', dest='roles_file',
            help=_('Roles file, overrides the default %s in the --templates '
                   'directory. May be an absolute path or the path relative '
                   ' to --templates') % constants.OVERCLOUD_ROLES_FILE
        )
        parser.add_argument(
            '--networks-file', '-n', dest='networks_file',
            help=_('Networks file, overrides the default %s in the '
                   '--templates directory') % constants.OVERCLOUD_NETWORKS_FILE
        )
        parser.add_argument(
            '--plan-environment-file', '-p',
            help=_('Plan Environment file, overrides the default %s in the '
                   '--templates directory') % constants.PLAN_ENVIRONMENT
        )
        parser.add_argument(
            '--no-cleanup', action='store_true',
            help=_('Don\'t cleanup temporary files, just log their location')
        )
        parser.add_argument(
            '--update-plan-only',
            action='store_true',
            help=_('Only update the plan. Do not perform the actual '
                   'deployment. NOTE: Will move to a discrete command  in a '
                   'future release.')
        )
        parser.add_argument(
            '--validation-errors-nonfatal',
            dest='validation_errors_fatal',
            action='store_false',
            default=True,
            help=_('Allow the deployment to continue in spite of validation '
                   'errors. Note that attempting deployment while errors '
                   'exist is likely to fail.')
        )
        parser.add_argument(
            '--validation-warnings-fatal',
            action='store_true',
            default=False,
            help=_('Exit if there are warnings from the configuration '
                   'pre-checks.')
        )
        parser.add_argument(
            '--disable-validations',
            action='store_true',
            default=False,
            help=_('DEPRECATED. Disable the pre-deployment validations '
                   'entirely. These validations are the built-in '
                   'pre-deployment validations. To enable external '
                   'validations from tripleo-validations, '
                   'use the --run-validations flag. These validations are '
                   'now run via the external validations in '
                   'tripleo-validations.'))
        parser.add_argument(
            '--dry-run',
            action='store_true',
            default=False,
            help=_('Only run validations, but do not apply any changes.')
        )
        parser.add_argument(
            '--run-validations',
            action='store_true',
            default=False,
            help=_('Run external validations from the tripleo-validations '
                   'project.'))
        parser.add_argument(
            '--skip-postconfig',
            action='store_true',
            default=False,
            help=_('Skip the overcloud post-deployment configuration.')
        )
        parser.add_argument(
            '--force-postconfig',
            action='store_true',
            default=False,
            help=_('Force the overcloud post-deployment configuration.')
        )
        parser.add_argument(
            '--skip-deploy-identifier',
            action='store_true',
            default=False,
            help=_('Skip generation of a unique identifier for the '
                   'DeployIdentifier parameter. The software configuration '
                   'deployment steps will only be triggered if there is an '
                   'actual change to the configuration. This option should '
                   'be used with Caution, and only if there is confidence '
                   'that the software configuration does not need to be '
                   'run, such as when scaling out certain roles.')
        )
        reg_group = parser.add_argument_group('Registration Parameters')
        reg_group.add_argument(
            '--rhel-reg',
            action='store_true',
            help=_('Register overcloud nodes to the customer portal or a '
                   'satellite.')
        )
        reg_group.add_argument(
            '--reg-method',
            choices=['satellite', 'portal'],
            default='satellite',
            help=_('RHEL registration method to use for the overcloud nodes.')
        )
        reg_group.add_argument(
            '--reg-org',
            default='',
            help=_('Organization key to use for registration.')
        )
        reg_group.add_argument(
            '--reg-force',
            action='store_true',
            help=_('Register the system even if it is already registered.')
        )
        reg_group.add_argument(
            '--reg-sat-url',
            default='',
            help=_('Satellite server to register overcloud nodes.')
        )
        reg_group.add_argument(
            '--reg-activation-key',
            default='',
            help=_('Activation key to use for registration.')
        )
        parser.add_argument(
            '--answers-file',
            help=_('Path to a YAML file with arguments and parameters.')
        )
        parser.add_argument(
            '--disable-password-generation',
            action='store_true',
            default=False,
            help=_('Disable password generation.')
        )
        parser.add_argument(
            '--deployed-server',
            action='store_true',
            default=False,
            help=_('Use pre-provisioned overcloud nodes. Removes baremetal,'
                   'compute and image services requirements from the'
                   'undercloud node. Must only be used with the'
                   '--disable-validations.')
        )
        parser.add_argument(
            '--config-download',
            action='store_true',
            default=True,
            help=_('Run deployment via config-download mechanism. This is '
                   'now the default, and this CLI options may be removed in '
                   'the future.')
        )
        parser.add_argument(
            '--no-config-download',
            '--stack-only',
            action='store_false',
            default=False,
            dest='config_download',
            help=_('Disable the config-download workflow and only create '
                   'the stack and associated OpenStack resources. No '
                   'software configuration will be applied.')
        )
        parser.add_argument(
            '--config-download-only',
            action='store_true',
            default=False,
            help=_('Disable the stack create/update, and only run the '
                   'config-download workflow to apply the software '
                   'configuration.')
        )
        parser.add_argument(
            '--output-dir',
            action='store',
            default=None,
            help=_('Directory to use for saved output when using '
                   '--config-download. The directory must be '
                   'writeable by the mistral user. When not '
                   'specified, the default server side value '
                   'will be used (/var/lib/mistral/<execution id>.')
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        self._setup_clients(parsed_args)

        # Swiftclient logs things like 404s at error level, which is a problem
        # because we use EAFP to check for the existence of files.  Turn off
        # most swiftclient logging to avoid cluttering up our output with
        # pointless tracebacks.
        sc_logger = logging.getLogger("swiftclient")
        sc_logger.setLevel(logging.CRITICAL)

        self._validate_args(parsed_args)

        stack = utils.get_stack(self.orchestration_client, parsed_args.stack)

        if stack and stack.stack_status == 'IN_PROGRESS':
            raise exceptions.StackInProgress(
                "Unable to deploy as the stack '{}' status is '{}'".format(
                    stack.stack_name, stack.stack_status))

        self._update_parameters(parsed_args, stack)

        stack_create = stack is None
        if stack_create:
            self.log.info("No stack found, will be doing a stack create")
        else:
            self.log.info("Stack found, will be doing a stack update")

        if parsed_args.rhel_reg:
            if parsed_args.reg_method == 'satellite':
                sat_required_args = (parsed_args.reg_org and
                                     parsed_args.reg_sat_url and
                                     parsed_args.reg_activation_key)
                if not sat_required_args:
                    raise exceptions.DeploymentError(
                        "ERROR: In order to use satellite registration, "
                        "you must specify --reg-org, --reg-sat-url, and "
                        "--reg-activation-key.")
            else:
                portal_required_args = (parsed_args.reg_org and
                                        parsed_args.reg_activation_key)
                if not portal_required_args:
                    raise exceptions.DeploymentError(
                        "ERROR: In order to use portal registration, you "
                        "must specify --reg-org, and "
                        "--reg-activation-key.")

        if parsed_args.dry_run:
            print("Validation Finished")
            return

        if not parsed_args.config_download_only:
            self._deploy_tripleo_heat_templates_tmpdir(stack, parsed_args)

        # Get a new copy of the stack after stack update/create. If it was
        # a create then the previous stack object would be None.
        stack = utils.get_stack(self.orchestration_client, parsed_args.stack)

        if parsed_args.update_plan_only:
            # If we are only updating the plan, then we either wont have a
            # stack yet or there wont be any changes and the following code
            # wont do anything.
            return

        if parsed_args.config_download:
            print("Deploying overcloud configuration")

            hosts = deployment.get_overcloud_hosts(
                stack, parsed_args.overcloud_ssh_network)
            deployment.enable_ssh_admin(self.log, self.clients,
                                        hosts,
                                        parsed_args.overcloud_ssh_user,
                                        parsed_args.overcloud_ssh_key)
            deployment.config_download(self.log, self.clients, stack,
                                       parsed_args.templates,
                                       parsed_args.overcloud_ssh_user,
                                       parsed_args.overcloud_ssh_key,
                                       parsed_args.overcloud_ssh_network,
                                       parsed_args.output_dir,
                                       verbosity=self.app_args.verbose_level)

        # Force fetching of attributes
        stack.get()

        overcloudrcs = deployment.create_overcloudrc(
            self.clients, container=stack.stack_name,
            no_proxy=parsed_args.no_proxy)

        rcpath = utils.write_overcloudrc(stack.stack_name, overcloudrcs)
        utils.create_tempest_deployer_input()

        # Run postconfig on create or force. Use force to makes sure endpoints
        # are created with deploy reruns and upgrades
        if (stack_create or parsed_args.force_postconfig
                and not parsed_args.skip_postconfig):
            self._deploy_postconfig(stack, parsed_args)

        overcloud_endpoint = utils.get_overcloud_endpoint(stack)

        horizon_url = deployment.get_horizon_url(
            self.clients, stack=stack.stack_name)

        print("Overcloud Endpoint: {0}".format(overcloud_endpoint))
        print("Overcloud Horizon Dashboard URL: {0}".format(horizon_url))
        print("Overcloud rc file: {0}".format(rcpath))
        print("Overcloud Deployed")


class GetDeploymentStatus(command.Command):
    """Get deployment status"""

    log = logging.getLogger(__name__ + ".GetDeploymentStatus")

    def get_parser(self, prog_name):
        parser = super(GetDeploymentStatus, self).get_parser(prog_name)
        parser.add_argument('--plan', '--stack',
                            help=_('Name of the stack/plan. '
                                   '(default: overcloud)'),
                            default='overcloud')
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        plan = parsed_args.plan

        status = deployment.get_deployment_status(
            self.app.client_manager,
            plan=plan
        )

        payload = status['workflow_status']['payload']
        execution = payload['execution']
        table = PrettyTable(
            ['Plan Name', 'Created', 'Updated', 'Deployment Status'])
        table.add_row([payload['plan_name'],
                       execution['created_at'],
                       execution['updated_at'],
                       payload['deployment_status']])
        print(table, file=self.app.stdout)


class GetDeploymentFailures(command.Command):
    """Get deployment failures"""

    log = logging.getLogger(__name__ + ".GetDeploymentFailures")

    def get_parser(self, prog_name):
        parser = super(GetDeploymentFailures, self).get_parser(prog_name)
        parser.add_argument('--plan', '--stack',
                            help=_('Name of the stack/plan. '
                                   '(default: overcloud)'),
                            default='overcloud')
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        plan = parsed_args.plan

        failures = deployment.get_deployment_failures(
            self.app.client_manager,
            plan=plan
        )

        out = self.app.stdout

        hosts = list(failures.keys())
        hosts.sort()

        for host in hosts:
            host_failures = failures[host]
            host_failures = sorted(host_failures, key=lambda k: k[0])
            out.write("|-> Failures for host: %s\n" % host)
            for task_name, task in host_failures:
                out.write('|--> Task: %s\n' % task_name)
                task_keys = sorted(task.keys())
                for task_key in task_keys:
                    task_value = task[task_key]
                    out.write('|---> %s: ' % task_key)
                    try:
                        value = json.dumps(task_value,
                                           sort_keys=True,
                                           separators=(',', ': '),
                                           indent=4)
                    except ValueError:
                        value = task_value
                    out.write('%s\n' % value)
            out.write('\n')
