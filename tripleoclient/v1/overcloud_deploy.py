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

import argparse
import os
import os.path
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from prettytable import PrettyTable
from pwd import getpwuid
import shutil
import time
import urllib
import yaml

from heatclient.common import template_utils
from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from tripleo_common.utils import plan as plan_utils

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import export
from tripleoclient import utils
from tripleoclient.workflows import deployment
from tripleoclient.workflows import parameters as workflow_params

CONF = cfg.CONF


def _validate_args_environment_dir(dirs):
    default = os.path.expanduser(constants.DEFAULT_ENV_DIRECTORY)
    not_found = [d for d in dirs if not os.path.isdir(d) and d != default]

    if not_found:
        raise oscexc.CommandError(
            "Error: The following environment directories were not found"
            ": {0}".format(", ".join(not_found)))


def _update_args_from_answers_file(parsed_args):
    if parsed_args.answers_file is None:
        return

    with open(parsed_args.answers_file, 'r') as answers_file:
        answers = yaml.safe_load(answers_file)

    if parsed_args.templates is None:
        parsed_args.templates = answers['templates']
    if 'environments' in answers:
        if parsed_args.environment_files is not None:
            answers['environments'].extend(parsed_args.environment_files)
        parsed_args.environment_files = answers['environments']
    if 'roles' in answers:
        if parsed_args.roles_file is None:
            parsed_args.roles_file = answers['roles']
    if 'networks' in answers:
        if parsed_args.networks_file is None:
            parsed_args.networks_file = answers['networks']


def _validate_args(parsed_args):
    if parsed_args.templates is None and parsed_args.answers_file is None:
        raise oscexc.CommandError(
            "You must specify either --templates or --answers-file")

    if not parsed_args.deployed_server:
        raise oscexc.CommandError(
            "Error: --provision-node is no longer supported")

    if (parsed_args.baremetal_deployment
            and (parsed_args.config_download_only or parsed_args.setup_only)):
        raise oscexc.CommandError(
            "Error: --config-download-only/--setup-only must not be used when "
            "using --baremetal-deployment")

    if (parsed_args.network_config and not parsed_args.baremetal_deployment):
        raise oscexc.CommandError(
            "Error: --baremetal-deployment must be used when using "
            "--network-config")

    if parsed_args.environment_directories:
        _validate_args_environment_dir(parsed_args.environment_directories)

    not_found = [x for x in [parsed_args.networks_file,
                             parsed_args.answers_file,
                             parsed_args.vip_file]
                 if x and not os.path.isfile(x)]

    jinja2_envs = []
    if parsed_args.environment_files:
        for env in parsed_args.environment_files:
            if env.endswith(".j2.yaml"):
                jinja2_envs.append(env)
                continue

            # Tolerate missing file if there's a j2.yaml file that will
            # be rendered in the plan but not available locally (yet)
            if (not os.path.isfile(env)
                    and not os.path.isfile(env.replace(".yaml", ".j2.yaml"))):
                not_found.append(env)

    if not_found:
        raise oscexc.CommandError(
            "Error: The following files were not found: {}".format(
                ", ".join(not_found)))

    if jinja2_envs:
        rewritten_paths = [e.replace(".j2.yaml", ".yaml") for e in jinja2_envs]
        raise oscexc.CommandError(
            "Error: The following jinja2 files were provided: {}. Did you "
            "mean {}?".format(' -e '.join(jinja2_envs),
                              ' -e '.join(rewritten_paths)))


def _validate_vip_file(stack, working_dir):
    # Check vip_file only used with network data v2
    networks_file_path = utils.get_networks_file_path(working_dir, stack)
    if not utils.is_network_data_v2(networks_file_path):
        raise oscexc.CommandError(
            'The --vip-file option can only be used in combination with a '
            'network data v2 format networks file. The provided file {} '
            'is network data v1 format'.format(networks_file_path))


class DeployOvercloud(command.Command):
    """Deploy Overcloud"""

    log = logging.getLogger(__name__ + ".DeployOvercloud")

    def _setup_clients(self, parsed_args):
        self.clients = self.app.client_manager
        self.orchestration_client = self.clients.orchestration

    def _update_parameters(self, args, parameters,
                           tht_root, user_tht_root):
        parameters['RootStackName'] = args.stack
        if not args.skip_deploy_identifier:
            parameters['DeployIdentifier'] = int(time.time())
        else:
            parameters['DeployIdentifier'] = ''

        # Check for existing passwords file
        password_params_path = os.path.join(
            self.working_dir,
            constants.PASSWORDS_ENV_FORMAT.format(args.stack))
        if os.path.exists(password_params_path):
            with open(password_params_path, 'r') as f:
                passwords_env = yaml.safe_load(f.read())
        else:
            passwords_env = None

        heat = None
        password_params = plan_utils.generate_passwords(
            None, heat, args.stack, passwords_env=passwords_env)

        # Save generated passwords file
        with open(password_params_path, 'w') as f:
            f.write(yaml.safe_dump(dict(parameter_defaults=password_params)))
        os.chmod(password_params_path, 0o600)

        parameters.update(password_params)

        param_args = (
            ('NtpServer', 'ntp_server'),
            ('NovaComputeLibvirtType', 'libvirt_type'),
        )

        # Update parameters from commandline
        for param, arg in param_args:
            if getattr(args, arg) is not None:
                parameters[param] = getattr(args, arg)

        parameters[
            'UndercloudHostsEntries'] = [utils.get_undercloud_host_entry()]

        parameters['CtlplaneNetworkAttributes'] = utils.get_ctlplane_attrs()

        return parameters

    def _check_limit_skiplist_warning(self, env):
        if env.get('parameter_defaults').get('DeploymentServerBlacklist'):
            msg = _('[WARNING] DeploymentServerBlacklist is defined and will '
                    'be ignored because --limit has been specified.')
            self.log.warning(msg)

    def _heat_deploy(self, stack_name, template_path,
                     env_files, timeout, tht_root, env,
                     run_validations,
                     roles_file,
                     env_files_tracker=None,
                     deployment_options=None):
        """Verify the Baremetal nodes are available and do a stack update"""

        self.log.debug("Getting template contents from plan %s" % stack_name)

        template_files, template = template_utils.get_template_contents(
            template_file=template_path)
        files = dict(list(template_files.items()) + list(env_files.items()))

        workflow_params.check_deprecated_parameters(
            self.clients,
            stack_name,
            template,
            files,
            env_files_tracker,
            self.working_dir)

        self.log.info("Deploying templates in the directory {0}".format(
            os.path.abspath(tht_root)))
        deployment.deploy_without_plan(
            self.clients, stack_name,
            template, files, env_files_tracker,
            self.log, self.working_dir)

    def create_template_dirs(self, parsed_args):
        tht_root = os.path.abspath(parsed_args.templates)
        new_tht_root = "%s/tripleo-heat-templates" % self.working_dir
        self.log.debug("Creating working templates tree in %s"
                       % new_tht_root)
        roles_file_path = utils.get_roles_file_path(self.working_dir,
                                                    parsed_args.stack)
        networks_file_path = utils.get_networks_file_path(self.working_dir,
                                                          parsed_args.stack)
        shutil.rmtree(new_tht_root, ignore_errors=True)
        shutil.copytree(tht_root, new_tht_root, symlinks=True)
        utils.jinja_render_files(self.log,
                                 templates=parsed_args.templates,
                                 working_dir=new_tht_root,
                                 roles_file=roles_file_path,
                                 networks_file=networks_file_path,
                                 base_path=new_tht_root)
        return new_tht_root, tht_root

    def create_env_files(self, parsed_args,
                         new_tht_root, user_tht_root):
        self.log.debug("Creating Environment files")
        # A dictionary to store resource registry types that are internal,
        # and should not be overridden in user provided environments.
        protected_overrides = {'registry_entries': dict()}
        created_env_files = [
            os.path.join(new_tht_root, constants.DEFAULT_RESOURCE_REGISTRY)]

        parameters = utils.build_enabled_sevices_image_params(
            created_env_files, parsed_args, new_tht_root, user_tht_root,
            self.working_dir)

        self._update_parameters(
            parsed_args, parameters, new_tht_root, user_tht_root)

        param_env = utils.create_parameters_env(
            parameters, new_tht_root, parsed_args.stack)
        created_env_files.extend(param_env)

        if parsed_args.baremetal_deployment is not None:
            created_env_files.extend(
                self._provision_networks(parsed_args, new_tht_root,
                                         protected_overrides))
            created_env_files.extend(
                self._provision_virtual_ips(parsed_args, new_tht_root,
                                            protected_overrides))
            self._unprovision_baremetal(parsed_args)
            created_env_files.extend(
                self._provision_baremetal(parsed_args, new_tht_root,
                                          protected_overrides))

        user_environments = []
        if parsed_args.environment_directories:
            user_environments.extend(utils.load_environment_directories(
                parsed_args.environment_directories))

        if parsed_args.environment_files:
            user_environments.extend(parsed_args.environment_files)

        if (not parsed_args.disable_protected_resource_types
                and user_environments):
            rewritten_user_environments = []
            for env_path in user_environments:
                env_path, abs_env_path = utils.rewrite_env_path(
                    env_path, new_tht_root, user_tht_root)
                rewritten_user_environments.append((env_path, abs_env_path))
            utils.check_prohibited_overrides(protected_overrides,
                                             rewritten_user_environments)
        utils.duplicate_param_check(user_environments=user_environments)
        created_env_files.extend(user_environments)

        return created_env_files

    def deploy_tripleo_heat_templates(self, parsed_args,
                                      new_tht_root, user_tht_root,
                                      created_env_files):
        """Deploy the fixed templates in TripleO Heat Templates"""

        self.log.info("Processing templates in the directory {0}".format(
            os.path.abspath(new_tht_root)))

        deployment_options = {}
        if parsed_args.deployment_python_interpreter:
            deployment_options['ansible_python_interpreter'] = \
                parsed_args.deployment_python_interpreter

        self.log.debug("Processing environment files %s" % created_env_files)
        env_files_tracker = []
        env_files, env = utils.process_multiple_environments(
            created_env_files, new_tht_root, user_tht_root,
            env_files_tracker=env_files_tracker,
            cleanup=(not parsed_args.no_cleanup))

        # Copy the env_files to tmp folder for archiving
        utils.copy_env_files(env_files, new_tht_root)

        if parsed_args.limit:
            # check if skip list is defined while using --limit and throw a
            # warning if necessary
            self._check_limit_skiplist_warning(env)

        # check if we're trying to deploy ceph during the overcloud deployment
        utils.check_deployed_ceph_stage(env)

        old_stack_env = utils.get_saved_stack_env(
            self.working_dir, parsed_args.stack)
        if old_stack_env:
            if not parsed_args.disable_validations:
                ceph_deployed = env.get('resource_registry', {}).get(
                    'OS::TripleO::Services::CephMon', 'OS::Heat::None')
                ceph_external = env.get('resource_registry', {}).get(
                    'OS::TripleO::Services::CephExternal', 'OS::Heat::None')
                # note (fpantano) if ceph is not TripleO deployed and no
                # external ceph cluster are present, there's no reason to
                # make this check and we can simply ignore it
                if (ceph_deployed != "OS::Heat::None"
                        or ceph_external != "OS::Heat::None"):
                    utils.check_ceph_fsid_matches_env_files(old_stack_env, env)
                    # upgrades: check if swift is deployed
                    utils.check_swift_and_rgw(old_stack_env, env,
                                              self.__class__.__name__)
        # check migration to service vips managed by servce
        utils.check_service_vips_migrated_to_service(env)

        # check if ceph-ansible env is present
        utils.check_ceph_ansible(env.get('resource_registry', {}),
                                 self.__class__.__name__)
        utils.check_neutron_resources(env)

        self._try_overcloud_deploy_with_compat_yaml(
            new_tht_root,
            parsed_args.stack, env_files,
            parsed_args.timeout, env,
            parsed_args.run_validations,
            parsed_args.roles_file,
            env_files_tracker=env_files_tracker,
            deployment_options=deployment_options)

    def _try_overcloud_deploy_with_compat_yaml(self, tht_root,
                                               stack_name,
                                               env_files, timeout,
                                               env, run_validations,
                                               roles_file,
                                               env_files_tracker=None,
                                               deployment_options=None):
        overcloud_yaml = os.path.join(tht_root, constants.OVERCLOUD_YAML_NAME)
        try:
            self._heat_deploy(stack_name, overcloud_yaml,
                              env_files, timeout,
                              tht_root, env,
                              run_validations,
                              roles_file,
                              env_files_tracker=env_files_tracker,
                              deployment_options=deployment_options)
        except oscexc.CommandError as e:
            messages = 'Failed to deploy: %s' % str(e)
            raise ValueError(messages)

    def _deploy_postconfig(self, parsed_args):
        self.log.debug("_deploy_postconfig(%s)" % parsed_args)

        overcloud_endpoint = utils.get_overcloud_endpoint(self.working_dir)
        # NOTE(jaosorior): The overcloud endpoint can contain an IP address or
        # an FQDN depending on how what it's configured to output in the
        # tripleo-heat-templates. Such a configuration can be done by
        # overriding the EndpointMap through parameter_defaults.
        overcloud_ip_or_fqdn = urllib.parse.urlparse(
            overcloud_endpoint).hostname

        keystone_admin_ip = utils.get_stack_saved_output_item(
            'KeystoneAdminVip', self.working_dir)
        no_proxy = os.environ.get('no_proxy', overcloud_ip_or_fqdn)
        no_proxy_list = map(utils.bracket_ipv6,
                            [no_proxy, overcloud_ip_or_fqdn,
                             keystone_admin_ip])
        os.environ['no_proxy'] = ','.join([x for x in no_proxy_list if x])

        utils.remove_known_hosts(overcloud_ip_or_fqdn)

    def _provision_baremetal(self, parsed_args, tht_root, protected_overrides):

        baremetal_file = utils.get_baremetal_file_path(self.working_dir,
                                                       parsed_args.stack)
        if not baremetal_file:
            return []

        baremetal_file_dir = os.path.dirname(baremetal_file)
        with open(baremetal_file, 'r') as fp:
            roles = yaml.safe_load(fp)

        utils.validate_roles_playbooks(baremetal_file_dir, roles)

        key = self.get_key_pair(parsed_args)
        with open('{}.pub'.format(key), 'rt') as fp:
            ssh_key = fp.read()

        output_path = utils.build_user_env_path(
            'baremetal-deployed.yaml',
            tht_root
        )
        extra_vars = {
            "stack_name": parsed_args.stack,
            "baremetal_deployment": roles,
            "baremetal_deployed_path": output_path,
            "ssh_private_key_file": key,
            "ssh_public_keys": ssh_key,
            "ssh_user_name": parsed_args.overcloud_ssh_user,
            "manage_network_ports": True,
            "configure_networking": parsed_args.network_config,
            "working_dir": self.working_dir,
            "templates": parsed_args.templates,
        }

        with utils.TempDirs() as tmp:
            utils.run_ansible_playbook(
                playbook='cli-overcloud-node-provision.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=utils.playbook_verbosity(self=self),
                extra_vars=extra_vars,
            )
        utils.run_role_playbooks(self, self.working_dir, baremetal_file_dir,
                                 roles, parsed_args.network_config)

        utils.extend_protected_overrides(protected_overrides, output_path)

        return [output_path]

    def _unprovision_baremetal(self, parsed_args):

        baremetal_file = utils.get_baremetal_file_path(self.working_dir,
                                                       parsed_args.stack)
        if not baremetal_file:
            return

        with open(baremetal_file, 'r') as fp:
            roles = yaml.safe_load(fp)

        with utils.TempDirs() as tmp:
            utils.run_ansible_playbook(
                playbook='cli-overcloud-node-unprovision.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=utils.playbook_verbosity(self=self),
                extra_vars={
                    "stack_name": parsed_args.stack,
                    "baremetal_deployment": roles,
                    "prompt": False,
                    "manage_network_ports": True,
                }
            )

    def _provision_networks(self, parsed_args, tht_root, protected_overrides):
        # Parse the network data, if any network have 'ip_subnet' or
        # 'ipv6_subnet' keys this is not a network-v2 format file. In this
        # case do nothing.
        networks_file_path = utils.get_networks_file_path(
            self.working_dir, parsed_args.stack)

        if not utils.is_network_data_v2(networks_file_path):
            return []

        output_path = utils.build_user_env_path(
            'networks-deployed.yaml',
            tht_root)
        extra_vars = {
            "network_data_path": networks_file_path,
            "network_deployed_path": output_path,
            "overwrite": True,
            "templates": parsed_args.templates,
        }

        with utils.TempDirs() as tmp:
            utils.run_ansible_playbook(
                playbook='cli-overcloud-network-provision.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=utils.playbook_verbosity(self=self),
                extra_vars=extra_vars,
            )

        utils.extend_protected_overrides(protected_overrides, output_path)

        return [output_path]

    def _provision_virtual_ips(self, parsed_args, tht_root,
                               protected_overrides):
        networks_file_path = utils.get_networks_file_path(self.working_dir,
                                                          parsed_args.stack)
        if not utils.is_network_data_v2(networks_file_path):
            return []

        vip_file_path = utils.get_vip_file_path(self.working_dir,
                                                parsed_args.stack)

        output_path = utils.build_user_env_path(
            'virtual-ips-deployed.yaml',
            tht_root)

        extra_vars = {
            "stack_name": parsed_args.stack,
            "vip_data_path": vip_file_path,
            "vip_deployed_path": output_path,
            "overwrite": True,
            "templates": parsed_args.templates,
        }

        with utils.TempDirs() as tmp:
            utils.run_ansible_playbook(
                playbook='cli-overcloud-network-vip-provision.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=utils.playbook_verbosity(self=self),
                extra_vars=extra_vars,
            )

        utils.extend_protected_overrides(protected_overrides, output_path)

        return [output_path]

    def _export_stack(self, parsed_args, should_filter,
                      config_download_dir, export_file):
        # Create overcloud export
        data = export.export_overcloud(
            self.working_dir,
            parsed_args.stack, True, should_filter,
            config_download_dir)
        # write the exported data
        with open(export_file, 'w') as f:
            yaml.safe_dump(data, f, default_flow_style=False)
            os.chmod(export_file, 0o600)

    def setup_ephemeral_heat(self, parsed_args):
        self.log.info("Using ephemeral heat for stack operation")
        self.heat_launcher = utils.get_heat_launcher(
            parsed_args.heat_type,
            api_container_image=parsed_args.heat_container_api_image,
            engine_container_image=parsed_args.heat_container_engine_image,
            heat_dir=os.path.join(self.working_dir,
                                  'heat-launcher'),
            use_tmp_dir=False,
            rm_heat=parsed_args.rm_heat,
            skip_heat_pull=parsed_args.skip_heat_pull)
        self.orchestration_client = utils.launch_heat(self.heat_launcher)
        self.clients.orchestration = self.orchestration_client

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
            default='tripleo-admin',
            help=_('User for ssh access to overcloud nodes')
        )
        parser.add_argument(
            '--overcloud-ssh-key',
            default=None,
            help=_('Key path for ssh access to overcloud nodes. When'
                   'undefined the key will be autodetected.')
        )
        parser.add_argument(
            '--overcloud-ssh-network',
            help=_('Network name to use for ssh access to overcloud nodes.'),
            default='ctlplane'
        )
        parser.add_argument(
            '--overcloud-ssh-enable-timeout',
            help=_('This option no longer has any effect.'),
            type=int,
            default=constants.ENABLE_SSH_ADMIN_TIMEOUT
        )
        parser.add_argument(
            '--overcloud-ssh-port-timeout',
            help=_('Timeout for the ssh port to become active.'),
            type=int,
            default=constants.ENABLE_SSH_ADMIN_SSH_PORT_TIMEOUT
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
            '--vip-file', dest='vip_file',
            help=_('Configuration file describing the network Virtual IPs.'))
        parser.add_argument(
            '--no-cleanup', action='store_true',
            help=_('Don\'t cleanup temporary files, just log their location')
        )
        parser.add_argument(
            '--update-plan-only',
            action='store_true',
            help=_('DEPRECATED: Only update the plan. Do not perform the '
                   'actual deployment. NOTE: Will move to a discrete command  '
                   'in a future release. Not supported anymore.')
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
            default=True,
            help=_('DEPRECATED. Disable the pre-deployment validations '
                   'entirely. These validations are the built-in '
                   'pre-deployment validations. To enable external '
                   'validations from tripleo-validations, '
                   'use the --run-validations flag. These validations are '
                   'now run via the external validations in '
                   'tripleo-validations.'))
        parser.add_argument(
            '--inflight-validations',
            action='store_true',
            default=False,
            dest='inflight',
            help=_('Activate in-flight validations during the deploy. '
                   'In-flight validations provide a robust way to ensure '
                   'deployed services are running right after their '
                   'activation. Defaults to False.')
        )
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
            default=True,
            help=_('DEPRECATED: Use pre-provisioned overcloud nodes.'
                   'Now the default and this CLI option has no effect.')
        )
        parser.add_argument(
            '--provision-nodes',
            action='store_false',
            dest='deployed_server',
            default=True,
            help=_('DEPRECATED: Provision overcloud nodes with heat.'
                   'This method is no longer supported.')
        )
        parser.add_argument(
            '--config-download',
            action='store_true',
            default=True,
            help=_('DEPRECATED: Run deployment via config-download mechanism. '
                   'This is now the default, and this CLI options has no '
                   'effect.')
        )
        parser.add_argument(
            '--no-config-download',
            '--stack-only',
            action='store_true',
            default=False,
            dest='stack_only',
            help=_('Disable the config-download workflow and only create '
                   'the stack and download the config. No software '
                   'configuration, setup, or any changes will be applied '
                   'to overcloud nodes.')
        )
        parser.add_argument(
            '--config-download-only',
            action='store_true',
            default=False,
            help=_('Disable the stack create and setup, and only run the '
                   'config-download workflow to apply the software '
                   'configuration. Requires that config-download setup '
                   'was previously completed, either with --stack-only '
                   'and --setup-only or a full deployment')
        )
        parser.add_argument(
            '--setup-only',
            action='store_true',
            default=False,
            help=_('Disable the stack and config-download workflow to apply '
                   'the software configuration and only run the setup to '
                   'enable ssh connectivity.')
        )
        parser.add_argument(
            '--config-dir',
            dest='config_dir',
            default=None,
            help=_('The directory where the configuration files will be '
                   'pushed'),
        )
        parser.add_argument(
            '--config-type',
            dest='config_type',
            type=list,
            default=None,
            help=_('Only used when "--setup-only" is invoked. '
                   'Type of object config to be extract from the deployment, '
                   'defaults to all keys available'),
        )
        parser.add_argument(
            '--no-preserve-config',
            dest='preserve_config_dir',
            action='store_false',
            default=True,
            help=('Only used when "--setup-only" is invoked. '
                  'If specified, will delete and recreate the --config-dir '
                  'if it already exists. Default is to use the existing dir '
                  'location and overwrite files. Files in --config-dir not '
                  'from the stack will be preserved by default.')
        )
        parser.add_argument(
            '--output-dir',
            action='store',
            default=None,
            help=_('Directory to use for saved output when using '
                   '--config-download. When not '
                   'specified, <working-dir>/config-download will be used.')
        )
        parser.add_argument(
            '--override-ansible-cfg',
            action='store',
            default=None,
            help=_('Path to ansible configuration file. The configuration '
                   'in the file will override any configuration used by '
                   'config-download by default.')
        )
        parser.add_argument(
            '--config-download-timeout',
            action='store',
            type=int,
            default=None,
            help=_('Timeout (in minutes) to use for config-download steps. If '
                   'unset, will default to however much time is leftover '
                   'from the --timeout parameter after the stack operation.')
        )
        parser.add_argument('--deployment-python-interpreter', default=None,
                            help=_('The path to python interpreter to use for '
                                   'the deployment actions. This may need to '
                                   'be used if deploying on a python2 host '
                                   'from a python3 system or vice versa.'))
        parser.add_argument(
            '-b', '--baremetal-deployment',
            metavar='<baremetal_deployment.yaml>',
            nargs='?',
            const=True,
            help=_('Deploy baremetal nodes, network and virtual IP addresses '
                   'as defined in baremetal_deployment.yaml along with '
                   'overcloud. If no baremetal_deployment YAML file is given, '
                   'the tripleo-<stack_name>-baremetal-deployment.yaml file '
                   'in the working-dir will be used.'))
        parser.add_argument('--network-config',
                            help=_('Apply network config to provisioned '
                                   'nodes.'),
                            default=False,
                            action="store_true")
        parser.add_argument(
            '--limit',
            action='store',
            default=None,
            help=_("A string that identifies a single node or comma-separated"
                   "list of nodes the config-download Ansible playbook "
                   "execution will be limited to. For example: --limit"
                   " \"compute-0,compute-1,compute-5\".")
        )
        parser.add_argument(
            '--tags',
            action='store',
            default=None,
            help=_('A list of tags to use when running the the config-download'
                   ' ansible-playbook command.')
        )
        parser.add_argument(
            '--skip-tags',
            action='store',
            default=None,
            help=_('A list of tags to skip when running the the'
                   ' config-download ansible-playbook command.')
        )
        parser.add_argument(
            '--ansible-forks',
            action='store',
            default=None,
            type=int,
            help=_('The number of Ansible forks to use for the'
                   ' config-download ansible-playbook command.')
        )
        parser.add_argument(
            '--disable-container-prepare',
            action='store_true',
            default=False,
            help=_('Disable the container preparation actions to prevent '
                   'container tags from being updated and new containers '
                   'from being fetched. If you skip this but do not have '
                   'the container parameters configured, the deployment '
                   'action may fail.')
        )
        parser.add_argument(
            '--working-dir',
            action='store',
            help=_('The working directory for the deployment where all '
                   'input, output, and generated files will be stored.\n'
                   'Defaults to "$HOME/overcloud-deploy/<stack>"')
        )
        parser.add_argument(
            '--heat-type',
            action='store',
            default='pod',
            choices=['pod', 'container', 'native'],
            help=_('The type of Heat process to use to execute '
                   'the deployment.\n'
                   'pod (Default): Use an ephemeral Heat pod.\n'
                   'container (Experimental): Use an ephemeral Heat '
                   'container.\n'
                   'native (Experimental): Use an ephemeral Heat process.')
        )
        parser.add_argument(
            '--heat-container-api-image',
            metavar='<HEAT_CONTAINER_API_IMAGE>',
            dest='heat_container_api_image',
            default=constants.DEFAULT_EPHEMERAL_HEAT_API_CONTAINER,
            help=_('The container image to use when launching the heat-api '
                   'process. Only used when --heat-type=pod. '
                   'Defaults to: {}'.format(
                       constants.DEFAULT_EPHEMERAL_HEAT_API_CONTAINER))
        )
        parser.add_argument(
            '--heat-container-engine-image',
            metavar='<HEAT_CONTAINER_ENGINE_IMAGE>',
            dest='heat_container_engine_image',
            default=constants.DEFAULT_EPHEMERAL_HEAT_ENGINE_CONTAINER,
            help=_('The container image to use when launching the heat-engine '
                   'process. Only used when --heat-type=pod. '
                   'Defaults to: {}'.format(
                       constants.DEFAULT_EPHEMERAL_HEAT_ENGINE_CONTAINER))
        )
        parser.add_argument(
            '--rm-heat',
            action='store_true',
            default=False,
            help=_('If specified and --heat-type is container or pod '
                   'any existing container or pod of a previous '
                   'ephemeral Heat process will be deleted first. '
                   'Ignored if --heat-type is native.')
        )
        parser.add_argument(
            '--skip-heat-pull',
            action='store_true',
            default=False,
            help=_('When --heat-type is pod or container, assume '
                   'the container image has already been pulled ')
        )
        parser.add_argument(
            '--disable-protected-resource-types',
            action='store_true',
            default=False,
            help=_('Disable protected resource type overrides. Resources '
                   'types that are used internally are protected, and cannot '
                   'be overridden in the user environment. Setting this '
                   'argument disables the protection, allowing the protected '
                   'resource types to be override in the user environment.')
        )
        parser.add_argument(
            '-y', '--yes', default=False,
            action='store_true',
            help=_('Use -y or --yes to skip any confirmation required before '
                   'the deploy operation. Use this with caution!')
        )
        parser.add_argument(
            '--allow-deprecated-network-data', default=False,
            action='store_true',
            help=_('Set this to allow using deprecated network data YAML '
                   'definition schema.')
        )

        return parser

    def take_action(self, parsed_args):
        logging.register_options(CONF)
        logging.setup(CONF, '')
        self.log.debug("take_action(%s)" % parsed_args)

        if (parsed_args.networks_file and
                (not parsed_args.yes
                 and not parsed_args.allow_deprecated_network_data)):
            if not utils.is_network_data_v2(parsed_args.networks_file):
                confirm = utils.prompt_user_for_confirmation(
                    'DEPRECATED network data definition {} provided. Please '
                    'update the network data definition to version 2.\n'
                    'Do you still wish to continue with deployment [y/N]'
                    .format(parsed_args.networks_file),
                    self.log)
                if not confirm:
                    raise oscexc.CommandError("Action not confirmed, exiting.")

        if not parsed_args.working_dir:
            self.working_dir = utils.get_default_working_dir(
                parsed_args.stack)
        else:
            self.working_dir = parsed_args.working_dir
        utils.makedirs(self.working_dir)
        utils.check_deploy_backups(self.working_dir)

        if parsed_args.update_plan_only:
            raise exceptions.DeploymentError(
                'Only plan update is not supported.')

        deploy_status = 'DEPLOY_SUCCESS'
        deploy_message = 'successfully'

        self._setup_clients(parsed_args)

        _update_args_from_answers_file(parsed_args)

        _validate_args(parsed_args)

        # Make a copy of the files provided on command line in the working dir
        # If the command is re-run without providing the argument the "backup"
        # from the previous run in the working dir is used.
        utils.update_working_dir_defaults(self.working_dir, parsed_args)

        if parsed_args.vip_file:
            _validate_vip_file(parsed_args.stack, self.working_dir)

        # Throw warning if deprecated service is enabled and
        # ask user if deployment should still be continued.
        if parsed_args.environment_files:
            utils.check_deprecated_service_is_enabled(
                parsed_args.environment_files)

        if parsed_args.dry_run:
            self.log.info("Validation Finished")
            return

        self.heat_launcher = None
        start = time.time()

        new_tht_root, user_tht_root = \
            self.create_template_dirs(parsed_args)
        created_env_files = self.create_env_files(
                parsed_args, new_tht_root, user_tht_root)

        # full_deploy means we're doing a full deployment
        # e.g., no --*-only args were passed
        full_deploy = not (parsed_args.stack_only or parsed_args.setup_only or
                           parsed_args.config_download_only)
        # do_stack is True when:
        # --stack-only
        # a full deployment
        do_stack = (parsed_args.stack_only or full_deploy)
        # do_setup is True when:
        # --setup-only OR
        # a full deployment
        do_setup = parsed_args.setup_only or full_deploy
        # do_config_download is True when:
        # --config-download-only OR
        # a full deployment
        do_config_download = parsed_args.config_download_only or full_deploy

        config_download_dir = parsed_args.output_dir or \
            os.path.join(self.working_dir, "config-download")
        horizon_url = None
        overcloud_endpoint = None
        old_rcpath = None
        rcpath = None

        # All code within this "try" block requires Heat, and no other code
        # outside the block should require Heat. With ephemeral Heat, the Heat
        # pods will be cleaned up in the "finally" clause, such that it's not
        # running during later parts of overcloud deploy.
        self.log.info("Deploying overcloud.")
        deployment.set_deployment_status(
            parsed_args.stack,
            status='DEPLOYING',
            working_dir=self.working_dir)

        try:
            if do_stack:
                self.setup_ephemeral_heat(parsed_args)

                self.deploy_tripleo_heat_templates(
                    parsed_args, new_tht_root,
                    user_tht_root, created_env_files)

                stack = utils.get_stack(
                    self.orchestration_client, parsed_args.stack)
                utils.save_stack(stack, self.working_dir)

                horizon_url = deployment.get_horizon_url(
                    stack=stack.stack_name,
                    heat_type=parsed_args.heat_type,
                    working_dir=self.working_dir)

                overcloud_endpoint = utils.get_overcloud_endpoint(
                    self.working_dir)
                overcloud_admin_vip = utils.get_stack_saved_output_item(
                    'KeystoneAdminVip', self.working_dir)
                rc_params = utils.get_rc_params(self.working_dir)

                # For backwards compatibility, we will also write overcloudrc
                # to $HOME and then self.working_dir.
                old_rcpath = deployment.create_overcloudrc(
                    parsed_args.stack, overcloud_endpoint, overcloud_admin_vip,
                    rc_params, parsed_args.no_proxy)
                rcpath = deployment.create_overcloudrc(
                    parsed_args.stack, overcloud_endpoint, overcloud_admin_vip,
                    rc_params, parsed_args.no_proxy, self.working_dir)

                # Download config
                config_dir = parsed_args.config_dir or config_download_dir
                config_type = parsed_args.config_type
                preserve_config_dir = parsed_args.preserve_config_dir
                key_file = utils.get_key(parsed_args.stack)
                extra_vars = {
                    'plan': parsed_args.stack,
                    'config_dir': config_dir,
                    'preserve_config': preserve_config_dir,
                    'output_dir': config_download_dir,
                    'ansible_ssh_private_key_file': key_file,
                    'ssh_network': parsed_args.overcloud_ssh_network,
                    'python_interpreter':
                        parsed_args.deployment_python_interpreter,
                }
                if parsed_args.config_type:
                    extra_vars['config_type'] = config_type

                playbook = 'cli-config-download.yaml'
                ansible_work_dir = os.path.join(
                    self.working_dir, os.path.splitext(playbook)[0])
                utils.run_ansible_playbook(
                    playbook='cli-config-download.yaml',
                    inventory='localhost,',
                    workdir=ansible_work_dir,
                    playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                    reproduce_command=True,
                    verbosity=utils.playbook_verbosity(self=self),
                    extra_vars=extra_vars
                )
        except (BaseException, Exception):
            with excutils.save_and_reraise_exception():
                deploy_status = 'DEPLOY_FAILED'
                deploy_message = 'with error'
                deployment.set_deployment_status(
                    parsed_args.stack,
                    status=deploy_status,
                    working_dir=self.working_dir)

        finally:
            if self.heat_launcher:
                self.log.info("Stopping ephemeral heat.")
                utils.kill_heat(self.heat_launcher)
                utils.rm_heat(self.heat_launcher)
        try:
            if do_setup:
                deployment.get_hosts_and_enable_ssh_admin(
                    parsed_args.stack,
                    parsed_args.overcloud_ssh_network,
                    parsed_args.overcloud_ssh_user,
                    self.get_key_pair(parsed_args),
                    parsed_args.overcloud_ssh_port_timeout,
                    self.working_dir,
                    verbosity=utils.playbook_verbosity(self=self),
                    heat_type=parsed_args.heat_type
                )

            if do_config_download:
                if parsed_args.config_download_timeout:
                    timeout = parsed_args.config_download_timeout
                else:
                    used = int((time.time() - start) // 60)
                    timeout = parsed_args.timeout - used
                    if timeout <= 0:
                        raise exceptions.DeploymentError(
                            'Deployment timed out after %sm' % used)

                deployment_options = {}
                if parsed_args.deployment_python_interpreter:
                    deployment_options['ansible_python_interpreter'] = \
                        parsed_args.deployment_python_interpreter

                deployment.make_config_download_dir(config_download_dir,
                                                    parsed_args.stack)

                deployment.config_download(
                    self.log,
                    self.clients,
                    parsed_args.stack,
                    parsed_args.overcloud_ssh_network,
                    config_download_dir,
                    parsed_args.override_ansible_cfg,
                    timeout=parsed_args.overcloud_ssh_port_timeout,
                    verbosity=utils.playbook_verbosity(self=self),
                    deployment_options=deployment_options,
                    in_flight_validations=parsed_args.inflight,
                    deployment_timeout=timeout,
                    tags=parsed_args.tags,
                    skip_tags=parsed_args.skip_tags,
                    limit_hosts=utils.playbook_limit_parse(
                        limit_nodes=parsed_args.limit
                    ),
                    forks=parsed_args.ansible_forks,
                    denyed_hostnames=utils.get_stack_saved_output_item(
                        'BlacklistedHostnames', self.working_dir))
            deployment.set_deployment_status(
                parsed_args.stack,
                status=deploy_status,
                working_dir=self.working_dir)
        except (BaseException, Exception):
            with excutils.save_and_reraise_exception():
                deploy_status = 'DEPLOY_FAILED'
                deploy_message = 'with error'
                deployment.set_deployment_status(
                    parsed_args.stack,
                    status=deploy_status,
                    working_dir=self.working_dir)
        finally:
            try:
                # Run postconfig on create or force
                if (stack or parsed_args.force_postconfig
                        and not parsed_args.skip_postconfig):
                    self._deploy_postconfig(parsed_args)
            except Exception as e:
                self.log.error('Exception during postconfig')
                self.log.error(e)

            try:
                # Copy clouds.yaml to the cloud user directory
                user = \
                    getpwuid(os.stat(constants.CLOUD_HOME_DIR).st_uid).pw_name
                utils.copy_clouds_yaml(user)
            except Exception as e:
                self.log.error('Exception creating clouds.yaml')
                self.log.error(e)

            try:
                utils.create_tempest_deployer_input(
                    output_dir=self.working_dir)
            except Exception as e:
                self.log.error('Exception creating tempest configuration.')
                self.log.error(e)

            try:
                if do_stack:
                    # Create overcloud export
                    self._export_stack(
                        parsed_args, False,
                        config_download_dir,
                        os.path.join(
                            self.working_dir, "%s-export.yaml" %
                            parsed_args.stack))
                    # Create overcloud cell export
                    self._export_stack(
                        parsed_args, True,
                        config_download_dir,
                        os.path.join(
                            self.working_dir, "%s-cell-export.yaml" %
                            parsed_args.stack))
            except Exception as e:
                self.log.error('Exception creating overcloud export.')
                self.log.error(e)

            if do_config_download:
                print("Overcloud Endpoint: {0}".format(overcloud_endpoint))
                print("Overcloud Horizon Dashboard URL: {0}".format(
                    horizon_url))
                print("Overcloud rc file: {} and {}".format(
                    rcpath, old_rcpath))
                print("Overcloud Deployed {0}".format(deploy_message))

            try:
                if parsed_args.output_dir:
                    ansible_dir = config_download_dir
                else:
                    ansible_dir = None
                archive_filename = utils.archive_deploy_artifacts(
                    self.log, parsed_args.stack, self.working_dir, ansible_dir)
                utils.create_archive_dir()
                utils.run_command(
                    ['sudo', 'cp', archive_filename,
                     constants.TRIPLEO_ARCHIVE_DIR])
            except Exception as e:
                self.log.error('Exception archiving deploy artifacts')
                self.log.error(e)


class GetDeploymentStatus(command.Command):
    """Get deployment status"""

    log = logging.getLogger(__name__ + ".GetDeploymentStatus")

    def get_parser(self, prog_name):
        parser = super(GetDeploymentStatus, self).get_parser(prog_name)
        parser.add_argument('--plan', '--stack',
                            help=_('Name of the stack/plan. '
                                   '(default: overcloud)'),
                            default='overcloud')
        parser.add_argument(
            '--working-dir',
            action='store',
            help=_('The working directory for the deployment where all '
                   'input, output, and generated files are stored.\n'
                   'Defaults to "$HOME/overcloud-deploy/<stack>"'))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        stack = parsed_args.plan
        if not parsed_args.working_dir:
            working_dir = utils.get_default_working_dir(stack)
        else:
            working_dir = parsed_args.working_dir

        status = deployment.get_deployment_status(
            self.app.client_manager,
            stack,
            working_dir
        )

        if not status:
            print('No deployment was found for %s' % stack)
            return

        table = PrettyTable(
            ['Stack Name', 'Deployment Status'])
        table.add_row([stack, status])
        print(table, file=self.app.stdout)
