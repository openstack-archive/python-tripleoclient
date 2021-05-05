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
from collections import OrderedDict
import os
import os.path
from oslo_config import cfg
from oslo_log import log as logging
from prettytable import PrettyTable
from pwd import getpwuid
import re
import shutil
import six
import subprocess
import time
import yaml

from heatclient.common import template_utils
from keystoneauth1.exceptions.catalog import EndpointNotFound
import openstack
from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from tripleo_common.image import kolla_builder
from tripleo_common import update
from tripleo_common.utils import plan as plan_utils

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils
from tripleoclient.workflows import deployment
from tripleoclient.workflows import parameters as workflow_params
from tripleoclient.workflows import roles

CONF = cfg.CONF


class DeployOvercloud(command.Command):
    """Deploy Overcloud"""

    log = logging.getLogger(__name__ + ".DeployOvercloud")

    def _setup_clients(self, parsed_args):
        self.clients = self.app.client_manager
        self.orchestration_client = self.clients.orchestration
        if not parsed_args.deployed_server:
            try:
                self.compute_client = self.clients.compute
                self.baremetal_client = self.clients.baremetal
            except EndpointNotFound:
                self.log.warning('WARNING: Nova endpoint not available. '
                                 'Assuming --deployed-server')
                parsed_args.deployed_server = True

    def _update_args_from_answers_file(self, args):
        if args.answers_file is not None:
            with open(args.answers_file, 'r') as answers_file:
                answers = yaml.safe_load(answers_file)

            if args.templates is None:
                args.templates = answers['templates']
            if 'environments' in answers:
                if args.environment_files is not None:
                    answers['environments'].extend(args.environment_files)
                args.environment_files = answers['environments']

    def _update_parameters(self, args, parameters,
                           tht_root, user_tht_root):
        parameters['RootStackName'] = args.stack
        if not args.skip_deploy_identifier:
            parameters['DeployIdentifier'] = int(time.time())
        else:
            parameters['DeployIdentifier'] = ''

        if args.heat_type != 'installed':
            heat = None
        else:
            heat = self.orchestration_client

        # Check for existing passwords file
        password_params_path = os.path.join(
            self.working_dir,
            constants.PASSWORDS_ENV_FORMAT.format(args.stack))
        if os.path.exists(password_params_path):
            with open(password_params_path, 'r') as f:
                passwords_env = yaml.safe_load(f.read())
        else:
            passwords_env = None

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
            if getattr(args, arg, None) is not None:
                parameters[param] = getattr(args, arg)

        parameters[
            'UndercloudHostsEntries'] = [self._get_undercloud_host_entry()]

        parameters['CtlplaneNetworkAttributes'] = self._get_ctlplane_attrs()

        return parameters

    def _get_ctlplane_attrs(self):
        try:
            conn = openstack.connect('undercloud')
        except openstack.exceptions.ConfigException:
            return dict()

        if not conn.endpoint_for('network'):
            return dict()

        network = conn.network.find_network('ctlplane')
        if network is None:
            return dict()

        net_attributes_map = {'network': dict(), 'subnets': dict()}

        net_attributes_map['network'].update({
            'name': network.name,
            'mtu': network.mtu,
            'dns_domain': network.dns_domain,
            'tags': network.tags,
        })

        for subnet_id in network.subnet_ids:
            subnet = conn.network.get_subnet(subnet_id)
            net_attributes_map['subnets'].update({
                subnet.name: {
                    'name': subnet.name,
                    'cidr': subnet.cidr,
                    'gateway_ip': subnet.gateway_ip,
                    'host_routes': subnet.host_routes,
                    'dns_nameservers': subnet.dns_nameservers,
                    'ip_version': subnet.ip_version,
                }
            })

        return net_attributes_map

    def _cleanup_host_entry(self, entry):
        # remove any tab or space excess
        entry_stripped = re.sub('[ \t]+', ' ', str(entry).rstrip())
        # removes any duplicate identical lines
        unique_lines = list(set(entry_stripped.splitlines()))
        ret = ''
        for line in unique_lines:
            # remove any duplicate word
            hosts_unique = (' '.join(
                OrderedDict((w, w) for w in line.split()).keys()))
            if hosts_unique != '':
                ret += hosts_unique + '\n'
        return ret.rstrip('\n')

    def _get_undercloud_host_entry(self):
        """Get hosts entry for undercloud ctlplane network

        The host entry will be added on overcloud nodes
        """
        ctlplane_hostname = '.'.join([utils.get_short_hostname(), 'ctlplane'])
        cmd = ['getent', 'hosts', ctlplane_hostname]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                   universal_newlines=True)
        out, err = process.communicate()
        if process.returncode != 0:
            raise exceptions.DeploymentError('No entry for %s in /etc/hosts'
                                             % ctlplane_hostname)
        return self._cleanup_host_entry(out)

    def _check_limit_skiplist_warning(self, env):
        if env.get('parameter_defaults').get('DeploymentServerBlacklist'):
            msg = _('[WARNING] DeploymentServerBlacklist is defined and will '
                    'be ignored because --limit has been specified.')
            self.log.warning(msg)

    def _heat_deploy(self, stack, stack_name, template_path,
                     env_files, timeout, tht_root, env,
                     run_validations,
                     roles_file,
                     env_files_tracker=None,
                     deployment_options=None):
        """Verify the Baremetal nodes are available and do a stack update"""

        if stack:
            self.log.debug(
                "Checking compatibilities of neutron drivers for {0}".format(
                    stack_name))
            msg = update.check_neutron_mechanism_drivers(
                env, stack, None, stack_name)
            if msg:
                raise oscexc.CommandError(msg)

        self.log.debug("Getting template contents from plan %s" % stack_name)

        template_files, template = template_utils.get_template_contents(
            template_file=template_path)
        files = dict(list(template_files.items()) + list(env_files.items()))

        workflow_params.check_deprecated_parameters(
            self.clients, stack_name, tht_root, template,
            roles_file, files, env_files_tracker)

        self.log.info("Deploying templates in the directory {0}".format(
            os.path.abspath(tht_root)))
        deployment.deploy_without_plan(
            self.clients, stack, stack_name,
            template, files, env_files_tracker,
            self.log, self.working_dir)

    def create_template_dirs(self, parsed_args):
        tht_root = os.path.abspath(parsed_args.templates)
        new_tht_root = "%s/tripleo-heat-templates" % self.working_dir
        self.log.debug("Creating working templates tree in %s"
                       % new_tht_root)
        shutil.rmtree(new_tht_root, ignore_errors=True)
        shutil.copytree(tht_root, new_tht_root, symlinks=True)
        utils.jinja_render_files(self.log, parsed_args.templates,
                                 new_tht_root,
                                 parsed_args.roles_file,
                                 parsed_args.networks_file,
                                 new_tht_root)
        return new_tht_root, tht_root

    def build_image_params(self, env_files, parsed_args,
                           new_tht_root, user_tht_root):
        image_params = plan_utils.default_image_params()
        if not parsed_args.disable_container_prepare:
            if parsed_args.environment_directories:
                env_files.extend(utils.load_environment_directories(
                    parsed_args.environment_directories))

            if parsed_args.environment_files:
                env_files.extend(parsed_args.environment_files)

            _, env = utils.process_multiple_environments(
                env_files, new_tht_root, user_tht_root,
                cleanup=(not parsed_args.no_cleanup))

            updated_params = kolla_builder.container_images_prepare_multi(
                env, roles.get_roles_data(parsed_args.roles_file,
                                          new_tht_root), dry_run=True)
            if updated_params:
                image_params.update(updated_params)

        return image_params

    def create_env_files(self, stack, parsed_args,
                         new_tht_root, user_tht_root):
        self.log.debug("Creating Environment files")
        created_env_files = []

        created_env_files.append(
            os.path.join(new_tht_root, constants.DEFAULT_RESOURCE_REGISTRY))

        parameters = self.build_image_params(
            created_env_files, parsed_args, new_tht_root, user_tht_root)

        self._update_parameters(
            parsed_args, parameters, new_tht_root, user_tht_root)

        stack_is_new = stack is None
        parameters['StackAction'] = 'CREATE' if stack_is_new else 'UPDATE'

        param_env = utils.create_parameters_env(
            parameters, new_tht_root, parsed_args.stack)
        created_env_files.extend(param_env)

        if stack:
            env_path = utils.create_breakpoint_cleanup_env(
                new_tht_root, parsed_args.stack)
            created_env_files.extend(env_path)

        if parsed_args.deployed_server:
            created_env_files.append(
                os.path.join(
                    new_tht_root,
                    constants.DEPLOYED_SERVER_ENVIRONMENT))

        created_env_files.extend(
            self._provision_baremetal(parsed_args, new_tht_root))

        if parsed_args.environment_directories:
            created_env_files.extend(utils.load_environment_directories(
                parsed_args.environment_directories))

        if parsed_args.environment_files:
            created_env_files.extend(parsed_args.environment_files)

        return created_env_files

    def deploy_tripleo_heat_templates(self, stack, parsed_args,
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

        # Invokes the workflows specified in plan environment file
        if parsed_args.plan_environment_file:
            output_path = utils.build_user_env_path(
                'derived_parameters.yaml', new_tht_root)
            workflow_params.build_derived_params_environment(
                self.clients, parsed_args.stack, new_tht_root, env_files,
                env_files_tracker, parsed_args.roles_file,
                parsed_args.plan_environment_file,
                output_path, utils.playbook_verbosity(self=self))

            created_env_files.append(output_path)
            env_files_tracker = []
            env_files, env = utils.process_multiple_environments(
                created_env_files, new_tht_root, user_tht_root,
                env_files_tracker=env_files_tracker,
                cleanup=(not parsed_args.no_cleanup))

        # Copy the env_files to tmp folder for archiving
        self._copy_env_files(env_files, new_tht_root)

        if parsed_args.limit:
            # check if skip list is defined while using --limit and throw a
            # warning if necessary
            self._check_limit_skiplist_warning(env)

        if stack:
            if not parsed_args.disable_validations:
                # note(aschultz): network validation goes here before we deploy
                utils.check_stack_network_matches_env_files(stack, env)
                ceph_deployed = env.get('resource_registry', {}).get(
                    'OS::TripleO::Services::CephMon', 'OS::Heat::None')
                ceph_external = env.get('resource_registry', {}).get(
                    'OS::TripleO::Services::CephExternal', 'OS::Heat::None')
                # note (fpantano) if ceph is not TripleO deployed and no
                # external ceph cluster are present, there's no reason to
                # make this check and we can simply ignore it
                if (ceph_deployed != "OS::Heat::None"
                        or ceph_external != "OS::Heat::None"):
                    utils.check_ceph_fsid_matches_env_files(stack, env)
                    # upgrades: check if swift is deployed
                    utils.check_swift_and_rgw(stack, env,
                                              self.__class__.__name__)
        # check migration to new nic config with ansible
        utils.check_nic_config_with_ansible(stack, env)
        # check migration to service vips managed by servce
        utils.check_service_vips_migrated_to_service(stack, env)

        if parsed_args.heat_type != 'installed':
            self.setup_ephemeral_heat(
                parsed_args, env.get('parameter_defaults'))

        self._try_overcloud_deploy_with_compat_yaml(
            new_tht_root, stack,
            parsed_args.stack, env_files,
            parsed_args.timeout, env,
            parsed_args.run_validations,
            parsed_args.roles_file,
            env_files_tracker=env_files_tracker,
            deployment_options=deployment_options)

        self._unprovision_baremetal(parsed_args)

    def _copy_env_files(self, files_dict, tht_root):
        file_prefix = "file://"

        for fullpath in files_dict.keys():

            if not fullpath.startswith(file_prefix):
                continue

            path = fullpath[len(file_prefix):]

            if path.startswith(tht_root):
                continue

            reloc_path = os.path.join(
                tht_root,
                "user-environments/{}".format(os.path.basename(path)))
            utils.safe_write(reloc_path, files_dict[fullpath])

    def _try_overcloud_deploy_with_compat_yaml(self, tht_root, stack,
                                               stack_name,
                                               env_files, timeout,
                                               env, run_validations,
                                               roles_file,
                                               env_files_tracker=None,
                                               deployment_options=None):
        overcloud_yaml = os.path.join(tht_root, constants.OVERCLOUD_YAML_NAME)
        try:
            self._heat_deploy(stack, stack_name, overcloud_yaml,
                              env_files, timeout,
                              tht_root, env,
                              run_validations,
                              roles_file,
                              env_files_tracker=env_files_tracker,
                              deployment_options=deployment_options)
        except Exception as e:
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

            # Check networks_file existence
            if parsed_args.networks_file:
                if not os.path.isfile(parsed_args.networks_file):
                    nonexisting_envs.append(parsed_args.networks_file)

            # check plan_environment_file existence
            if parsed_args.plan_environment_file:
                if not os.path.isfile(parsed_args.plan_environment_file):
                    nonexisting_envs.append(parsed_args.plan_environment_file)

            # check answers_file existence
            if parsed_args.answers_file:
                if not os.path.isfile(parsed_args.answers_file):
                    nonexisting_envs.append(parsed_args.answers_file)

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

        if (parsed_args.baremetal_deployment
                and not parsed_args.deployed_server):
            raise oscexc.CommandError(
                "Error: --deployed-server must be used when using "
                "--baremetal-deployment")

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

    def _provision_baremetal(self, parsed_args, tht_root):

        if not parsed_args.baremetal_deployment:
            return []

        with open(parsed_args.baremetal_deployment, 'r') as fp:
            roles = yaml.safe_load(fp)

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
            "ssh_public_keys": ssh_key,
            "ssh_user_name": parsed_args.overcloud_ssh_user
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

        with open(output_path, 'r') as fp:
            parameter_defaults = yaml.safe_load(fp)

        utils.write_user_environment(
            parameter_defaults,
            'baremetal-deployed.yaml',
            tht_root,
            parsed_args.stack)

        return [output_path]

    def _unprovision_baremetal(self, parsed_args):

        if not parsed_args.baremetal_deployment:
            return

        with open(parsed_args.baremetal_deployment, 'r') as fp:
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
                }
            )

    def setup_ephemeral_heat(self, parsed_args, parameters):
        self.log.info("Using tripleo-deploy with "
                      "ephemeral heat-all for stack operation")
        api_container_image = parameters['ContainerHeatApiImage']
        engine_container_image = \
            parameters['ContainerHeatEngineImage']
        restore_db = (parsed_args.setup_only or
                      parsed_args.config_download_only)
        self.heat_launcher = utils.get_heat_launcher(
            parsed_args.heat_type,
            api_container_image=api_container_image,
            engine_container_image=engine_container_image,
            heat_dir=os.path.join(self.working_dir,
                                  'heat-launcher'),
            use_tmp_dir=False,
            rm_heat=parsed_args.rm_heat,
            skip_heat_pull=parsed_args.skip_heat_pull)
        self.orchestration_client = \
            utils.launch_heat(self.heat_launcher, restore_db=restore_db)
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
            default='heat-admin',
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
            '--plan-environment-file', '-p',
            help=_('Plan Environment file for derived parameters.')
        )
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
            default=False,
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
            '--setup-only',
            action='store_true',
            default=False,
            help=_('option will automate the setup and download steps '
                   'required to prepare the environment for manual '
                   'ansible execution.')
        )
        parser.add_argument(
            '--config-dir',
            dest='config_dir',
            default=os.path.join(
                constants.CLOUD_HOME_DIR,
                'tripleo-config'
            ),
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
        parser.add_argument('-b', '--baremetal-deployment',
                            metavar='<baremetal_deployment.yaml>',
                            help=_('Configuration file describing the '
                                   'baremetal deployment'))
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
            default='installed',
            choices=['system', 'pod', 'container', 'native'],
            help=_('The type of Heat process to use to execute '
                   'the deployment.\n'
                   'installed (Default): Use the system installed '
                   'Heat.\n'
                   'pod: Use an ephemeral Heat pod.\n'
                   'container: Use an ephemeral Heat container.\n'
                   'native: Use an ephemeral Heat process.')
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
        return parser

    def take_action(self, parsed_args):
        logging.register_options(CONF)
        logging.setup(CONF, '')
        self.log.debug("take_action(%s)" % parsed_args)

        if not parsed_args.working_dir:
            self.working_dir = utils.get_default_working_dir(
                parsed_args.stack)
        else:
            self.working_dir = parsed_args.working_dir
        utils.makedirs(self.working_dir)

        if parsed_args.update_plan_only:
            raise exceptions.DeploymentError(
                'Only plan update is not supported.')

        deploy_status = 'DEPLOY_SUCCESS'
        deploy_message = 'without error'

        self._setup_clients(parsed_args)

        # Swiftclient logs things like 404s at error level, which is a problem
        # because we use EAFP to check for the existence of files.  Turn off
        # most swiftclient logging to avoid cluttering up our output with
        # pointless tracebacks.
        sc_logger = logging.getLogger("swiftclient")
        sc_logger.setLevel(logging.CRITICAL)

        self._validate_args(parsed_args)

        # Throw warning if deprecated service is enabled and
        # ask user if deployment should still be continued.
        if parsed_args.environment_files:
            utils.check_deprecated_service_is_enabled(
                parsed_args.environment_files)

        self._update_args_from_answers_file(parsed_args)

        if parsed_args.dry_run:
            self.log.info("Validation Finished")
            return

        self.heat_launcher = None
        stack = None
        stack_create = None
        start = time.time()

        if parsed_args.heat_type == 'installed':
            stack = utils.get_stack(self.orchestration_client,
                                    parsed_args.stack)

            stack_create = stack is None
            if stack_create:
                self.log.info("No stack found, "
                              "will be doing a stack create")
            else:
                self.log.info("Stack found, "
                              "will be doing a stack update")

        new_tht_root, user_tht_root = \
            self.create_template_dirs(parsed_args)
        created_env_files = self.create_env_files(
                stack, parsed_args, new_tht_root, user_tht_root)

        try:
            if not (parsed_args.config_download_only or
                    parsed_args.setup_only):
                self.deploy_tripleo_heat_templates(
                    stack, parsed_args, new_tht_root,
                    user_tht_root, created_env_files)
        except Exception:
            if parsed_args.heat_type != 'installed' and self.heat_launcher:
                self.log.info("Stopping ephemeral heat.")
                utils.kill_heat(self.heat_launcher)
                utils.rm_heat(self.heat_launcher, backup_db=True)
            raise

        # Get a new copy of the stack after stack update/create. If it was
        # a create then the previous stack object would be None.
        stack = utils.get_stack(self.orchestration_client, parsed_args.stack)

        overcloud_endpoint = None
        old_rcpath = None
        rcpath = None
        horizon_url = None

        try:
            # Force fetching of attributes
            stack.get()
            overcloud_endpoint = utils.get_overcloud_endpoint(stack)
            horizon_url = deployment.get_horizon_url(
                stack=stack.stack_name,
                heat_type=parsed_args.heat_type,
                working_dir=self.working_dir)
            rc_params = utils.get_rc_params(
                self.orchestration_client,
                parsed_args.stack)

            # For backwards compatibility, we will also write overcloudrc to
            # $HOME and then self.working_dir.
            old_rcpath = deployment.create_overcloudrc(
                stack, rc_params, parsed_args.no_proxy)
            rcpath = deployment.create_overcloudrc(
                stack, rc_params, parsed_args.no_proxy,
                self.working_dir)

            config_download_dir = parsed_args.output_dir or \
                os.path.join(self.working_dir, "config-download")

            if parsed_args.config_download or parsed_args.setup_only:
                self.log.info("Deploying overcloud configuration")
                deployment.set_deployment_status(
                    stack.stack_name,
                    status='DEPLOYING',
                    working_dir=self.working_dir
                )

                if not parsed_args.config_download_only and \
                   not parsed_args.setup_only:
                    deployment.get_hosts_and_enable_ssh_admin(
                        stack,
                        parsed_args.overcloud_ssh_network,
                        parsed_args.overcloud_ssh_user,
                        self.get_key_pair(parsed_args),
                        parsed_args.overcloud_ssh_port_timeout,
                        verbosity=utils.playbook_verbosity(self=self),
                        heat_type=parsed_args.heat_type
                    )

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
                    stack,
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
                    setup_only=parsed_args.setup_only
                )

                if parsed_args.setup_only:
                    # Download config
                    config_dir = os.path.abspath(parsed_args.config_dir)
                    config_type = parsed_args.config_type
                    preserve_config_dir = parsed_args.preserve_config_dir
                    extra_vars = {
                        'plan': stack.stack_name,
                        'config_dir': config_dir,
                        'preserve_config': preserve_config_dir
                    }
                    if parsed_args.config_type:
                        extra_vars['config_type'] = config_type

                    with utils.TempDirs() as tmp:
                        utils.run_ansible_playbook(
                            playbook='cli-config-download-export.yaml',
                            inventory='localhost,',
                            workdir=tmp,
                            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                            verbosity=utils.playbook_verbosity(self=self),
                            extra_vars=extra_vars
                        )

                    # Run admin authorize
                    deployment.get_hosts_and_enable_ssh_admin(
                        stack,
                        parsed_args.overcloud_ssh_network,
                        parsed_args.overcloud_ssh_user,
                        self.get_key_pair(parsed_args),
                        parsed_args.overcloud_ssh_port_timeout,
                        verbosity=utils.playbook_verbosity(self=self),
                        heat_type=parsed_args.heat_type
                    )

                deployment.set_deployment_status(
                    stack.stack_name,
                    status=deploy_status,
                    working_dir=self.working_dir)
        except Exception as deploy_e:
            deploy_status = 'DEPLOY_FAILED'
            deploy_message = 'with error'
            deploy_trace = deploy_e
            deployment.set_deployment_status(
                stack.stack_name,
                status=deploy_status,
                working_dir=self.working_dir
            )
        finally:
            try:
                # Run postconfig on create or force
                if (stack_create or parsed_args.force_postconfig
                        and not parsed_args.skip_postconfig):
                    self._deploy_postconfig(stack, parsed_args)
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
                if (parsed_args.heat_type != 'installed' and
                        parsed_args.config_download):
                    # Create overcloud export
                    data = utils.export_overcloud(
                        self.orchestration_client,
                        parsed_args.stack, True, False,
                        config_download_dir)
                    export_file = os.path.join(
                        self.working_dir, "%s-export.yaml" % parsed_args.stack)
                    # write the exported data
                    with open(export_file, 'w') as f:
                        yaml.safe_dump(data, f, default_flow_style=False)
                        os.chmod(export_file, 0o600)
            except Exception as e:
                self.log.error('Exception creating overcloud export.')
                self.log.error(e)

            print("Overcloud Endpoint: {0}".format(overcloud_endpoint))
            print("Overcloud Horizon Dashboard URL: {0}".format(horizon_url))
            print("Overcloud rc file: {} and {}".format(
                rcpath, old_rcpath))
            print("Overcloud Deployed {0}".format(deploy_message))

            try:
                if parsed_args.heat_type != 'installed':
                    self.log.info("Stopping ephemeral heat.")
                    utils.kill_heat(self.heat_launcher)
                    utils.rm_heat(self.heat_launcher, backup_db=True)
            except Exception as e:
                self.log.error('Exception stopping ephemeral Heat')
                self.log.error(e)

            try:
                if parsed_args.output_dir:
                    ansible_dir = config_download_dir
                else:
                    ansible_dir = None
                utils.archive_deploy_artifacts(self.log, parsed_args.stack,
                                               self.working_dir, ansible_dir)
            except Exception as e:
                self.log.error('Exception archiving deploy artifacts')
                self.log.error(e)

            if deploy_status == 'DEPLOY_FAILED':
                raise(deploy_trace)


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
            self.log.info('No deployment was found for %s' % stack)
            return

        table = PrettyTable(
            ['Stack Name', 'Deployment Status'])
        table.add_row([stack, status])
        print(table, file=self.app.stdout)
