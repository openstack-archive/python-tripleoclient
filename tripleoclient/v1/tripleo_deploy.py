#   Copyright 2016 Red Hat, Inc.
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
import logging
import netaddr
import os
import pwd
import re
import shutil
import six
import sys
import tarfile
import tempfile
import traceback
import yaml

from cliff import command
from datetime import datetime
from heatclient.common import event_utils
from heatclient.common import template_utils
from openstackclient.i18n import _
from six.moves import configparser

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import heat_launcher
from tripleoclient import utils

from tripleo_common.image import kolla_builder
from tripleo_common.utils import passwords as password_utils

# For ansible download
from tripleo_common.inventory import TripleoInventory
from tripleo_common.utils import config

VIP_CIDR_PREFIX_LEN = 32
DEPLOY_FAILURE_MESSAGE = """
##########################################################
containerized undercloud deployment failed.

ERROR: Heat log files: {0}

See the previous output for details about what went wrong.

##########################################################
"""
DEPLOY_COMPLETION_MESSAGE = """
########################################################
containerized undercloud deployment complete.

Useful files:

Password file is at {0}
The stackrc file is at {1}

Use these files to interact with OpenStack services, and
ensure they are secured.

########################################################
"""


class Deploy(command.Command):
    """Deploy containerized Undercloud"""

    log = logging.getLogger(__name__ + ".Deploy")
    auth_required = False
    heat_pid = None
    tht_render = None
    output_dir = None
    tmp_env_file_name = None
    tmp_ansible_dir = None

    def _get_tar_filename(self):
        """Return tarball name for the install artifacts"""
        return '%s/undercloud-install-%s.tar.bzip2' % \
               (self.output_dir,
                datetime.utcnow().strftime('%Y%m%d%H%M%S'))

    def _create_install_artifact(self):
        """Create a tarball of the temporary folders used"""
        self.log.debug("Preserving deployment artifacts")

        def remove_output_dir(info):
            """Tar filter to remove output dir from path"""
            # leading path to tar is home/stack/ rather than /home/stack
            leading_path = self.output_dir[1:] + '/'
            info.name = info.name.replace(leading_path, '')
            return info

        # tar up working data and put in
        # output_dir/undercloud-install-TS.tar.bzip2
        tar_filename = self._get_tar_filename()
        try:
            tf = tarfile.open(tar_filename, 'w:bz2')
            tf.add(self.tht_render, recursive=True, filter=remove_output_dir)
            if self.tmp_env_file_name:
                tf.add(self.tmp_env_file_name, filter=remove_output_dir)
            tf.add(self.tmp_ansible_dir, recursive=True,
                   filter=remove_output_dir)
            tf.close()
        except Exception as ex:
            self.log.error("Unable to create artifact tarball, %s"
                           % ex.message)
        return tar_filename

    def _create_working_dirs(self):
        """Creates temporary working directories"""
        if self.output_dir and not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)
        if self.tht_render and not os.path.exists(self.tht_render):
            os.mkdir(self.tht_render)
        if not self.tmp_ansible_dir:
            self.tmp_ansible_dir = tempfile.mkdtemp(
                prefix='undercloud-ansible-', dir=self.output_dir)

    def _cleanup_working_dirs(self, cleanup=False):
        """Cleanup temporary working directories

        :param cleanup: Set to true if you DO want to cleanup the dirs
        """
        if cleanup:
            if self.tht_render and os.path.exists(self.tht_render):
                shutil.rmtree(self.tht_render, ignore_errors=True)

            self.tht_render = None
            if self.tmp_env_file_name:
                try:
                    os.remove(self.tmp_env_file_name)
                    self.tmp_env_file_name = None
                except Exception as ex:
                    if 'No such file or directory' in six.text_type(ex):
                        pass
            if self.tmp_ansible_dir and os.path.exists(self.tmp_ansible_dir):
                shutil.rmtree(self.tmp_ansible_dir)
                self.tmp_ansible_dir = None
        else:
            self.log.warning("Not cleaning working directory %s"
                             % self.tht_render)
            self.log.warning("Not removing temporary environment file %s"
                             % self.tmp_env_file_name)
            self.log.warning("Not cleaning ansible directory %s"
                             % self.tmp_ansible_dir)

    def _configure_puppet(self):
        self.log.info('Configuring puppet modules symlinks ...')
        utils.bulk_symlink(self.log, constants.TRIPLEO_PUPPET_MODULES,
                           constants.PUPPET_MODULES,
                           constants.PUPPET_BASE)

    def _update_passwords_env(self, output_dir, passwords=None):
        pw_file = os.path.join(output_dir, 'tripleo-undercloud-passwords.yaml')
        undercloud_pw_file = os.path.join(output_dir,
                                          'undercloud-passwords.conf')
        stack_env = {'parameter_defaults': {}}

        # Getting passwords that were managed by instack-undercloud so
        # we can upgrade to a containerized undercloud and keep old passwords.
        legacy_env = {}
        if os.path.exists(undercloud_pw_file):
            config = configparser.ConfigParser()
            config.read(undercloud_pw_file)
            for k, v in config.items('auth'):
                # Manage exceptions
                if k == 'undercloud_db_password':
                    k = 'MysqlRootPassword'
                elif k == 'undercloud_rabbit_username':
                    k = 'RabbitUserName'
                elif k == 'undercloud_heat_encryption_key':
                    k = 'HeatAuthEncryptionKey'
                else:
                    k = ''.join(i.capitalize() for i in k.split('_')[1:])
                legacy_env[k] = v

        if os.path.exists(pw_file):
            with open(pw_file) as pf:
                stack_env = yaml.safe_load(pf.read())

        pw = password_utils.generate_passwords(stack_env=stack_env)
        stack_env['parameter_defaults'].update(pw)
        # Override what has been generated by tripleo-common with old passwords
        # if any.
        stack_env['parameter_defaults'].update(legacy_env)

        if passwords:
            # These passwords are the DefaultPasswords so we only
            # update if they don't already exist in stack_env
            for p, v in passwords.items():
                if p not in stack_env['parameter_defaults']:
                    stack_env['parameter_defaults'][p] = v

        # Write out the password file in yaml for heat.
        # This contains sensitive data so ensure it's not world-readable
        with open(pw_file, 'w') as pf:
            yaml.safe_dump(stack_env, pf, default_flow_style=False)
        # Using chmod here instead of permissions on the open above so we don't
        # have to fight with umask.
        os.chmod(pw_file, 0o600)
        # Write out an instack undercloud compatible version.
        # This contains sensitive data so ensure it's not world-readable
        with open(undercloud_pw_file, 'w') as pf:
            pf.write('[auth]\n')
            for p, v in stack_env['parameter_defaults'].items():
                if 'Password' in p or 'Token' in p or p.endswith('Kek'):
                    # Convert camelcase from heat templates into the underscore
                    # format used by instack undercloud.
                    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', p)
                    pw_key = re.sub('([a-z0-9])([A-Z])',
                                    r'\1_\2', s1).lower()
                    pf.write('undercloud_%s: %s\n' % (pw_key, v))
        os.chmod(undercloud_pw_file, 0o600)

        return pw_file

    def _generate_hosts_parameters(self, parsed_args, p_ip):
        hostname = utils.get_short_hostname()
        domain = parsed_args.local_domain

        data = {
            'CloudName': p_ip,
            'CloudDomain': domain,
            'CloudNameInternal': '%s.internalapi.%s' % (hostname, domain),
            'CloudNameStorage': '%s.storage.%s' % (hostname, domain),
            'CloudNameStorageManagement': ('%s.storagemgmt.%s'
                                           % (hostname, domain)),
            'CloudNameCtlplane': '%s.ctlplane.%s' % (hostname, domain),
        }
        return data

    def _generate_portmap_parameters(self, ip_addr, cidr_prefixlen,
                                     ctlplane_vip_addr, public_vip_addr):
        hostname = utils.get_short_hostname()

        data = {
            'ControlPlaneSubnetCidr': '%s' % cidr_prefixlen,
            'HostnameMap': {
                'undercloud-undercloud-0': '%s' % hostname
            },
            # The settings below allow us to inject a custom public
            # VIP. This requires use of the generated
            # ../network/ports/external_from_pool.yaml resource in t-h-t.
            'IPPool': {
                'external': [public_vip_addr]
            },
            'ExternalNetCidr': '%s/%s' % (public_vip_addr, cidr_prefixlen),
            # This requires use of the
            # ../deployed-server/deployed-neutron-port.yaml resource in t-h-t
            # We use this for the control plane VIP and also via
            # the environments/deployed-server-noop-ctlplane.yaml
            # for the server IP itself
            'DeployedServerPortMap': {
                ('%s-ctlplane' % hostname): {
                    'fixed_ips': [{'ip_address': ip_addr}],
                    'subnets': [{'cidr': cidr_prefixlen}]
                },
                'control_virtual_ip': {
                    'fixed_ips': [{'ip_address': ctlplane_vip_addr}],
                    'subnets': [{'cidr': VIP_CIDR_PREFIX_LEN}]
                },
                'public_virtual_ip': {
                    'fixed_ips': [{'ip_address': public_vip_addr}],
                    'subnets': [{'cidr': VIP_CIDR_PREFIX_LEN}]
                }
            }
        }
        return data

    def _kill_heat(self, parsed_args):
        """Tear down heat installer and temp files

        Kill the heat launcher/installer process.
        Teardown temp files created in the deployment process,
        when cleanup is requested.

        """
        if self.heat_pid:
            self.heat_launch.kill_heat(self.heat_pid)
            pid, ret = os.waitpid(self.heat_pid, 0)
            self.heat_pid = None

    def _launch_heat(self, parsed_args):
        # we do this as root to chown config files properly for docker, etc.
        if parsed_args.heat_native:
            self.heat_launch = heat_launcher.HeatNativeLauncher(
                parsed_args.heat_api_port,
                parsed_args.heat_container_image,
                parsed_args.heat_user)
        else:
            self.heat_launch = heat_launcher.HeatDockerLauncher(
                parsed_args.heat_api_port,
                parsed_args.heat_container_image,
                parsed_args.heat_user)

        # NOTE(dprince): we launch heat with fork exec because
        # we don't want it to inherit our args. Launching heat
        # as a "library" would be cool... but that would require
        # more refactoring. It runs a single process and we kill
        # it always below.
        self.heat_pid = os.fork()
        if self.heat_pid == 0:
            if parsed_args.heat_native:
                try:
                    uid = pwd.getpwnam(parsed_args.heat_user).pw_uid
                    gid = pwd.getpwnam(parsed_args.heat_user).pw_gid
                except KeyError:
                    raise exceptions.DeploymentError(
                        "Please create a %s user account before "
                        "proceeding." % parsed_args.heat_user)
                os.setgid(gid)
                os.setuid(uid)
            self.heat_launch.heat_db_sync()
            # Exec() never returns.
            self.heat_launch.launch_heat()

        # NOTE(dprince): we use our own client here because we set
        # auth_required=False above because keystone isn't running when this
        # command starts
        tripleoclients = self.app.client_manager.tripleoclient
        orchestration_client = \
            tripleoclients.local_orchestration(parsed_args.heat_api_port)

        return orchestration_client

    def _setup_heat_environments(self, parsed_args):
        """Process tripleo heat templates with jinja and deploy into work dir

        * Copy --templates content into a working dir
          created as 'output_dir/tripleo-heat-installer-templates'.
        * Process j2/install additional templates there
        * Return the environments list for futher processing as a new base.

        The first two items are reserved for the
        overcloud-resource-registry-puppet.yaml and passwords files.
        """

        self.tht_render = os.path.join(parsed_args.output_dir,
                                       'tripleo-heat-installer-templates')
        # The target should not exist, bear in mind consequent deploys.
        shutil.rmtree(self.tht_render, ignore_errors=True)
        shutil.copytree(parsed_args.templates, self.tht_render, symlinks=True)

        # generate jinja templates by its work dir location
        self.log.debug("Using roles file %s" % parsed_args.roles_file)
        process_templates = os.path.join(parsed_args.templates,
                                         'tools/process-templates.py')
        args = ['python', process_templates, '--roles-data',
                parsed_args.roles_file, '--output-dir', self.tht_render]
        if utils.run_command_and_log(self.log, args, cwd=self.tht_render) != 0:
            # TODO(aschultz): improve error messaging
            raise exceptions.DeploymentError("Problems generating templates.")

        self.log.info("Deploying templates in the directory {0}".format(
                      os.path.abspath(self.tht_render)))

        self.log.warning("** Creating Environment file **")
        environments = []

        resource_registry_path = os.path.join(
            self.tht_render, 'overcloud-resource-registry-puppet.yaml')
        environments.insert(0, resource_registry_path)

        # this will allow the user to overwrite passwords with custom envs
        pw_file = self._update_passwords_env(self.output_dir)
        environments.insert(1, pw_file)

        undercloud_env_path = os.path.join(
            self.tht_render, 'environments', 'undercloud.yaml')
        environments.append(undercloud_env_path)

        # use deployed-server because we run os-collect-config locally
        deployed_server_env = os.path.join(
            self.tht_render, 'environments',
            'config-download-environment.yaml')
        environments.append(deployed_server_env)

        # use deployed-server because we run os-collect-config locally
        deployed_server_env = os.path.join(
            self.tht_render, 'environments',
            'deployed-server-noop-ctlplane.yaml')
        environments.append(deployed_server_env)

        if parsed_args.environment_files:
            environments.extend(parsed_args.environment_files)

        with tempfile.NamedTemporaryFile(delete=False) as tmp_env_file:
            self.tmp_env_file_name = tmp_env_file.name

            ip_nw = netaddr.IPNetwork(parsed_args.local_ip)
            ip = str(ip_nw.ip)
            cidr_prefixlen = ip_nw.prefixlen

            if parsed_args.control_virtual_ip:
                c_ip = parsed_args.control_virtual_ip
            else:
                c_ip = ip

            if parsed_args.public_virtual_ip:
                p_ip = parsed_args.public_virtual_ip
            else:
                p_ip = ip

            tmp_env = self._generate_hosts_parameters(parsed_args, p_ip)
            tmp_env.update(self._generate_portmap_parameters(
                ip, cidr_prefixlen, c_ip, p_ip))

            with open(self.tmp_env_file_name, 'w') as env_file:
                yaml.safe_dump({'parameter_defaults': tmp_env}, env_file,
                               default_flow_style=False)
            environments.append(self.tmp_env_file_name)

        if parsed_args.hieradata_override:
            environments.append(self._process_hieradata_overrides(
                parsed_args.hieradata_override))

        return environments

    def _prepare_container_images(self, env, roles_file):
        if roles_file:
            with open(roles_file) as f:
                roles_data = yaml.safe_load(f)
        else:
            roles_data = None
        image_params = kolla_builder.container_images_prepare_multi(
            env, roles_data)

        # use setdefault to ensure every needed image parameter is
        # populated without replacing user-set values
        if image_params:
            pd = env.get('parameter_defaults', {})
            for k, v in image_params.items():
                pd.setdefault(k, v)

    def _deploy_tripleo_heat_templates(self, orchestration_client,
                                       parsed_args):
        """Deploy the fixed templates in TripleO Heat Templates"""

        # sets self.tht_render to the working dir with deployed templates
        environments = self._setup_heat_environments(parsed_args)

        # rewrite paths to consume t-h-t env files from the working dir
        self.log.debug("Processing environment files %s" % environments)
        env_files, env = utils.process_multiple_environments(
            environments, self.tht_render, parsed_args.templates,
            cleanup=parsed_args.cleanup)

        roles_file = os.path.join(
            self.tht_render, parsed_args.roles_file)
        self._prepare_container_images(env, roles_file)

        self.log.debug("Getting template contents")
        template_path = os.path.join(self.tht_render, 'overcloud.yaml')
        template_files, template = \
            template_utils.get_template_contents(template_path)

        files = dict(list(template_files.items()) + list(env_files.items()))

        stack_name = parsed_args.stack

        self.log.debug("Deploying stack: %s", stack_name)
        self.log.debug("Deploying template: %s", template)
        self.log.debug("Deploying environment: %s", env)
        self.log.debug("Deploying files: %s", files)

        stack_args = {
            'stack_name': stack_name,
            'template': template,
            'environment': env,
            'files': files,
        }

        if parsed_args.timeout:
            stack_args['timeout_mins'] = parsed_args.timeout

        self.log.warning("** Performing Heat stack create.. **")
        stack = orchestration_client.stacks.create(**stack_args)
        stack_id = stack['stack']['id']

        return "%s/%s" % (stack_name, stack_id)

    def _download_ansible_playbooks(self, client, stack_name):
        stack_config = config.Config(client)
        self._create_working_dirs()

        self.log.warning('** Downloading undercloud ansible.. **')
        # python output buffering is making this seem to take forever..
        sys.stdout.flush()
        stack_config.write_config(stack_config.fetch_config('undercloud'),
                                  'undercloud',
                                  self.tmp_ansible_dir)

        inventory = TripleoInventory(
            hclient=client,
            plan_name=stack_name,
            ansible_ssh_user='root')

        inv_path = os.path.join(self.tmp_ansible_dir, 'inventory.yaml')
        extra_vars = {'Undercloud': {'ansible_connection': 'local'}}
        inventory.write_static_inventory(inv_path, extra_vars)

        self.log.info('** Downloaded undercloud ansible to %s **' %
                      self.tmp_ansible_dir)
        sys.stdout.flush()
        return self.tmp_ansible_dir

    # Never returns, calls exec()
    def _launch_ansible_deploy(self, ansible_dir):
        self.log.warning('** Running ansible deploy tasks **')
        os.chdir(ansible_dir)
        playbook_inventory = os.path.join(ansible_dir, 'inventory.yaml')
        cmd = ['ansible-playbook', '-i', playbook_inventory,
               'deploy_steps_playbook.yaml', '-e', 'role_name=Undercloud',
               '-e', 'tripleo_role_name=Undercloud',
               '-e', 'deploy_server_id=undercloud', '-e',
               'bootstrap_server_id=undercloud']
        self.log.debug('Running Ansible Deploy tasks: %s' % (' '.join(cmd)))
        return utils.run_command_and_log(self.log, cmd)

    def _launch_ansible_upgrade(self, ansible_dir):
        self.log.warning('** Running ansible upgrade tasks **')
        os.chdir(ansible_dir)
        playbook_inventory = os.path.join(ansible_dir, 'inventory.yaml')
        cmd = ['ansible-playbook', '-i', playbook_inventory,
               'upgrade_steps_playbook.yaml', '-e', 'role_name=Undercloud',
               '-e', 'tripleo_role_name=Undercloud',
               '-e', 'deploy_server_id=undercloud', '-e',
               'bootstrap_server_id=undercloud', '--skip-tags', 'validation']
        self.log.debug('Running Ansible Upgrade tasks: %s' % (' '.join(cmd)))
        return utils.run_command_and_log(self.log, cmd)

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False
        )
        parser.add_argument(
            '--templates', nargs='?', const=constants.TRIPLEO_HEAT_TEMPLATES,
            help=_("The directory containing the Heat templates to deploy"),
        )
        parser.add_argument('--standalone', default=False, action='store_true',
                            help=_("Run deployment as a standalone deployment "
                                   "with no undercloud."))
        parser.add_argument('--upgrade', default=False, action='store_true',
                            help=_("Upgrade an existing deployment."))
        parser.add_argument('--stack',
                            help=_("Stack name to create"),
                            default='undercloud')
        parser.add_argument('--output-dir',
                            dest='output_dir',
                            help=_("Directory to output state, processed heat "
                                   "templates, ansible deployment files."),
                            default=constants.UNDERCLOUD_OUTPUT_DIR)
        parser.add_argument('--output-only',
                            dest='output_only',
                            action='store_true',
                            default=False,
                            help=_("Do not execute the Ansible playbooks. By"
                                   " default the playbooks are saved to the"
                                   " output-dir and then executed.")),
        parser.add_argument('-t', '--timeout', metavar='<TIMEOUT>',
                            type=int, default=30,
                            help=_('Deployment timeout in minutes.'))
        parser.add_argument(
            '-e', '--environment-file', metavar='<HEAT ENVIRONMENT FILE>',
            action='append', dest='environment_files',
            help=_('Environment files to be passed to the heat stack-create '
                   'or heat stack-update command. (Can be specified more than '
                   'once.)')
        )
        parser.add_argument(
            '--roles-file', '-r', dest='roles_file',
            help=_('Roles file, overrides the default %s in the --templates '
                   'directory') % constants.UNDERCLOUD_ROLES_FILE,
            default=constants.UNDERCLOUD_ROLES_FILE
        )
        parser.add_argument(
            '--heat-api-port', metavar='<HEAT_API_PORT>',
            dest='heat_api_port',
            default='8006',
            help=_('Heat API port to use for the installers private'
                   ' Heat API instance. Optional. Default: 8006.)')
        )
        parser.add_argument(
            '--heat-user', metavar='<HEAT_USER>',
            dest='heat_user',
            default='heat',
            help=_('User to execute the non-priveleged heat-all process. '
                   'Defaults to heat.')
        )
        parser.add_argument(
            '--heat-container-image', metavar='<HEAT_CONTAINER_IMAGE>',
            dest='heat_container_image',
            default='tripleomaster/centos-binary-heat-all',
            help=_('The container image to use when launching the heat-all '
                   'process. Defaults to: '
                   'tripleomaster/centos-binary-heat-all')
        )
        parser.add_argument(
            '--heat-native',
            action='store_true',
            default=True,
            help=_('Execute the heat-all process natively on this host. '
                   'This option requires that the heat-all binaries '
                   'be installed locally on this machine. '
                   'This option is enabled by default which means heat-all is '
                   'executed on the host OS directly.')
        )
        parser.add_argument(
            '--local-ip', metavar='<LOCAL_IP>',
            dest='local_ip',
            help=_('Local IP/CIDR for undercloud traffic. Required.')
        )
        parser.add_argument(
            '--control-virtual-ip', metavar='<CONTROL_VIRTUAL_IP>',
            dest='control_virtual_ip',
            help=_('Control plane VIP. This allows the undercloud installer '
                   'to configure a custom VIP on the control plane.')
        )
        parser.add_argument(
            '--public-virtual-ip', metavar='<PUBLIC_VIRTUAL_IP>',
            dest='public_virtual_ip',
            help=_('Public nw VIP. This allows the undercloud installer '
                   'to configure a custom VIP on the public (external) NW.')
        )
        parser.add_argument(
            '--local-domain', metavar='<LOCAL_DOMAIN>',
            dest='local_domain',
            default='undercloud',
            help=_('Local domain for undercloud and its API endpoints')
        )
        parser.add_argument(
            '--cleanup',
            action='store_true', default=False,
            help=_('Cleanup temporary files. Using this flag will '
                   'remove the temporary files used during deployment in '
                   'after the command is run.'),

        )
        parser.add_argument(
            '--hieradata-override', nargs='?',
            help=_('Path to hieradata override file. When it points to a heat '
                   'env file, it is passed in t-h-t via --environment-file. '
                   'When the file contains legacy instack data, '
                   'it is wrapped with UndercloudExtraConfig and also '
                   'passed in for t-h-t as a temp file created in '
                   '--output-dir. Note, instack hiera data may be '
                   'not t-h-t compatible and will highly likely require a '
                   'manual revision.')
        )
        return parser

    def _process_hieradata_overrides(self, override_file=None):
        """Count in hiera data overrides including legacy formats

        Return a file name that points to processed hiera data overrides file
        """
        if not override_file or not os.path.exists(override_file):
            # we should never get here because there's a check in
            # undercloud_conf but stranger things have happened.
            msg = 'hieradata_override file could not be found %s' %\
                  override_file
            self.log.error(msg)
            raise exceptions.DeploymentError(msg)

        target = override_file
        data = open(target, 'r').read()
        hiera_data = yaml.safe_load(data)
        if not hiera_data:
            msg = 'Unsupported data format in hieradata override %s' % target
            self.log.error(msg)
            raise exceptions.DeploymentError(msg)
        self._create_working_dirs()

        # NOTE(bogdando): In t-h-t, hiera data should come in wrapped as
        # {parameter_defaults: {UndercloudExtraConfig: ... }}
        if ('UndercloudExtraConfig' not in hiera_data.get('parameter_defaults',
                                                          {})):
            hiera_override_file = os.path.join(
                self.tht_render, 'tripleo-hieradata-override.yaml')
            self.log.info('Converting hiera overrides for t-h-t from '
                          'legacy format into a file %s' %
                          hiera_override_file)
            yaml.safe_dump(
                {'parameter_defaults': {
                 'UndercloudExtraConfig': hiera_data}},
                hiera_override_file,
                default_flow_style=False)
            target = hiera_override_file
        return target

    def _standalone_deploy(self, parsed_args):
        if not parsed_args.local_ip:
            self.log.error('Please set --local-ip to the correct '
                           'ipaddress/cidr for this machine.')
            return

        if not os.environ.get('HEAT_API_PORT'):
            os.environ['HEAT_API_PORT'] = parsed_args.heat_api_port

        # The main thread runs as root and we drop privs for forked
        # processes below. Only the heat deploy/os-collect-config forked
        # process runs as root.
        if os.geteuid() != 0:
            raise exceptions.DeploymentError("Please run as root.")

        # prepare working spaces
        self.output_dir = os.path.abspath(parsed_args.output_dir)
        self._create_working_dirs()

        # configure puppet
        self._configure_puppet()

        rc = 1
        try:
            # Launch heat.
            orchestration_client = self._launch_heat(parsed_args)
            # Wait for heat to be ready.
            utils.wait_api_port_ready(parsed_args.heat_api_port)
            # Deploy TripleO Heat templates.
            stack_id = \
                self._deploy_tripleo_heat_templates(orchestration_client,
                                                    parsed_args)
            # Wait for complete..
            status, msg = event_utils.poll_for_events(
                orchestration_client, stack_id, nested_depth=6)
            if status != "CREATE_COMPLETE":
                raise Exception("Stack create failed; %s" % msg)

            # download the ansible playbooks and execute them.
            ansible_dir = \
                self._download_ansible_playbooks(orchestration_client,
                                                 parsed_args.stack)
            # Kill heat, we're done with it now.
            self._kill_heat(parsed_args)
            if not parsed_args.output_only:
                # Run Upgrade tasks before the deployment
                if parsed_args.upgrade:
                    rc = self._launch_ansible_upgrade(ansible_dir)
                rc = self._launch_ansible_deploy(ansible_dir)
        except Exception as e:
            self.log.error("Exception: %s" % e)
            self.log.error(traceback.format_exception(*sys.exc_info()))
            raise
        finally:
            self._kill_heat(parsed_args)
            tar_filename = self._create_install_artifact()
            self._cleanup_working_dirs(cleanup=parsed_args.cleanup)
            if tar_filename:
                self.log.warning('Install artifact is located at %s' %
                                 tar_filename)
            if not parsed_args.output_only and rc != 0:
                # We only get here on error.
                self.log.error(DEPLOY_FAILURE_MESSAGE.format(
                    self.heat_launch.install_tmp
                    ))
            else:
                self.log.warning(DEPLOY_COMPLETION_MESSAGE.format(
                    '~/undercloud-passwords.conf',
                    '~/stackrc'
                    ))
            return rc

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if parsed_args.standalone:
            if self._standalone_deploy(parsed_args) != 0:
                raise exceptions.DeploymentError('Deployment failed.')
        else:
            raise exceptions.DeploymentError('Non-standalone is currently not '
                                             'supported')
