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
import json
import logging
import netaddr
import os
import pwd
import re
import shutil
import six
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import yaml

from cliff import command
from datetime import datetime
from heatclient.common import event_utils
from heatclient.common import template_utils
from osc_lib.i18n import _
from six.moves import configparser

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import heat_launcher
from tripleoclient import utils

from tripleo_common import constants as tc_constants
from tripleo_common.image import kolla_builder
from tripleo_common.utils import passwords as password_utils

# For ansible download and config generation
from tripleo_common.actions import ansible
from tripleo_common.inventory import TripleoInventory
from tripleo_common.utils import config

DEPLOY_FAILURE_MESSAGE = """
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Deployment Failed!

ERROR: Heat log files: {0}

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
"""
DEPLOY_COMPLETION_MESSAGE = """
########################################################

Deployment successful!

########################################################
"""
OUTPUT_ONLY_COMPLETION_MESSAGE = """
########################################################

Deployment information successfully generated!

########################################################
"""
STANDALONE_COMPLETION_MESSAGE = """
##########################################################

Useful files:

The clouds.yaml file is at {0}

Use "export OS_CLOUD=standalone" before running the
openstack command.

##########################################################
"""


class Deploy(command.Command):
    """Deploy containerized Undercloud"""

    log = logging.getLogger(__name__ + ".Deploy")
    auth_required = False
    heat_pid = None
    tht_render = None
    output_dir = None
    tmp_ansible_dir = None
    stack_update_mark = None
    stack_action = 'CREATE'
    deployment_user = None
    ansible_dir = None
    python_version = sys.version_info[0]
    ansible_playbook_cmd = "ansible-playbook-{}".format(python_version)
    python_cmd = "python{}".format(python_version)

    def _is_undercloud_deploy(self, parsed_args):
        return parsed_args.standalone_role == 'Undercloud' and \
            parsed_args.stack == 'undercloud'

    def _run_preflight_checks(self, parsed_args):
        """Run preflight deployment checks

        Perform any pre-deployment checks that we want to run when deploying
        standalone deployments. This is skipped when in output only mode or
        when used with an undercloud. The undercloud has it's own set of
        deployment preflight requirements.

        :param parsed_args: parsed arguments from the cli
        """
        # we skip preflight checks for output only and undercloud
        if parsed_args.output_only or self._is_undercloud_deploy(parsed_args):
            return

        # in standalone we don't want to fixup the /etc/hosts as we'll be
        # managing that elsewhere during the deployment
        utils.check_hostname(fix_etc_hosts=False, logger=self.log)

        # Users can use http_proxy and https_proxy as part of the deployment,
        # however we need localhost to not be proxied because we use it to talk
        # to our heat api.
        utils.check_env_for_proxy(no_proxy_hosts=['127.0.0.1'])

    # NOTE(cjeanner) Quick'n'dirty way before we have proper
    # escalation support through oslo.privsep
    def _set_data_rights(self, file_name, user=None,
                         mode=0o600):

        u = user or self.deployment_user
        u_flag = None
        f_flag = None
        if u:
            if os.path.exists(file_name):
                try:
                    pwd.getpwnam(u)
                    cmd = 'sudo chown -R %s %s' % (u, file_name)
                    subprocess.check_call(cmd.split())
                except KeyError:
                    u_flag = 'Unknown'
            else:
                f_flag = "Absent"
        else:
            u_flag = 'Undefined'

        if u_flag:
            self.log.warning(_('%(u_f)s user "%(u)s". You might need to '
                             'manually set ownership after the deploy')
                             % {'u_f': u_flag, 'u': user})
        if f_flag:
            self.log.warning(_('%(f)s file is %(f_f)s.')
                             % {'f': file_name, 'f_f': f_flag})
        else:
            os.chmod(file_name, mode)

    def _set_stack_action(self, parsed_args):
        """Set the stack action for deployment"""
        # Prepare the heat stack action we want to start deployment with
        if ((os.path.isfile(self.stack_update_mark) or
           parsed_args.force_stack_update) and
           not parsed_args.force_stack_create):
            self.stack_action = 'UPDATE'

        self.log.warning(
            _('The heat stack {0} action is {1}').format(
                parsed_args.stack, self.stack_action))

    def _get_roles_file_path(self, parsed_args):
        """Return roles_file for the deployment"""
        if not parsed_args.roles_file:
            roles_file = os.path.join(parsed_args.templates,
                                      constants.UNDERCLOUD_ROLES_FILE)
        else:
            roles_file = parsed_args.roles_file
        return roles_file

    def _get_networks_file_path(self, parsed_args):
        """Return networks_file for the deployment"""
        if not parsed_args.networks_file:
            return os.path.join(parsed_args.templates,
                                constants.STANDALONE_NETWORKS_FILE)
        else:
            return parsed_args.networks_file

    def _get_plan_env_file_path(self, parsed_args):
        """Return plan_environment_file for the deployment"""
        if not parsed_args.plan_environment_file:
            plan_env = os.path.join(parsed_args.templates,
                                    constants.PLAN_ENVIRONMENT)
        else:
            plan_env = parsed_args.plan_environment_file
        return plan_env

    def _get_primary_role_name(self, roles_file_path, templates):
        """Return the primary role name"""
        roles_data = utils.fetch_roles_file(
            roles_file_path, templates)
        if not roles_data:
            # TODO(aschultz): should this be Undercloud instead?
            return 'Controller'

        for r in roles_data:
            if 'tags' in r and 'primary' in r['tags']:
                return r['name']
        self.log.warning('No primary role found in roles_data, using '
                         'first defined role')
        return roles_data[0]['name']

    def _get_tar_filename(self):
        """Return tarball name for the install artifacts"""
        return '%s/undercloud-install-%s.tar.bzip2' % \
               (self.output_dir,
                datetime.utcnow().strftime('%Y%m%d%H%M%S'))

    def _create_install_artifact(self, user):
        """Create a tarball of the temporary folders used"""
        self.log.debug(_("Preserving deployment artifacts"))

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
            tf.add(self.tmp_ansible_dir, recursive=True,
                   filter=remove_output_dir)
            tf.close()
        except Exception as ex:
            msg = _("Unable to create artifact tarball, %s") % ex.message
            self.log.error(msg)
            raise exceptions.DeploymentError(msg)
        # TODO(cjeanner) drop that once using oslo.privsep
        self._set_data_rights(tar_filename, user=user)
        return tar_filename

    def _create_persistent_dirs(self):
        """Creates temporary working directories"""
        if not os.path.exists(constants.STANDALONE_EPHEMERAL_STACK_VSTATE):
            os.mkdir(constants.STANDALONE_EPHEMERAL_STACK_VSTATE)

    def _create_working_dirs(self):
        """Creates temporary working directories"""
        if self.output_dir and not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)
        if not self.tht_render:
            self.tht_render = os.path.join(self.output_dir,
                                           'tripleo-heat-installer-templates')
            # Clear dir since we're using a static name and shutils.copytree
            # needs the folder to not exist. We'll generate the
            # contents each time. This should clear the folder on the first
            # run of this function.
            shutil.rmtree(self.tht_render, ignore_errors=True)
        if not self.tmp_ansible_dir:
            self.tmp_ansible_dir = tempfile.mkdtemp(
                prefix='undercloud-ansible-', dir=self.output_dir)

    def _populate_templates_dir(self, source_templates_dir):
        """Creates template dir with templates

        * Copy --templates content into a working dir
          created as 'output_dir/tripleo-heat-installer-templates'.

        :param source_templates_dir: string to a directory containing our
                                     source templates
        """
        self._create_working_dirs()
        if not os.path.exists(source_templates_dir):
            raise exceptions.NotFound("%s template director does not exists" %
                                      source_templates_dir)
        if not os.path.exists(self.tht_render):
            shutil.copytree(source_templates_dir, self.tht_render,
                            symlinks=True)

    def _set_default_plan(self):
        """Populate default plan-environment.yaml and capabilities-map.yaml."""
        if not os.path.isfile(os.path.join(self.tht_render,
                              'plan-environment.yaml')):
            shutil.copy(os.path.join(self.tht_render, 'plan-samples',
                        'openstack', 'plan-environment.yaml'), self.tht_render)
        if not os.path.isfile(os.path.join(self.tht_render,
                              'capabilities-map.yaml')):
            shutil.copy(os.path.join(self.tht_render, 'plan-samples',
                        'openstack', 'capabilities-map.yaml'), self.tht_render)

    def _cleanup_working_dirs(self, cleanup=False, user=None):
        """Cleanup temporary working directories

        :param cleanup: Set to true if you DO want to cleanup the dirs
        """
        if cleanup:
            if self.tht_render and os.path.exists(self.tht_render):
                shutil.rmtree(self.tht_render, ignore_errors=True)

            self.tht_render = None
            if self.tmp_ansible_dir and os.path.exists(self.tmp_ansible_dir):
                shutil.rmtree(self.tmp_ansible_dir)
                self.tmp_ansible_dir = None
        else:
            self.log.warning(_("Not cleaning working directory %s")
                             % self.tht_render)
            # TODO(cjeanner) drop that once using oslo.privsep
            self._set_data_rights(self.tht_render, user=user, mode=0o700)
            self.log.warning(_("Not cleaning ansible directory %s")
                             % self.tmp_ansible_dir)
            # TODO(cjeanner) drop that once using oslo.privsep
            self._set_data_rights(self.tmp_ansible_dir, user=user, mode=0o700)

    def _configure_puppet(self):
        self.log.info(_('Configuring puppet modules symlinks ...'))
        utils.bulk_symlink(self.log, constants.TRIPLEO_PUPPET_MODULES,
                           constants.PUPPET_MODULES,
                           constants.PUPPET_BASE)

    def _update_passwords_env(self, output_dir, user, upgrade=None,
                              passwords=None):
        pw_file = os.path.join(output_dir, 'tripleo-undercloud-passwords.yaml')
        undercloud_pw_file = os.path.join(output_dir,
                                          'undercloud-passwords.conf')

        # Generated passwords take the lowest precedence, allowing
        # custom overrides
        stack_env = {'parameter_defaults': {}}
        stack_env['parameter_defaults'] = password_utils.generate_passwords(
            stack_env=stack_env)
        if os.path.exists(pw_file):
            with open(pw_file) as pf:
                stack_env['parameter_defaults'].update(
                    yaml.safe_load(pf.read())['parameter_defaults'])

        if upgrade:
            # Getting passwords that were managed by instack-undercloud so
            # we can upgrade to a containerized undercloud and keep old
            # passwords.
            legacy_env = {}
            if os.path.exists(undercloud_pw_file):
                config = configparser.ConfigParser()
                config.read(undercloud_pw_file)
                for k, v in config.items('auth'):
                    # Manage exceptions
                    if k == 'undercloud_db_password':
                        k = 'MysqlRootPassword'
                    elif k == 'undercloud_rabbit_username':
                        k = 'RpcUserName'
                    elif k == 'undercloud_rabbit_password':
                        try:
                            # NOTE(aschultz): Only save rabbit password to rpc
                            # if it's not already defined for the upgrade case.
                            # The passwords are usually different so we don't
                            # want to overwrite it if it already exists because
                            # we'll end up rewriting the passwords later and
                            # causing problems.
                            config.get('auth', 'undercloud_rpc_password')
                        except Exception:
                            legacy_env['RpcPassword'] = v
                        k = 'RabbitPassword'
                    elif k == 'undercloud_rabbit_cookie':
                        k = 'RabbitCookie'
                    elif k == 'undercloud_heat_encryption_key':
                        k = 'HeatAuthEncryptionKey'
                    elif k == 'undercloud_libvirt_tls_password':
                        k = 'LibvirtTLSPassword'
                    elif k == 'undercloud_ha_proxy_stats_password':
                        k = 'HAProxyStatsPassword'
                    else:
                        k = ''.join(i.capitalize() for i in k.split('_')[1:])
                    legacy_env[k] = v

            # Get the keystone keys before upgrade
            keystone_fernet_repo = '/etc/keystone/fernet-keys/'
            keystone_credential_repo = '/etc/keystone/credential-keys/'
            self._set_data_rights('/etc/keystone', user=user)

            for key_index in range(0, 2):
                file_name = keystone_credential_repo + str(key_index)
                key = 'KeystoneCredential' + str(key_index)
                if os.path.exists(file_name):
                    with open(file_name, 'r') as file_content:
                        content = file_content.read()
                        legacy_env[key] = content

            fernet_keys = {}
            file_count = 0
            if os.path.exists(keystone_fernet_repo):
                file_count = len(os.listdir(keystone_fernet_repo))

            for key_index in range(0, file_count):
                file_name = keystone_fernet_repo + str(key_index)
                if os.path.exists(file_name):
                    with open(file_name, 'r') as file_content:
                        content = file_content.read()
                        fernet_keys[file_name] = {'content': content}
            if fernet_keys:
                legacy_env['KeystoneFernetKeys'] = fernet_keys

            # Override with picked legacy instack-undercloud values
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
        # TODO(cjeanner) drop that once using oslo.privsep
        # Do not forget to re-add os.chmod 0o600 on that one!
        self._set_data_rights(pw_file, user=user)
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

        # TODO(cjeanner) drop that once using oslo.privsep
        # Do not forget to re-add os.chmod 0o600 on that one!
        self._set_data_rights(undercloud_pw_file, user=user)

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

    def _generate_portmap_parameters(self, ip_addr, ip_nw, ctlplane_vip_addr,
                                     public_vip_addr, stack_name='Undercloud',
                                     role_name='Undercloud'):
        hostname = utils.get_short_hostname()

        # in order for deployed server network information to match correctly,
        # we need to ensure the HostnameMap matches our hostname
        hostname_map_name = "%s-%s-0" % (stack_name.lower(), role_name.lower())
        data = {
            'HostnameMap': {
                hostname_map_name: '%s' % hostname
            },
            # The settings below allow us to inject a custom public
            # VIP. This requires use of the generated
            # ../network/ports/external_from_pool.yaml resource in t-h-t.
            'IPPool': {
                'external': [public_vip_addr]
            },
            'ExternalNetCidr': '%s/%s' % (public_vip_addr, ip_nw.prefixlen),
            # This requires use of the
            # ../deployed-server/deployed-neutron-port.yaml resource in t-h-t
            # We use this for the control plane VIP and also via
            # the environments/deployed-server-noop-ctlplane.yaml
            # for the server IP itself
            'DeployedServerPortMap': {
                ('%s-ctlplane' % hostname): {
                    'fixed_ips': [{'ip_address': ip_addr}],
                    'subnets': [{'cidr': str(ip_nw)}],
                    'network': {'tags': [str(ip_nw)]}
                },
                'control_virtual_ip': {
                    'fixed_ips': [{'ip_address': ctlplane_vip_addr}],
                    'subnets': [{'cidr': str(ip_nw)}],
                    'network': {'tags': [str(ip_nw)]}
                },
                'public_virtual_ip': {
                    'fixed_ips': [{'ip_address': public_vip_addr}],
                    'subnets': [{'cidr': str(ip_nw)}],
                    'network': {'tags': [str(ip_nw)]}
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
        if parsed_args.heat_native is not None and \
                parsed_args.heat_native.lower() == "false":
            self.heat_launch = heat_launcher.HeatContainerLauncher(
                parsed_args.heat_api_port,
                parsed_args.heat_container_image,
                parsed_args.heat_user)
        else:
            self.heat_launch = heat_launcher.HeatNativeLauncher(
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
            if parsed_args.heat_native is not None and \
                    parsed_args.heat_native.lower() == "true":
                try:
                    uid = pwd.getpwnam(parsed_args.heat_user).pw_uid
                    gid = pwd.getpwnam(parsed_args.heat_user).pw_gid
                except KeyError:
                    msg = _(
                        "Please create a %s user account before "
                        "proceeding.") % parsed_args.heat_user
                    self.log.error(msg)
                    raise exceptions.DeploymentError(msg)
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

    def _normalize_user_templates(self, user_tht_root, tht_root, env_files=[]):
        """copy environment files into tht render path

        This assumes any env file that includes user_tht_root has already
        been copied into tht_root.

        :param user_tht_root: string path to the user's template dir
        :param tht_root: string path to our deployed tht_root
        :param env_files: list of paths to environment files
        :return list of absolute pathed environment files that exist in
                tht_root
        """
        environments = []
        # normalize the user template path to ensure it doesn't have a trailing
        # slash
        user_tht = os.path.abspath(user_tht_root)
        for env_path in env_files:
            self.log.debug("Processing file %s" % env_path)
            abs_env_path = os.path.abspath(env_path)
            if (abs_env_path.startswith(user_tht_root) and
                    ((user_tht + '/') in env_path or
                     (user_tht + '/') in abs_env_path or
                     user_tht == abs_env_path or
                     user_tht == env_path)):
                # file is in tht and will be copied, so just update path
                new_env_path = env_path.replace(user_tht + '/',
                                                tht_root + '/')
                self.log.debug("Redirecting %s to %s"
                               % (abs_env_path, new_env_path))
                environments.append(new_env_path)
            elif abs_env_path.startswith(tht_root):
                self.log.debug("File already in tht_root %s")
                environments.append(abs_env_path)
            else:
                self.log.debug("File outside of tht_root %s, copying in")
                # file is outside of THT, just copy it in
                # TODO(aschultz): probably shouldn't be flattened?
                target_dest = os.path.join(tht_root,
                                           os.path.basename(abs_env_path))
                if os.path.exists(target_dest):
                    raise exceptions.DeploymentError("%s already exists, "
                                                     "please rename the "
                                                     "file to something else"
                                                     % target_dest)
                shutil.copy(abs_env_path, tht_root)
                environments.append(target_dest)
        return environments

    def _setup_heat_environments(self, roles_file_path, networks_file_path,
                                 parsed_args):
        """Process tripleo heat templates with jinja and deploy into work dir

        * Process j2/install additional templates there
        * Return the environments list for futher processing as a new base.

        The first two items are reserved for the
        overcloud-resource-registry-puppet.yaml and passwords files.
        """

        self.log.warning(_("** Handling template files **"))
        env_files = []

        # TODO(aschultz): in overcloud deploy we have a --environments-dir
        # we might want to handle something similar for this
        # (shardy) alternatively perhaps we should rely on the plan-environment
        # environments list instead?
        if parsed_args.environment_files:
            env_files.extend(parsed_args.environment_files)

        # ensure any user provided templates get copied into tht_render
        user_environments = self._normalize_user_templates(
            parsed_args.templates, self.tht_render, env_files)

        # generate jinja templates by its work dir location
        self.log.debug(_("Using roles file %s") % roles_file_path)
        process_templates = os.path.join(parsed_args.templates,
                                         'tools/process-templates.py')
        args = [self.python_cmd, process_templates, '--roles-data',
                roles_file_path, '--network-data', networks_file_path,
                '--output-dir', self.tht_render]
        if utils.run_command_and_log(self.log, args, cwd=self.tht_render) != 0:
            # TODO(aschultz): improve error messaging
            msg = _("Problems generating templates.")
            self.log.error(msg)
            raise exceptions.DeploymentError(msg)

        # NOTE(aschultz): the next set of environment files are system included
        # so we have to include them at the front of our environment list so a
        # user can override anything in them.

        # Include any environments from the plan-environment.yaml
        plan_env_path = utils.rel_or_abs_path(
            self._get_plan_env_file_path(parsed_args), self.tht_render)
        with open(plan_env_path, 'r') as f:
            plan_env_data = yaml.safe_load(f)
        environments = [utils.rel_or_abs_path(e.get('path'), self.tht_render)
                        for e in plan_env_data.get('environments', {})]

        # this will allow the user to overwrite passwords with custom envs
        # or pick instack legacy passwords as is, if upgrading from instack
        pw_file = self._update_passwords_env(
            self.output_dir,
            parsed_args.deployment_user,
            parsed_args.upgrade,
        )
        environments.append(pw_file)

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

        self.log.info(_("Deploying templates in the directory {0}").format(
            os.path.abspath(self.tht_render)))

        maps_file = os.path.join(self.tht_render,
                                 'tripleoclient-hosts-portmaps.yaml')
        ip_nw = netaddr.IPNetwork(parsed_args.local_ip)
        ip = str(ip_nw.ip)

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
            ip, ip_nw, c_ip, p_ip,
            stack_name=parsed_args.stack,
            role_name=self._get_primary_role_name(
                roles_file_path, parsed_args.templates)))

        with open(maps_file, 'w') as env_file:
            yaml.safe_dump({'parameter_defaults': tmp_env}, env_file,
                           default_flow_style=False)
        environments.append(maps_file)

        # NOTE(aschultz): this doesn't get copied into tht_root but
        # we always include the hieradata override stuff last.
        if parsed_args.hieradata_override:
            environments.append(self._process_hieradata_overrides(
                parsed_args.hieradata_override,
                parsed_args.standalone_role))

        # Create a persistent drop-in file to indicate the stack
        # virtual state changes
        stack_vstate_dropin = os.path.join(self.tht_render,
                                           '%s-stack-vstate-dropin.yaml' %
                                           parsed_args.stack)
        with open(stack_vstate_dropin, 'w') as dropin_file:
            yaml.safe_dump(
                {'parameter_defaults': {
                    'StackAction': self.stack_action,
                    'DeployIdentifier': int(time.time())}},
                dropin_file, default_flow_style=False)
        environments.append(stack_vstate_dropin)

        return environments + user_environments

    def _prepare_container_images(self, env, roles_data):
        image_params = kolla_builder.container_images_prepare_multi(
            env, roles_data, dry_run=True)

        # use setdefault to ensure every needed image parameter is
        # populated without replacing user-set values
        if image_params:
            pd = env.get('parameter_defaults', {})
            for k, v in image_params.items():
                pd.setdefault(k, v)

    def _deploy_tripleo_heat_templates(self, orchestration_client,
                                       parsed_args):
        """Deploy the fixed templates in TripleO Heat Templates"""
        roles_file_path = self._get_roles_file_path(parsed_args)
        networks_file_path = self._get_networks_file_path(parsed_args)

        # sets self.tht_render to the working dir with deployed templates
        environments = self._setup_heat_environments(
            roles_file_path, networks_file_path, parsed_args)

        # rewrite paths to consume t-h-t env files from the working dir
        self.log.debug(_("Processing environment files %s") % environments)
        env_files, env = utils.process_multiple_environments(
            environments, self.tht_render, parsed_args.templates,
            cleanup=parsed_args.cleanup)

        roles_data = utils.fetch_roles_file(
            roles_file_path, parsed_args.templates)
        to_remove = set()
        for key, value in env.get('resource_registry', {}).items():
            if (key.startswith('OS::TripleO::Services::') and
                    value == 'OS::Heat::None'):
                to_remove.add(key)
        if to_remove:
            for role in roles_data:
                for service in to_remove:
                    try:
                        role.get('ServicesDefault', []).remove(service)
                    except ValueError:
                        pass
            self.log.info('Removing unused services, updating roles')
            # This will clean up the directory and set it up again
            self.tht_render = None
            self._populate_templates_dir(parsed_args.templates)
            roles_file_path = os.path.join(
                self.tht_render, 'roles-data-override.yaml')
            with open(roles_file_path, "w") as f:
                f.write(yaml.safe_dump(roles_data))
            # Redo the dance
            environments = self._setup_heat_environments(
                roles_file_path, networks_file_path, parsed_args)
            env_files, env = utils.process_multiple_environments(
                environments, self.tht_render, parsed_args.templates,
                cleanup=parsed_args.cleanup)

        self._prepare_container_images(env, roles_data)

        self.log.debug(_("Getting template contents"))
        template_path = os.path.join(self.tht_render, 'overcloud.yaml')
        template_files, template = \
            template_utils.get_template_contents(template_path)

        files = dict(list(template_files.items()) + list(env_files.items()))

        stack_name = parsed_args.stack

        self.log.debug(_("Deploying stack: %s") % stack_name)
        self.log.debug(_("Deploying template: %s") % template)
        self.log.debug(_("Deploying environment: %s") % env)
        self.log.debug(_("Deploying files: %s") % files)

        stack_args = {
            'stack_name': stack_name,
            'template': template,
            'environment': env,
            'files': files,
        }

        if parsed_args.timeout:
            stack_args['timeout_mins'] = parsed_args.timeout

        self.log.warning(_("** Performing Heat stack create.. **"))
        stack = orchestration_client.stacks.create(**stack_args)
        stack_id = stack['stack']['id']

        return "%s/%s" % (stack_name, stack_id)

    def _download_ansible_playbooks(self, client, stack_name,
                                    tripleo_role_name='Standalone',
                                    python_interpreter=sys.executable):
        stack_config = config.Config(client)
        self._create_working_dirs()

        self.log.warning(_('** Downloading {0} ansible.. **').format(
            stack_name))
        # python output buffering is making this seem to take forever..
        sys.stdout.flush()
        stack_config.write_config(stack_config.fetch_config(stack_name),
                                  stack_name,
                                  self.tmp_ansible_dir)

        inventory = TripleoInventory(
            hclient=client,
            plan_name=stack_name,
            ansible_ssh_user='root')

        inv_path = os.path.join(self.tmp_ansible_dir, 'inventory.yaml')
        extra_vars = {
            tripleo_role_name: {
                'ansible_connection': 'local',
                'ansible_python_interpreter': python_interpreter,
                }
            }

        inventory.write_static_inventory(inv_path, extra_vars)

        self.log.info(_('** Downloaded {0} ansible to {1} **').format(
                      stack_name, self.tmp_ansible_dir))
        sys.stdout.flush()
        return self.tmp_ansible_dir

    # Never returns, calls exec()
    def _launch_ansible(self, ansible_dir, list_args=None, operation="deploy"):

        if list_args is None:
            if operation not in constants.DEPLOY_ANSIBLE_ACTIONS.keys():
                self.log.error(_('Operation %s is not allowed') % operation)
                raise exceptions.DeploymentError('Invalid operation to run in '
                                                 'ansible.')
            list_args = constants.DEPLOY_ANSIBLE_ACTIONS[operation].split()

        self.log.warning(_('** Running ansible %s tasks **') % operation)
        os.chdir(ansible_dir)
        playbook_inventory = os.path.join(ansible_dir, 'inventory.yaml')
        cmd = [self.ansible_playbook_cmd, '-i', playbook_inventory] + list_args
        self.log.debug('Running Ansible %s tasks: %s' % (operation, ' '
                       .join(cmd)))
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
            default=constants.TRIPLEO_HEAT_TEMPLATES
        )
        parser.add_argument('--standalone', default=False, action='store_true',
                            help=_("Run deployment as a standalone deployment "
                                   "with no undercloud."))
        parser.add_argument('--upgrade', default=False, action='store_true',
                            help=_("Upgrade an existing deployment."))
        parser.add_argument('-y', '--yes', default=False, action='store_true',
                            help=_("Skip yes/no prompt (assume yes)."))
        parser.add_argument('--stack',
                            help=_("Name for the ephemeral (one-time create "
                                   "and forget) heat stack."),
                            default='standalone')
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
        parser.add_argument('--standalone-role', default='Standalone',
                            help=_("The role to use for standalone "
                                   "configuration when populating the "
                                   "deployment actions."))
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
            help=_(
                'Roles file, overrides the default %s in the t-h-t templates '
                'directory used for deployment. May be an '
                'absolute path or the path relative to the templates dir.'
                ) % constants.UNDERCLOUD_ROLES_FILE
        )
        parser.add_argument(
            '--networks-file', '-n', dest='networks_file',
            help=_(
                'Roles file, overrides the default %s in the t-h-t templates '
                'directory used for deployment. May be an '
                'absolute path or the path relative to the templates dir.'
                ) % constants.STANDALONE_NETWORKS_FILE
        )
        parser.add_argument(
            '--plan-environment-file', '-p',
            help=_('Plan Environment file, overrides the default %s in the '
                   '--templates directory') % constants.PLAN_ENVIRONMENT
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
            help=_('User to execute the non-privileged heat-all process. '
                   'Defaults to heat.')
        )
        # TODO(cjeanner) drop that once using oslo.privsep
        parser.add_argument(
            '--deployment-user',
            dest='deployment_user',
            default=os.environ.get('SUDO_USER', 'stack'),
            help=_('User who executes the tripleo deploy command. '
                   'Defaults to $SUDO_USER. If $SUDO_USER is unset '
                   'it defaults to stack.')
        )
        parser.add_argument('--deployment-python-interpreter', default=None,
                            help=_('The path to python interpreter to use for '
                                   'the deployment actions. If not specified '
                                   'the python version of the openstackclient '
                                   'will be used. This may need to be used '
                                   'if deploying on a python2 host from a '
                                   'python3 system or vice versa.'))
        parser.add_argument(
            '--heat-container-image', metavar='<HEAT_CONTAINER_IMAGE>',
            dest='heat_container_image',
            default='tripleomaster/centos-binary-heat-all:current-tripleo',
            help=_('The container image to use when launching the heat-all '
                   'process. Defaults to: '
                   'tripleomaster/centos-binary-heat-all:current-tripleo')
        )
        parser.add_argument(
            '--heat-native',
            dest='heat_native',
            nargs='?',
            default=None,
            const="true",
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
            default='localdomain',
            help=_('Local domain for standalone cloud and its API endpoints')
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
                   'it is wrapped with <role>ExtraConfig and also '
                   'passed in for t-h-t as a temp file created in '
                   '--output-dir. Note, instack hiera data may be '
                   'not t-h-t compatible and will highly likely require a '
                   'manual revision.')
        )
        parser.add_argument(
            '--keep-running',
            action='store_true',
            default=False,
            help=_('Keep the ephemeral Heat running after the stack operation '
                   'is complete. This is for debugging purposes only. '
                   'The ephemeral Heat can be used by openstackclient with:\n'
                   'OS_AUTH_TYPE=none '
                   'OS_ENDPOINT=http://127.0.0.1:8006/v1/admin '
                   'openstack stack list\n '
                   'where 8006 is the port specified by --heat-api-port.')
        )

        stack_action_group = parser.add_mutually_exclusive_group()

        stack_action_group.add_argument(
            '--force-stack-update',
            dest='force_stack_update',
            action='store_true',
            default=False,
            help=_("Do a virtual update of the ephemeral "
                   "heat stack (it cannot take real updates). "
                   "New or failed deployments "
                   "always have the stack_action=CREATE. This "
                   "option enforces stack_action=UPDATE."),
        )
        stack_action_group.add_argument(
            '--force-stack-create',
            dest='force_stack_create',
            action='store_true',
            default=False,
            help=_("Do a virtual create of the ephemeral "
                   "heat stack. New or failed deployments "
                   "always have the stack_action=CREATE. This "
                   "option enforces stack_action=CREATE."),
        )
        return parser

    def _process_hieradata_overrides(self, override_file=None,
                                     tripleo_role_name='Standalone'):
        """Count in hiera data overrides including legacy formats

        Return a file name that points to processed hiera data overrides file
        """
        if not override_file or not os.path.exists(override_file):
            # we should never get here because there's a check in
            # undercloud_conf but stranger things have happened.
            msg = (_('hieradata_override file could not be found %s') %
                   override_file)
            self.log.error(msg)
            raise exceptions.DeploymentError(msg)

        target = override_file
        with open(target, 'rb') as fb:
            data = fb.read()
        if not data.strip():
            # since an empty file isn't valid yaml, let's be more specific
            msg = (_("hieradata override file (%s) cannot be empty") % target)
            self.log.error(msg)
            raise exceptions.DeploymentError(msg)

        hiera_data = yaml.safe_load(data)
        if not hiera_data:
            msg = (_('Unsupported data format in hieradata override %s') %
                   target)
            self.log.error(msg)
            raise exceptions.DeploymentError(msg)
        self._create_working_dirs()

        # NOTE(bogdando): In t-h-t, hiera data should come in wrapped as
        # {parameter_defaults: {UndercloudExtraConfig: ... }}
        extra_config_var = '%sExtraConfig' % tripleo_role_name
        if (extra_config_var not in hiera_data.get('parameter_defaults', {})):
            hiera_override_file = os.path.join(
                self.tht_render, 'tripleo-hieradata-override.yaml')
            self.log.info('Converting hiera overrides for t-h-t from '
                          'legacy format into a file %s' %
                          hiera_override_file)
            with open(hiera_override_file, 'w') as override:
                yaml.safe_dump(
                    {'parameter_defaults': {
                     extra_config_var: hiera_data}},
                    override,
                    default_flow_style=False)
            target = hiera_override_file
        return target

    def _dump_ansible_errors(self, f, name):
        if not os.path.isfile(f):
            return

        failures = None
        with open(f, 'r') as ff:
            try:
                failures = json.load(ff)
            except Exception:
                self.log.error(
                    _('Could not read ansible errors from file %s') % f)

        if not failures or not failures.get(name, {}):
            return

        self.log.error(_('** Found ansible errors for %s deployment! **') %
                       name)
        self.log.error(json.dumps(failures.get(name, {}), indent=1))

    def _standalone_deploy(self, parsed_args):
        # NOTE(aschultz): the tripleo deploy interface is experimental but only
        # when not being invoked via undercloud install. Print a warning...
        if not self._is_undercloud_deploy(parsed_args):
            self.log.warning('[EXPERIMENTAL] The tripleo deploy interface is '
                             'an experimental interface. It may change in the '
                             'next release.')
        if not parsed_args.local_ip:
            msg = _('Please set --local-ip to the correct '
                    'ipaddress/cidr for this machine.')
            self.log.error(msg)
            raise exceptions.DeploymentError(msg)

        if not os.environ.get('HEAT_API_PORT'):
            os.environ['HEAT_API_PORT'] = parsed_args.heat_api_port

        # The main thread runs as root and we drop privs for forked
        # processes below. Only the heat deploy/os-collect-config forked
        # process runs as root.
        if os.geteuid() != 0:
            msg = _("Please run as root.")
            self.log.error(msg)
            raise exceptions.DeploymentError(msg)

        self._run_preflight_checks(parsed_args)

        # prepare working spaces
        self.output_dir = os.path.abspath(parsed_args.output_dir)
        self._create_working_dirs()
        # The state that needs to be persisted between serial deployments
        # and cannot be contained in ephemeral heat stacks or working dirs
        self._create_persistent_dirs()

        # configure puppet
        self._configure_puppet()

        # copy the templates dir in place
        self._populate_templates_dir(parsed_args.templates)

        # Set default plan if not specified by user
        self._set_default_plan()

        rc = 1
        try:
            # NOTE(bogdando): Look for the unique virtual update mark matching
            # the heat stack name we are going to create below. If found the
            # mark, consider the stack action is UPDATE instead of CREATE.
            mark_uuid = '_'.join(['update_mark', parsed_args.stack])
            self.stack_update_mark = os.path.join(
                constants.STANDALONE_EPHEMERAL_STACK_VSTATE,
                mark_uuid)

            self._set_stack_action(parsed_args)

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
                message = _("Stack create failed; %s") % msg
                self.log.error(message)
                raise exceptions.DeploymentError(message)

            # download the ansible playbooks and execute them.
            depl_python = utils.get_deployment_python_interpreter(parsed_args)
            self.ansible_dir = \
                self._download_ansible_playbooks(orchestration_client,
                                                 parsed_args.stack,
                                                 parsed_args.standalone_role,
                                                 depl_python)

            # Do not override user's custom ansible configuraition file,
            # it may have been pre-created with the tripleo CLI, or the like
            ansible_config = os.path.join(self.output_dir, 'ansible.cfg')
            if not os.path.isfile(ansible_config):
                self.log.warning(
                    _('Generating default ansible config file %s') %
                    ansible_config)
                # FIXME(bogdando): unhardcode key/transport for future
                # multi-node
                ansible.write_default_ansible_cfg(
                    self.ansible_dir,
                    parsed_args.deployment_user,
                    ssh_private_key=None,
                    transport='local')
            else:
                self.log.warning(
                    _('Using the existing %s for deployment') % ansible_config)
                shutil.copy(ansible_config, self.ansible_dir)

            # Kill heat, we're done with it now.
            if not parsed_args.keep_running:
                self._kill_heat(parsed_args)
            if not parsed_args.output_only:
                if parsed_args.upgrade:
                    # Run Upgrade tasks before the deployment
                    rc = self._launch_ansible(self.ansible_dir,
                                              operation='upgrade')
                    if rc != 0:
                        raise exceptions.DeploymentError('Upgrade failed')
                rc = self._launch_ansible(self.ansible_dir)
                if rc != 0:
                    raise exceptions.DeploymentError('Deployment failed')
                if parsed_args.upgrade:
                    # Run Post Upgrade tasks after the deployment
                    rc = self._launch_ansible(self.ansible_dir,
                                              operation='post-upgrade')
                    if rc != 0:
                        raise exceptions.DeploymentError('Post Upgrade failed')
                    # Run Online Upgrade tasks after the deployment
                    rc = self._launch_ansible(self.ansible_dir,
                                              operation='online-upgrade')
                    if rc != 0:
                        raise exceptions.DeploymentError(
                            'Online Upgrade failed')
        except Exception as e:
            self.log.error("Exception: %s" % six.text_type(e))
            self.log.error(traceback.print_exc())
            raise exceptions.DeploymentError(six.text_type(e))
        finally:
            if not parsed_args.keep_running:
                self._kill_heat(parsed_args)
            tar_filename = \
                self._create_install_artifact(parsed_args.deployment_user)
            if self.ansible_dir:
                self._dump_ansible_errors(
                    os.path.join(self.ansible_dir,
                                 tc_constants.ANSIBLE_ERRORS_FILE),
                    parsed_args.stack)
            self._cleanup_working_dirs(
                cleanup=parsed_args.cleanup,
                user=parsed_args.deployment_user
                )
            if tar_filename:
                self.log.warning('Install artifact is located at %s' %
                                 tar_filename)
            if not parsed_args.output_only and rc != 0:
                # We only get here on error.
                # Alter the stack virtual state for failed deployments
                if (self.stack_update_mark and
                   not parsed_args.force_stack_update and
                   os.path.isfile(self.stack_update_mark)):
                    self.log.warning(
                        _('The heat stack %s virtual state/action is '
                          'reset to CREATE. Use "--force-stack-update" to '
                          'set it forcefully to UPDATE') % parsed_args.stack)
                    self.log.warning(
                        _('Removing the stack virtual update mark file %s') %
                        self.stack_update_mark)
                    os.remove(self.stack_update_mark)

                self.log.error(DEPLOY_FAILURE_MESSAGE.format(
                    self.heat_launch.install_tmp
                    ))
                raise exceptions.DeploymentError('Deployment failed.')
            else:
                # We only get here if no errors
                if parsed_args.output_only:
                    success_messaging = OUTPUT_ONLY_COMPLETION_MESSAGE
                else:
                    success_messaging = DEPLOY_COMPLETION_MESSAGE

                if not self._is_undercloud_deploy(parsed_args):
                    success_messaging = success_messaging + \
                        STANDALONE_COMPLETION_MESSAGE.format(
                            '~/.config/openstack/clouds.yaml')

                self.log.warning(success_messaging)
                if (self.stack_update_mark and
                   (not parsed_args.output_only or
                       parsed_args.force_stack_update)):
                    # Persist the unique mark file for this stack
                    # Do not update its atime file system attribute to keep its
                    # genuine timestamp for the 1st time the stack state had
                    # been (virtually) changed to match stack_action UPDATE
                    self.log.warning(
                        _('Writing the stack virtual update mark file %s') %
                        self.stack_update_mark)
                    open(self.stack_update_mark, 'w').close()
                elif parsed_args.output_only:
                    self.log.warning(
                        _('Not creating the stack %s virtual update mark file '
                          'in the --output-only mode! Re-run with '
                          '--force-stack-update, if you want to enforce it.') %
                        parsed_args.stack)
                else:
                    self.log.warning(
                        _('Not creating the stack %s virtual update mark '
                          'file') % parsed_args.stack)

            return rc

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        utils.ansible_symlink()
        unconf_msg = _('User did not confirm upgrade, so exiting. '
                       'Consider using the --yes parameter if you '
                       'prefer to skip this warning in the future')
        try:
            if parsed_args.upgrade and (
                    not parsed_args.yes and sys.stdin.isatty()):
                prompt_response = six.moves.input(
                    ('It is strongly recommended to perform a backup '
                     'before the upgrade. Are you sure you want to '
                     'upgrade [y/N]?')
                ).lower()
                if not prompt_response.startswith('y'):
                    raise exceptions.UndercloudUpgradeNotConfirmed(unconf_msg)
        except (KeyboardInterrupt, EOFError) as e:
            if e.__class__ == KeyboardInterrupt:
                # ctrl-c
                raise exceptions.UndercloudUpgradeNotConfirmed("(ctrl-c) %s" %
                                                               unconf_msg)
            else:
                # ctrl-d
                raise exceptions.UndercloudUpgradeNotConfirmed("(ctrl-d) %s" %
                                                               unconf_msg)

        try:
            if parsed_args.standalone:
                if self._standalone_deploy(parsed_args) != 0:
                    msg = _('Deployment failed.')
                    self.log.error(msg)
                    raise exceptions.DeploymentError(msg)
            else:
                msg = _('Non-standalone is currently not supported')
                self.log.error(msg)
                raise exceptions.DeploymentError(msg)
        finally:
            # send erase sequence to reset the cmdline if paunch/ansible
            # mangled some escape sequences
            utils.send_cmdline_erase_sequence()
