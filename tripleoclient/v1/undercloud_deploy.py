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
import glob
import logging
import netaddr
import os
import pwd
import re
import subprocess
import sys
import tempfile
import time
import traceback
import yaml

try:
    from urllib2 import HTTPError
    from urllib2 import URLError
    from urllib2 import urlopen
except ImportError:
    # python3
    from urllib.error import HTTPError
    from urllib.error import URLError
    from urllib.request import urlopen

from cliff import command
from heatclient.common import event_utils
from heatclient.common import template_utils
from heatclient.common import utils as heat_utils
from openstackclient.i18n import _

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import heat_launcher

from tripleo_common.utils import passwords as password_utils

# For ansible download
from tripleo_common.inventory import TripleoInventory
from tripleo_common.utils import config


class DeployUndercloud(command.Command):
    """Deploy Undercloud (experimental feature)"""

    log = logging.getLogger(__name__ + ".DeployUndercloud")
    auth_required = False
    heat_pid = None

    def _get_hostname(self):
        p = subprocess.Popen(["hostname", "-s"], stdout=subprocess.PIPE)
        return p.communicate()[0].rstrip()

    def _configure_puppet(self):
        print('Configuring puppet modules symlinks ...')
        src = constants.TRIPLEO_PUPPET_MODULES
        dst = constants.PUPPET_MODULES
        subprocess.check_call(['mkdir', '-p', dst])
        tmp = tempfile.mkdtemp(dir=constants.PUPPET_BASE)
        os.chmod(tmp, 0o755)
        for obj in os.listdir(src):
            tmpf = os.path.join(tmp, obj)
            os.symlink(os.path.join(src, obj), tmpf)
            os.rename(tmpf, os.path.join(dst, obj))
        os.rmdir(tmp)

    def _wait_local_port_ready(self, api_port):
        count = 0
        while count < 30:
            time.sleep(1)
            count += 1
            try:
                urlopen("http://127.0.0.1:%s/" % api_port, timeout=1)
            except HTTPError as he:
                if he.code == 300:
                    return True
                pass
            except URLError:
                pass
        return False

    def _update_passwords_env(self, output_dir, passwords=None):
        pw_file = os.path.join(output_dir, 'tripleo-undercloud-passwords.yaml')
        undercloud_pw_file = os.path.join(output_dir,
                                          'undercloud-passwords.conf')
        stack_env = {'parameter_defaults': {}}
        if os.path.exists(pw_file):
            with open(pw_file) as pf:
                stack_env = yaml.safe_load(pf.read())

        pw = password_utils.generate_passwords(stack_env=stack_env)
        stack_env['parameter_defaults'].update(pw)

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
                if 'Password' in p or 'Token' in p:
                    # Convert camelcase from heat templates into the underscore
                    # format used by instack undercloud.
                    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', p)
                    pw_key = re.sub('([a-z0-9])([A-Z])',
                                    r'\1_\2', s1).lower()
                    pf.write('undercloud_%s: %s\n' % (pw_key, v))
        os.chmod(undercloud_pw_file, 0o600)

        return pw_file

    def _generate_hosts_parameters(self, parsed_args):
        hostname = self._get_hostname()
        domain = parsed_args.local_domain

        data = {
            'CloudName': hostname,
            'CloudDomain': domain,
            'CloudNameInternal': '%s.internalapi.%s' % (hostname, domain),
            'CloudNameStorage': '%s.storage.%s' % (hostname, domain),
            'CloudNameStorageManagement': ('%s.storagemgmt.%s'
                                           % (hostname, domain)),
            'CloudNameCtlplane': '%s.ctlplane.%s' % (hostname, domain),
        }
        return data

    def _generate_portmap_parameters(self, ip_addr, cidr):
        hostname = self._get_hostname()

        data = {
            'HostnameMap': {
                'undercloud-undercloud-0': '%s' % hostname
            },
            'DeployedServerPortMap': {
                ('%s-ctlplane' % hostname): {
                    'fixed_ips': [{'ip_address': ip_addr}],
                    'subnets': [{'cidr': cidr}]
                },
                'control_virtual_ip': {
                    'fixed_ips': [{'ip_address': ip_addr}],
                    'subnets': [{'cidr': cidr}]
                }
            }
        }
        return data

    def _kill_heat(self):
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
        tht_root = parsed_args.templates
        # generate jinja templates
        self.log.debug("Using roles file %s" % parsed_args.roles_file)
        args = ['python', 'tools/process-templates.py', '--roles-data',
                parsed_args.roles_file]
        subprocess.check_call(args, cwd=tht_root)

        print("Deploying templates in the directory {0}".format(
            os.path.abspath(tht_root)))

        self.log.debug("Creating Environment file")
        environments = []

        resource_registry_path = os.path.join(
            tht_root, 'overcloud-resource-registry-puppet.yaml')
        environments.insert(0, resource_registry_path)

        # this will allow the user to overwrite passwords with custom envs
        pw_file = self._update_passwords_env(parsed_args.output_dir)
        environments.insert(1, pw_file)

        undercloud_env_path = os.path.join(
            tht_root, 'environments', 'undercloud.yaml')
        environments.append(undercloud_env_path)

        # use deployed-server because we run os-collect-config locally
        deployed_server_env = os.path.join(
            tht_root, 'environments',
            'config-download-environment.yaml')
        environments.append(deployed_server_env)

        # use deployed-server because we run os-collect-config locally
        deployed_server_env = os.path.join(
            tht_root, 'environments',
            'deployed-server-noop-ctlplane.yaml')
        environments.append(deployed_server_env)

        if parsed_args.environment_files:
            environments.extend(parsed_args.environment_files)

        with tempfile.NamedTemporaryFile(delete=False) as tmp_env_file:
            tmp_env = self._generate_hosts_parameters(parsed_args)

            ip_nw = netaddr.IPNetwork(parsed_args.local_ip)
            ip = str(ip_nw.ip)
            cidr = str(ip_nw.netmask)
            tmp_env.update(self._generate_portmap_parameters(ip, cidr))

            with open(tmp_env_file.name, 'w') as env_file:
                yaml.safe_dump({'parameter_defaults': tmp_env}, env_file,
                               default_flow_style=False)
            environments.append(tmp_env_file.name)

        return environments

    def _deploy_tripleo_heat_templates(self, orchestration_client,
                                       parsed_args):
        """Deploy the fixed templates in TripleO Heat Templates"""

        environments = self._setup_heat_environments(parsed_args)

        self.log.debug("Processing environment files")
        env_files, env = (
            template_utils.process_multiple_environments_and_files(
                environments))

        self.log.debug("Getting template contents")
        template_path = os.path.join(parsed_args.templates, 'overcloud.yaml')
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

        self.log.info("Performing Heat stack create")
        stack = orchestration_client.stacks.create(**stack_args)
        stack_id = stack['stack']['id']

        return stack_id

    def _wait_for_heat_complete(self, orchestration_client, stack_id, timeout):

        # Wait for the stack to go to COMPLETE.
        timeout_t = time.time() + 60 * timeout
        marker = None
        event_log_context = heat_utils.EventLogContext()
        kwargs = {
            'sort_dir': 'asc',
            'nested_depth': '6'
        }
        while True:
            time.sleep(2)
            events = event_utils.get_events(
                orchestration_client,
                stack_id=stack_id,
                event_args=kwargs,
                marker=marker)
            if events:
                marker = getattr(events[-1], 'id', None)
                events_log = heat_utils.event_log_formatter(
                    events, event_log_context)
                print(events_log)

            status = orchestration_client.stacks.get(stack_id).status
            if status == 'FAILED':
                raise Exception('Stack create failed')
            if status == 'COMPLETE':
                break
            if time.time() > timeout_t:
                msg = 'Stack creation timeout: %d minutes elapsed' % (timeout)
                raise Exception(msg)

    def _download_ansible_playbooks(self, client, stack_name, output_dir):
        stack_config = config.Config(client)

        print('** Downloading undercloud ansible.. **')
        # python output buffering is making this seem to take forever..
        sys.stdout.flush()
        stack_config.download_config('undercloud', output_dir)

        # Sadly the above writes the ansible config to a new directory each
        # time.  This finds the newest new entry.
        ansible_dir = max(glob.iglob('%s/tripleo-*-config' % output_dir),
                          key=os.path.getctime)

        inventory = TripleoInventory(
            hclient=client,
            plan_name=stack_name,
            ansible_ssh_user='root')

        inv_path = os.path.join(ansible_dir, 'inventory.yaml')
        extra_vars = {'Undercloud': {'ansible_connection': 'local'}}
        inventory.write_static_inventory(inv_path, extra_vars)

        print('** Downloaded undercloud ansible to %s **' % ansible_dir)
        sys.stdout.flush()
        return ansible_dir

    # Never returns, calls exec()
    def _launch_ansible(self, ansible_dir):
        os.chdir(ansible_dir)
        playbook_inventory = os.path.join(ansible_dir, 'inventory.yaml')
        cmd = ['ansible-playbook', '-i', playbook_inventory,
               'deploy_steps_playbook.yaml', '-e', 'role_name=Undercloud',
               '-e', 'deploy_server_id=undercloud', '-e',
               'bootstrap_server_id=undercloud']
        print('Running Ansible: %s' % (' '.join(cmd)))
        # execvp() doesn't return.
        os.execvp(cmd[0], cmd)

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
        parser.add_argument('--stack',
                            help=_("Stack name to create"),
                            default='undercloud')
        parser.add_argument('--output-dir',
                            dest='output_dir',
                            help=_("Directory to output state and ansible"
                                   " deployment files."),
                            default=os.environ.get('HOME', ''))
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
            '--local-domain', metavar='<LOCAL_DOMAIN>',
            dest='local_domain',
            default='undercloud',
            help=_('Local domain for undercloud and its API endpoints')
        )
        parser.add_argument(
            '-k',
            '--keep-running',
            action='store_true',
            dest='keep_running',
            help=_('Keep the process running on failures for debugging')
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        print("\nUndercloud deploy is an experimental developer focused "
              "feature that does not yet replace "
              "'openstack undercloud install'.")

        if not parsed_args.local_ip:
            print('Please set --local-ip to the correct ipaddress/cidr '
                  'for this machine.')
            return

        if not os.environ.get('HEAT_API_PORT'):
            os.environ['HEAT_API_PORT'] = parsed_args.heat_api_port

        # The main thread runs as root and we drop privs for forked
        # processes below. Only the heat deploy/os-collect-config forked
        # process runs as root.
        if os.geteuid() != 0:
            raise exceptions.DeploymentError("Please run as root.")

        # configure puppet
        self._configure_puppet()

        try:
            # Launch heat.
            orchestration_client = self._launch_heat(parsed_args)
            # Wait for heat to be ready.
            self._wait_local_port_ready(parsed_args.heat_api_port)
            # Deploy TripleO Heat templates.
            stack_id = \
                self._deploy_tripleo_heat_templates(orchestration_client,
                                                    parsed_args)
            # Wait for complete..
            self._wait_for_heat_complete(orchestration_client, stack_id,
                                         parsed_args.timeout)
            # download the ansible playbooks and execute them.
            ansible_dir = \
                self._download_ansible_playbooks(orchestration_client,
                                                 parsed_args.stack,
                                                 parsed_args.output_dir)
            # Kill heat, we're done with it now.
            self._kill_heat()
            # Never returns..  We exec() it directly.
            self._launch_ansible(ansible_dir)
        except Exception as e:
            print("Exception: %s" % e)
            print(traceback.format_exception(*sys.exc_info()))
            raise
        finally:
            # We only get here on error.
            print('ERROR: Heat log files: %s' % (self.heat_launch.install_tmp))
            self._kill_heat()
            return 1
