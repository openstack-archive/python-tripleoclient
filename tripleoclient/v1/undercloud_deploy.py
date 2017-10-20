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
import itertools
import logging
import netaddr
import os
import pwd
import signal
import subprocess
import sys
import tempfile
import time
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
from heatclient.common import template_utils
from openstackclient.i18n import _

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import fake_keystone
from tripleoclient import heat_launcher

from tripleo_common.utils import passwords as password_utils

REQUIRED_PACKAGES = iter([
    'python-heat-agent',
    'python-heat-agent-apply-config',
    'python-heat-agent-hiera',
    'python-heat-agent-puppet',
    'python-heat-agent-docker-cmd',
    'python-heat-agent-json-file',
    'python-heat-agent-ansible',
    'python-ipaddr',
    'python-tripleoclient',
    'docker',
    'openvswitch',
    'openstack-puppet-modules',
    'yum-plugin-priorities',
    'openstack-tripleo-common',
    'openstack-tripleo-heat-templates',
    'deltarpm'
])


INSTALLER_ENV = {
    'OS_AUTH_URL': 'http://127.0.0.1:35358',
    'OS_USERNAME': 'foo',
    'OS_PROJECT_NAME': 'foo',
    'OS_PASSWORD': 'bar'
}


class DeployUndercloud(command.Command):
    """Deploy Undercloud (experimental feature)"""

    log = logging.getLogger(__name__ + ".DeployUndercloud")
    auth_required = False
    prerequisites = REQUIRED_PACKAGES

    def _get_hostname(self):
        p = subprocess.Popen(["hostname", "-s"], stdout=subprocess.PIPE)
        return p.communicate()[0].rstrip()

    def _install_prerequisites(self, install_heat_native):
        print('Checking for installed prerequisites ...')
        processed = []

        if install_heat_native:
            self.prerequisites = itertools.chain(
                self.prerequisites,
                ['openstack-heat-api', 'openstack-heat-engine',
                 'openstack-heat-monolith'])

        for p in self.prerequisites:
            try:
                subprocess.check_call(['rpm', '-q', p])
            except subprocess.CalledProcessError as e:
                if e.returncode == 1:
                    processed.append(p)
                elif e.returncode != 0:
                    raise Exception('Failed to check for prerequisites: '
                                    '%s, the exit status %s'
                                    % (p, e.returncode))

        if len(processed) > 0:
            print('Installing prerequisites ...')
            subprocess.check_call(['yum', '-y', 'install'] + processed)

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

    def _lookup_tripleo_server_stackid(self, client, stack_id):
        server_stack_id = None

        for X in client.resources.list(stack_id, nested_depth=6):
            if X.resource_type in (
                    'OS::TripleO::Server',
                    'OS::TripleO::UndercloudServer'):
                server_stack_id = X.physical_resource_id

        return server_stack_id

    def _launch_os_collect_config(self, keystone_port, stack_id):
        print('Launching os-collect-config ...')
        os.execvp('os-collect-config',
                  ['os-collect-config',
                   '--polling-interval', '3',
                   '--heat-auth-url', 'http://127.0.0.1:%s/v3' % keystone_port,
                   '--heat-password', 'fake',
                   '--heat-user-id', 'admin',
                   '--heat-project-id', 'admin',
                   '--heat-stack-id', stack_id,
                   '--heat-resource-name', 'deployed-server', 'heat'])

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

    def _heat_deploy(self, stack_name, template_path, parameters,
                     environments, timeout, api_port, ks_port):
        self.log.debug("Processing environment files")
        env_files, env = (
            template_utils.process_multiple_environments_and_files(
                environments))

        self.log.debug("Getting template contents")
        template_files, template = template_utils.get_template_contents(
            template_path)

        files = dict(list(template_files.items()) + list(env_files.items()))

        # NOTE(dprince): we use our own client here because we set
        # auth_required=False above because keystone isn't running when this
        # command starts
        tripleoclients = self.app.client_manager.tripleoclient
        orchestration_client = tripleoclients.local_orchestration(api_port,
                                                                  ks_port)

        self.log.debug("Deploying stack: %s", stack_name)
        self.log.debug("Deploying template: %s", template)
        self.log.debug("Deploying parameters: %s", parameters)
        self.log.debug("Deploying environment: %s", env)
        self.log.debug("Deploying files: %s", files)

        stack_args = {
            'stack_name': stack_name,
            'template': template,
            'environment': env,
            'files': files,
        }

        if timeout:
            stack_args['timeout_mins'] = timeout

        self.log.info("Performing Heat stack create")
        stack = orchestration_client.stacks.create(**stack_args)
        stack_id = stack['stack']['id']

        event_list_pid = self._fork_heat_event_list()

        self.log.info("Looking up server stack id...")
        server_stack_id = None
        # NOTE(dprince) wait a bit to create the server_stack_id resource
        for c in range(timeout * 60):
            time.sleep(1)
            server_stack_id = self._lookup_tripleo_server_stackid(
                orchestration_client, stack_id)
            if server_stack_id:
                break
        if not server_stack_id:
            msg = ('Unable to find deployed server stack id. '
                   'See tripleo-heat-templates to ensure proper '
                   '"deployed-server" usage.')
            raise Exception(msg)
        self.log.debug("server_stack_id: %s" % server_stack_id)

        pid = None
        status = 'FAILED'
        try:
            pid = os.fork()
            if pid == 0:
                self._launch_os_collect_config(ks_port, server_stack_id)
            else:
                while True:
                    status = orchestration_client.stacks.get(stack_id).status
                    self.log.info(status)
                    if status in ['COMPLETE', 'FAILED']:
                        break
                    time.sleep(5)

        finally:
            if pid:
                os.kill(pid, signal.SIGKILL)
            if event_list_pid:
                os.kill(event_list_pid, signal.SIGKILL)
        stack_get = orchestration_client.stacks.get(stack_id)
        status = stack_get.status
        if status != 'FAILED':
            pw_rsrc = orchestration_client.resources.get(
                stack_id, 'DefaultPasswords')
            passwords = {p.title().replace("_", ""): v for p, v in
                         pw_rsrc.attributes.get('passwords', {}).items()}
            return passwords
        else:
            msg = "Stack create failed, reason: %s" % stack_get.reason
            raise Exception(msg)

    def _fork_heat_event_list(self):
        pid = os.fork()
        if pid == 0:
            try:
                os.setpgrp()
                os.setgid(pwd.getpwnam('nobody').pw_gid)
                os.setuid(pwd.getpwnam('nobody').pw_uid)
            except KeyError:
                raise exceptions.DeploymentError(
                    "Please create a 'nobody' user account before "
                    "proceeding.")
            subprocess.check_call(['openstack', 'stack', 'event', 'list',
                                   'undercloud', '--follow',
                                   '--nested-depth', '6'], env=INSTALLER_ENV)
            sys.exit(0)
        else:
            return pid

    def _fork_fake_keystone(self):
        pid = os.fork()
        if pid == 0:
            try:
                os.setpgrp()
                os.setgid(pwd.getpwnam('nobody').pw_gid)
                os.setuid(pwd.getpwnam('nobody').pw_uid)
            except KeyError:
                raise exceptions.DeploymentError(
                    "Please create a 'nobody' user account before "
                    "proceeding.")
            fake_keystone.launch()
            sys.exit(0)
        else:
            return pid

    def _update_passwords_env(self, passwords=None):
        pw_file = os.path.join(os.environ.get('HOME', ''),
                               'tripleo-undercloud-passwords.yaml')
        stack_env = {'parameter_defaults': {}}
        if os.path.exists(pw_file):
            with open(pw_file) as pf:
                stack_env = yaml.load(pf.read())

        pw = password_utils.generate_passwords(stack_env=stack_env)
        stack_env['parameter_defaults'].update(pw)

        if passwords:
            # These passwords are the DefaultPasswords so we only
            # update if they don't already exist in stack_env
            for p, v in passwords.items():
                if p not in stack_env['parameter_defaults']:
                    stack_env['parameter_defaults'][p] = v

        with open(pw_file, 'w') as pf:
            yaml.safe_dump(stack_env, pf, default_flow_style=False)

        return pw_file

    def _generate_hosts_parameters(self):
        hostname = self._get_hostname()
        domain = 'undercloud'

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

    def _deploy_tripleo_heat_templates(self, parsed_args):
        """Deploy the fixed templates in TripleO Heat Templates"""
        parameters = {}

        tht_root = parsed_args.templates
        # generate jinja templates
        args = ['python', 'tools/process-templates.py', '--roles-data',
                'roles_data_undercloud.yaml']
        subprocess.check_call(args, cwd=tht_root)

        print("Deploying templates in the directory {0}".format(
            os.path.abspath(tht_root)))

        self.log.debug("Creating Environment file")
        environments = []

        resource_registry_path = os.path.join(
            tht_root, 'overcloud-resource-registry-puppet.yaml')
        environments.insert(0, resource_registry_path)

        # this will allow the user to overwrite passwords with custom envs
        pw_file = self._update_passwords_env()
        environments.insert(1, pw_file)

        undercloud_env_path = os.path.join(
            tht_root, 'environments', 'undercloud.yaml')
        environments.append(undercloud_env_path)

        # use deployed-server because we run os-collect-config locally
        deployed_server_env = os.path.join(
            tht_root, 'environments',
            'deployed-server-noop-ctlplane.yaml')
        environments.append(deployed_server_env)

        if parsed_args.environment_files:
            environments.extend(parsed_args.environment_files)

        with tempfile.NamedTemporaryFile() as tmp_env_file:
            tmp_env = self._generate_hosts_parameters()

            ip_nw = netaddr.IPNetwork(parsed_args.local_ip)
            ip = str(ip_nw.ip)
            cidr = str(ip_nw.netmask)
            tmp_env.update(self._generate_portmap_parameters(ip, cidr))

            with open(tmp_env_file.name, 'w') as env_file:
                yaml.safe_dump({'parameter_defaults': tmp_env}, env_file,
                               default_flow_style=False)
            environments.append(tmp_env_file.name)

            undercloud_yaml = os.path.join(tht_root, 'overcloud.yaml')
            passwords = self._heat_deploy(parsed_args.stack, undercloud_yaml,
                                          parameters, environments,
                                          parsed_args.timeout,
                                          parsed_args.heat_api_port,
                                          parsed_args.fake_keystone_port)
            if passwords:
                # Get legacy passwords/secrets generated via heat
                # These need to be written to the passwords file
                # to avoid re-creating them every update
                self._update_passwords_env(passwords)
            return True

    def _write_credentials(self):
        fn = os.path.expanduser('~/installer_stackrc')
        with os.fdopen(os.open(fn, os.O_CREAT | os.O_WRONLY, 0o600), 'w') as f:
            f.write('# credentials to use while the undercloud '
                    'installer is running')
            for k, v in INSTALLER_ENV.items():
                f.write('export %s=%s\n' % (k, v))

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
            '--heat-api-port', metavar='<HEAT_API_PORT>',
            dest='heat_api_port',
            default='8006',
            help=_('Heat API port to use for the installers private'
                   ' Heat API instance. Optional. Default: 8006.)')
        )
        parser.add_argument(
            '--fake-keystone-port', metavar='<FAKE_KEYSTONE_PORT>',
            dest='fake_keystone_port',
            default='35358',
            help=_('Keystone API port to use for the installers private'
                   ' fake Keystone API instance. Optional. Default: 35358.)')
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
            default='tripleoupstream/centos-binary-heat-all',
            help=_('The container image to use when launching the heat-all '
                   'process. Defaults to: '
                   'tripleoupstream/centos-binary-heat-all')
        )
        parser.add_argument(
            '--heat-native',
            action='store_true',
            default=False,
            help=_('Execute the heat-all process natively on this host. '
                   'This option requires that the heat-all binaries '
                   'be installed locally on this machine. '
                   'This option is off by default which means heat-all is '
                   'executed in a docker container.')
        )
        parser.add_argument(
            '--local-ip', metavar='<LOCAL_IP>',
            dest='local_ip',
            help=_('Local IP/CIDR for undercloud traffic. Required.')
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

        # NOTE(dprince): It would be nice if heat supported true 'noauth'
        # use in a local format for our use case here (or perhaps dev testing)
        # but until it does running our own lightweight shim to mock out
        # the required API calls works just as well. To keep fake keystone
        # light we run it in a thread.
        if not os.environ.get('FAKE_KEYSTONE_PORT'):
            os.environ['FAKE_KEYSTONE_PORT'] = parsed_args.fake_keystone_port
        if not os.environ.get('HEAT_API_PORT'):
            os.environ['HEAT_API_PORT'] = parsed_args.heat_api_port

        # The main thread runs as root and we drop privs for forked
        # processes below. Only the heat deploy/os-collect-config forked
        # process runs as root.
        if os.geteuid() != 0:
            raise exceptions.DeploymentError("Please run as root.")

        # Install required packages and configure puppet
        self._install_prerequisites(parsed_args.heat_native)
        self._configure_puppet()

        keystone_pid = self._fork_fake_keystone()

        # we do this as root to chown config files properly for docker, etc.
        if parsed_args.heat_native:
            heat_launch = heat_launcher.HeatNativeLauncher(
                parsed_args.heat_api_port,
                parsed_args.fake_keystone_port,
                parsed_args.heat_container_image,
                parsed_args.heat_user)
        else:
            heat_launch = heat_launcher.HeatDockerLauncher(
                parsed_args.heat_api_port,
                parsed_args.fake_keystone_port,
                parsed_args.heat_container_image,
                parsed_args.heat_user)

        heat_pid = None
        try:
            # NOTE(dprince): we launch heat with fork exec because
            # we don't want it to inherit our args. Launching heat
            # as a "library" would be cool... but that would require
            # more refactoring. It runs a single process and we kill
            # it always below.
            heat_pid = os.fork()
            if heat_pid == 0:
                os.setpgrp()
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
                    heat_launch.heat_db_sync()
                    heat_launch.launch_heat()
                else:
                    heat_launch.heat_db_sync()
                    heat_launch.launch_heat()
            else:
                self._wait_local_port_ready(parsed_args.fake_keystone_port)
                self._wait_local_port_ready(parsed_args.heat_api_port)

                self._write_credentials()

                if self._deploy_tripleo_heat_templates(parsed_args):
                    print("\nDeploy Successful.")
                else:
                    print("\nUndercloud deployment failed: "
                          "press ctrl-c to exit.")
                    while parsed_args.keep_running:
                        try:
                            time.sleep(1)
                        except KeyboardInterrupt:
                            break

                    raise exceptions.DeploymentError("Stack create failed.")

        finally:
            if heat_launch:
                print('Log files at: %s' % heat_launch.install_tmp)
                heat_launch.kill_heat(heat_pid)
            if keystone_pid:
                os.kill(keystone_pid, signal.SIGKILL)
