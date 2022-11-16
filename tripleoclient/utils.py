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

import collections
from collections import abc as collections_abc

import configparser
import copy
import csv
import datetime
import errno
import getpass
import glob
import hashlib
import json
import logging

import multiprocessing
import netaddr
import openstack
import os
import os.path
import prettytable
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import yaml

from heatclient.common import event_utils
from heatclient.common import template_utils
from heatclient.common import utils as heat_utils
from heatclient.exc import HTTPNotFound
from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from oslo_concurrency import processutils

from heatclient import exc as hc_exc
from urllib import error as url_error
from urllib import parse as url_parse
from urllib import request

from tenacity import retry
from tenacity.stop import stop_after_attempt, stop_after_delay
from tenacity.wait import wait_fixed

from tripleo_common.image import image_uploader
from tripleo_common.image import kolla_builder
from tripleo_common.utils import plan as plan_utils
from tripleo_common.utils import heat as tc_heat_utils
from tripleo_common.utils import stack as stack_utils
from tripleo_common import update
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import heat_launcher

import warnings
warnings.simplefilter("ignore", UserWarning)

import ansible_runner  # noqa
from ansible.parsing.dataloader import DataLoader  # noqa
from ansible.inventory.manager import InventoryManager  # noqa

LOG = logging.getLogger(__name__ + ".utils")
_local_orchestration_client = None
_heat_pid = None


class Pushd(object):
    """Simple context manager to change directories and then return."""

    def __init__(self, directory):
        """This context manager will enter and exit directories.

        >>> with Pushd(directory='/tmp'):
        ...     with open('file', 'w') as f:
        ...         f.write('test')

        :param directory: path to change directory to
        :type directory: `string`
        """
        self.dir = directory
        self.pwd = self.cwd = os.getcwd()

    def __enter__(self):
        os.chdir(self.dir)
        self.cwd = os.getcwd()
        return self

    def __exit__(self, *args):
        if self.pwd != self.cwd:
            os.chdir(self.pwd)


class TempDirs(object):
    """Simple context manager to manage temp directories."""

    def __init__(self, dir_path=None, dir_prefix='tripleo', cleanup=True,
                 chdir=True):
        """This context manager will create, push, and cleanup temp directories.

        >>> with TempDirs() as t:
        ...     with open('file', 'w') as f:
        ...         f.write('test')
        ...     print(t)
        ...     os.mkdir('testing')
        ...     with open(os.path.join(t, 'file')) as w:
        ...         print(w.read())
        ...     with open('testing/file', 'w') as f:
        ...         f.write('things')
        ...     with open(os.path.join(t, 'testing/file')) as w:
        ...         print(w.read())

        :param dir_path: path to create the temp directory
        :type dir_path: `string`
        :param dir_prefix: prefix to add to a temp directory
        :type dir_prefix: `string`
        :param cleanup: when enabled the temp directory will be
                         removed on exit.
        :type cleanup: `boolean`
        :param chdir: Change to/from the created temporary dir on enter/exit.
        :type chdir: `boolean`
        """

        # NOTE(cloudnull): kwargs for tempfile.mkdtemp are created
        #                  because args are not processed correctly
        #                  in py2. When we drop py2 support (cent7)
        #                  these args can be removed and used directly
        #                  in the `tempfile.mkdtemp` function.
        tempdir_kwargs = dict()
        if dir_path:
            tempdir_kwargs['dir'] = dir_path

        if dir_prefix:
            tempdir_kwargs['prefix'] = dir_prefix

        self.dir = tempfile.mkdtemp(**tempdir_kwargs)
        self.pushd = Pushd(directory=self.dir)
        self.cleanup = cleanup
        self.chdir = chdir

    def __enter__(self):
        if self.chdir:
            self.pushd.__enter__()
        return self.dir

    def __exit__(self, *args):
        if self.chdir:
            self.pushd.__exit__()
        if self.cleanup:
            self.clean()
        else:
            LOG.warning("Not cleaning temporary directory [ %s ]" % self.dir)

    def clean(self):
        shutil.rmtree(self.dir, ignore_errors=True)
        LOG.info("Temporary directory [ %s ] cleaned up" % self.dir)


def _encode_envvars(env):
    """Encode a hash of values.

    :param env: A hash of key=value items.
    :type env: `dict`.
    """
    for key, value in env.items():
        env[key] = str(value)
    else:
        return env


def makedirs(dir_path):
    """Recursively make directories and log the interaction.

    :param dir_path: full path of the directories to make.
    :type dir_path: `string`
    :returns: `boolean`
    """

    try:
        os.makedirs(dir_path)
    except FileExistsError:
        LOG.debug(
            'Directory "{}" was not created because it'
            ' already exists.'.format(
                dir_path
            )
        )
        return False
    else:
        LOG.debug('Directory "{}" was created.'.format(dir_path))
        return True


def playbook_limit_parse(limit_nodes):
    """Return a parsed string for limits.

    This will sanitize user inputs so that we guarantee what is provided is
    expected to be functional. If limit_nodes is None, this function will
    return None.


    :returns: String
    """

    if not limit_nodes:
        return limit_nodes

    return ':'.join([i.strip() for i in re.split(',| |:', limit_nodes) if i])


def playbook_verbosity(self):
    """Return an integer for playbook verbosity levels.

    :param self: Class object used to interpret the runtime state.
    :type self: Object

    :returns: Integer
    """

    if self.app.options.debug:
        return 3
    if self.app_args.verbose_level <= 1:
        return 0
    return self.app_args.verbose_level


def run_ansible_playbook(playbook, inventory, workdir, playbook_dir=None,
                         connection='smart', output_callback='tripleo_dense',
                         ssh_user='root', key=None, module_path=None,
                         limit_hosts=None, tags=None, skip_tags=None,
                         verbosity=0, quiet=False, extra_vars=None,
                         extra_vars_file=None, plan='overcloud',
                         gathering_policy='smart', extra_env_variables=None,
                         parallel_run=False,
                         callback_whitelist=constants.ANSIBLE_CWL,
                         ansible_cfg=None, ansible_timeout=30,
                         reproduce_command=True,
                         timeout=None, forks=None,
                         ignore_unreachable=False):
    """Simple wrapper for ansible-playbook.

    :param playbook: Playbook filename.
    :type playbook: String

    :param inventory: Either proper inventory file, or a coma-separated list.
    :type inventory: String

    :param workdir: Location of the working directory.
    :type workdir: String

    :param playbook_dir: Location of the playbook directory.
                         (defaults to workdir).
    :type playbook_dir: String

    :param connection: Connection type (local, smart, etc).
    :type connection: String

    :param output_callback: Callback for output format. Defaults to
                            "tripleo_dense".
    :type output_callback: String

    :param callback_whitelist: Comma separated list of callback plugins.
                               Defaults to
                               "tripleo_dense,tripleo_profile_tasks,
                               tripleo_states".
                               Custom output_callback is also whitelisted.
    :type callback_whitelist: String

    :param ssh_user: User for the ssh connection.
    :type ssh_user: String

    :param key: Private key to use for the ssh connection.
    :type key: String

    :param module_path: Location of the ansible module and library.
    :type module_path: String

    :param limit_hosts: Limit the execution to the hosts.
    :type limit_hosts: String

    :param tags: Run specific tags.
    :type tags: String

    :param skip_tags: Skip specific tags.
    :type skip_tags: String

    :param verbosity: Verbosity level for Ansible execution.
    :type verbosity: Integer

    :param quiet: Disable all output (Defaults to False)
    :type quiet: Boolean

    :param extra_vars: Set additional variables as a Dict or the absolute
                       path of a JSON or YAML file type.
    :type extra_vars: Either a Dict or the absolute path of JSON or YAML

    :param extra_vars_file: Set additional ansible variables using an
                            extravar file.
    :type extra_vars_file: Dictionary

    :param plan: Plan name (Defaults to "overcloud").
    :type plan: String

    :param gathering_policy: This setting controls the default policy of
                             fact gathering ('smart', 'implicit', 'explicit').
    :type gathering_facts: String

    :param extra_env_variables: Dict option to extend or override any of the
                                default environment variables.
    :type extra_env_variables: Dict

    :param parallel_run: Isolate playbook execution when playbooks are to be
                         executed with multi-processing.
    :type parallel_run: Boolean

    :param ansible_cfg: Path to an ansible configuration file. One will be
                        generated in the artifact path if this option is None.
    :type ansible_cfg: String

    :param ansible_timeout: Timeout for ansible connections.
    :type ansible_timeout: int

    :param reproduce_command: Enable or disable option to reproduce ansible
                              commands upon failure. This option will produce
                              a bash script that can reproduce a failing
                              playbook command which is helpful for debugging
                              and retry purposes.
    :type reproduce_command: Boolean

    :param timeout: Timeout for ansible to finish playbook execution (minutes).
    :type timeout: int
    """

    def _playbook_check(play):
        if not os.path.exists(play):
            play = os.path.join(playbook_dir, play)
            if not os.path.exists(play):
                raise RuntimeError('No such playbook: {}'.format(play))
        LOG.debug('Ansible playbook {} found'.format(play))
        return play

    def _inventory(inventory):
        if inventory:
            if isinstance(inventory, str):
                # check is file path
                if os.path.exists(inventory):
                    return inventory
            elif isinstance(inventory, dict):
                inventory = yaml.safe_dump(
                    inventory,
                    default_flow_style=False
                )
            inv_file = ansible_runner.utils.dump_artifact(
                inventory,
                workdir,
                constants.ANSIBLE_HOSTS_FILENAME)
            os.chmod(inv_file, 0o600)
            return inv_file

    def _running_ansible_msg(playbook, timeout=None):
        if timeout and timeout > 0:
            return ('Running Ansible playbook with timeout %sm: %s,' %
                    (timeout, playbook))
        return ('Running Ansible playbook: %s,' % playbook)

    if not playbook_dir:
        playbook_dir = workdir

    # Ensure that the ansible-runner env exists
    runner_env = os.path.join(workdir, 'env')
    makedirs(runner_env)

    if extra_vars_file:
        runner_extra_vars = os.path.join(runner_env, 'extravars')
        with open(runner_extra_vars, 'w') as f:
            f.write(yaml.safe_dump(extra_vars_file, default_flow_style=False))

    if timeout and timeout > 0:
        settings_file = os.path.join(runner_env, 'settings')
        timeout_value = timeout * 60
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                settings_object = yaml.safe_load(f.read())
                settings_object['job_timeout'] = timeout_value
        else:
            settings_object = {'job_timeout': timeout_value}

        with open(settings_file, 'w') as f:
            f.write(yaml.safe_dump(settings_object, default_flow_style=False))

    if isinstance(playbook, (list, set)):
        verified_playbooks = [_playbook_check(play=i) for i in playbook]
        playbook = os.path.join(workdir, 'tripleo-multi-playbook.yaml')
        with open(playbook, 'w') as f:
            f.write(
                yaml.safe_dump(
                    [{'import_playbook': i} for i in verified_playbooks],
                    default_flow_style=False
                )
            )

        LOG.info(
            _running_ansible_msg(playbook, timeout) +
            ' multi-playbook execution: {}'
            ' Working directory: {},'
            ' Playbook directory: {}'.format(
                verified_playbooks,
                workdir,
                playbook_dir
            )
        )
    else:
        playbook = _playbook_check(play=playbook)
        LOG.info(
            _running_ansible_msg(playbook, timeout) +
            ' Working directory: {},'
            ' Playbook directory: {}'.format(
                workdir,
                playbook_dir
            )
        )

    if limit_hosts:
        LOG.info(
            'Running ansible with the following limit: {}'.format(
                limit_hosts
            )
        )
    ansible_fact_path = os.path.join(
        os.path.expanduser('~'),
        '.tripleo',
        'fact_cache'
    )
    makedirs(ansible_fact_path)

    if output_callback not in callback_whitelist.split(','):
        callback_whitelist = ','.join([callback_whitelist, output_callback])

    if not forks:
        forks = min(multiprocessing.cpu_count() * 4, 100)

    env = dict()
    env['ANSIBLE_SSH_ARGS'] = (
        '-o UserKnownHostsFile={} '
        '-o StrictHostKeyChecking=no '
        '-o ControlMaster=auto '
        '-o ControlPersist=30m '
        '-o ServerAliveInterval=64 '
        '-o ServerAliveCountMax=1024 '
        '-o Compression=no '
        '-o TCPKeepAlive=yes '
        '-o VerifyHostKeyDNS=no '
        '-o ForwardX11=no '
        '-o ForwardAgent=yes '
        '-o PreferredAuthentications=publickey '
        '-T'
    ).format(os.devnull)
    env['ANSIBLE_DISPLAY_FAILED_STDERR'] = True
    env['ANSIBLE_FORKS'] = forks
    env['ANSIBLE_TIMEOUT'] = ansible_timeout
    env['ANSIBLE_GATHER_TIMEOUT'] = 45
    env['ANSIBLE_SSH_RETRIES'] = 3
    env['ANSIBLE_PIPELINING'] = True
    env['ANSIBLE_SCP_IF_SSH'] = True
    env['ANSIBLE_REMOTE_USER'] = ssh_user
    env['ANSIBLE_STDOUT_CALLBACK'] = output_callback
    env['ANSIBLE_COLLECTIONS_PATHS'] = '/usr/share/ansible/collections'
    env['ANSIBLE_LIBRARY'] = (
        '/usr/share/ansible/tripleo-plugins/modules:'
        '/usr/share/ansible/plugins/modules:'
        '/usr/share/ceph-ansible/library:'
        '/usr/share/ansible-modules:'
        '{}/library'.format(constants.DEFAULT_VALIDATIONS_BASEDIR)
    )
    env['ANSIBLE_LOOKUP_PLUGINS'] = (
        '/usr/share/ansible/tripleo-plugins/lookup:'
        '/usr/share/ansible/plugins/lookup:'
        '/usr/share/ceph-ansible/plugins/lookup:'
        '{}/lookup_plugins'.format(
            constants.DEFAULT_VALIDATIONS_BASEDIR
        )
    )
    env['ANSIBLE_CALLBACK_PLUGINS'] = (
        '/usr/share/ansible/tripleo-plugins/callback:'
        '/usr/share/ansible/plugins/callback:'
        '/usr/share/ceph-ansible/plugins/callback:'
        '{}/callback_plugins'.format(
            constants.DEFAULT_VALIDATIONS_BASEDIR
        )
    )
    env['ANSIBLE_ACTION_PLUGINS'] = (
        '/usr/share/ansible/tripleo-plugins/action:'
        '/usr/share/ansible/plugins/action:'
        '/usr/share/ceph-ansible/plugins/actions:'
        '{}/action_plugins'.format(
            constants.DEFAULT_VALIDATIONS_BASEDIR
        )
    )
    env['ANSIBLE_FILTER_PLUGINS'] = (
        '/usr/share/ansible/tripleo-plugins/filter:'
        '/usr/share/ansible/plugins/filter:'
        '/usr/share/ceph-ansible/plugins/filter:'
        '{}/filter_plugins'.format(
            constants.DEFAULT_VALIDATIONS_BASEDIR
        )
    )
    env['ANSIBLE_ROLES_PATH'] = (
        '/usr/share/ansible/tripleo-roles:'
        '/usr/share/ansible/roles:'
        '/usr/share/ceph-ansible/roles:'
        '/etc/ansible/roles:'
        '{}/roles'.format(
            constants.DEFAULT_VALIDATIONS_BASEDIR
        )
    )
    env['ANSIBLE_CALLBACKS_ENABLED'] = callback_whitelist
    env['ANSIBLE_RETRY_FILES_ENABLED'] = False
    env['ANSIBLE_HOST_KEY_CHECKING'] = False
    env['ANSIBLE_TRANSPORT'] = connection
    env['ANSIBLE_CACHE_PLUGIN_TIMEOUT'] = 7200

    # Set var handling for better performance
    env['ANSIBLE_INJECT_FACT_VARS'] = False
    env['ANSIBLE_VARS_PLUGIN_STAGE'] = 'all'
    env['ANSIBLE_GATHER_SUBSET'] = '!all,min'

    if connection == 'local':
        env['ANSIBLE_PYTHON_INTERPRETER'] = sys.executable

    if gathering_policy in ('smart', 'explicit', 'implicit'):
        env['ANSIBLE_GATHERING'] = gathering_policy

    if module_path:
        env['ANSIBLE_LIBRARY'] = ':'.join(
            [env['ANSIBLE_LIBRARY'], module_path]
        )

    env['TRIPLEO_PLAN_NAME'] = plan

    get_uid = int(os.getenv('SUDO_UID', os.getuid()))
    try:
        user_pwd = pwd.getpwuid(get_uid)
    except (KeyError, TypeError):
        home = constants.CLOUD_HOME_DIR
    else:
        home = user_pwd.pw_dir

    env['ANSIBLE_LOG_PATH'] = os.path.join(home, 'ansible.log')

    if key:
        env['ANSIBLE_PRIVATE_KEY_FILE'] = key

    # NOTE(cloudnull): Re-apply the original environment ensuring that
    # anything defined on the CLI is set accordingly.
    env.update(os.environ.copy())

    if extra_env_variables:
        if not isinstance(extra_env_variables, dict):
            msg = "extra_env_variables must be a dict"
            LOG.error(msg)
            raise SystemError(msg)
        else:
            env.update(extra_env_variables)

    if 'ANSIBLE_CONFIG' not in env and not ansible_cfg:
        ansible_cfg = os.path.join(workdir, 'ansible.cfg')
        config = configparser.ConfigParser()
        if os.path.isfile(ansible_cfg):
            config.read(ansible_cfg)

        if 'defaults' not in config.sections():
            config.add_section('defaults')

        config.set('defaults', 'internal_poll_interval', '0.01')
        with open(ansible_cfg, 'w') as f:
            config.write(f)
        env['ANSIBLE_CONFIG'] = ansible_cfg
    elif 'ANSIBLE_CONFIG' not in env and ansible_cfg:
        env['ANSIBLE_CONFIG'] = ansible_cfg

    command_path = None
    with TempDirs(chdir=False) as ansible_artifact_path:

        r_opts = {
            'private_data_dir': workdir,
            'project_dir': playbook_dir,
            'inventory': _inventory(inventory),
            'envvars': _encode_envvars(env=env),
            'playbook': playbook,
            'verbosity': verbosity,
            'quiet': quiet,
            'extravars': extra_vars,
            'fact_cache': ansible_fact_path,
            'fact_cache_type': 'jsonfile',
            'artifact_dir': ansible_artifact_path,
            'rotate_artifacts': 256
        }

        if skip_tags:
            r_opts['skip_tags'] = skip_tags

        if tags:
            r_opts['tags'] = tags

        if limit_hosts:
            r_opts['limit'] = limit_hosts

        if parallel_run:
            r_opts['directory_isolation_base_path'] = ansible_artifact_path

        runner_config = ansible_runner.runner_config.RunnerConfig(**r_opts)
        runner_config.prepare()
        runner = ansible_runner.Runner(config=runner_config)

        if reproduce_command:
            command_path = os.path.join(
                workdir,
                "ansible-playbook-command.sh"
            )
            with open(command_path, 'w') as f:
                f.write('#!/usr/bin/env bash\n')
                f.write('echo -e "Exporting environment variables"\n')
                for key, value in r_opts['envvars'].items():
                    f.write('export {}="{}"\n'.format(key, value))
                f.write('echo -e "Running Ansible command"\n')
                args = '{} "$@"\n'.format(' '.join(runner_config.command))
                # Single quote the dict passed to -e
                args = re.sub('({.*})', '\'\\1\'', args)
                f.write(args)
            os.chmod(command_path, 0o750)

        try:
            status, rc = runner.run()
        finally:
            # NOTE(cloudnull): After a playbook executes, ensure the log
            #                  file, if it exists, was created with
            #                  appropriate ownership.
            _log_path = r_opts['envvars']['ANSIBLE_LOG_PATH']
            if os.path.isfile(_log_path):
                os.chown(_log_path, get_uid, -1)
            # Save files we care about
            with open(os.path.join(workdir, 'stdout'), 'w') as f:
                f.write(runner.stdout.read())
            for output in 'status', 'rc':
                val = getattr(runner, output)
                if val:
                    with open(os.path.join(workdir, output), 'w') as f:
                        f.write(str(val))

    if rc != 0:
        if rc == 4 and ignore_unreachable:
            LOG.info('Ignoring unreachable nodes')
        else:
            err_msg = (
                'Ansible execution failed. playbook: {},'
                ' Run Status: {},'
                ' Return Code: {}'.format(
                    playbook,
                    status,
                    rc
                )
            )
            if command_path:
                err_msg += (
                    ', To rerun the failed command manually execute the'
                    ' following script: {}'.format(
                        command_path
                    )
                )

            if not quiet:
                LOG.error(err_msg)

            raise RuntimeError(err_msg)

    LOG.info(
        'Ansible execution success. playbook: {}'.format(
            playbook))


def convert(data):
    """Recursively converts dictionary keys,values to strings."""
    if isinstance(data, str):
        return str(data)
    if isinstance(data, collections_abc.Mapping):
        return dict(map(convert, data.items()))
    if isinstance(data, collections_abc.Iterable):
        return type(data)(map(convert, data))
    return data


def bracket_ipv6(address):
    """Put a bracket around address if it is valid IPv6

    Return it unchanged if it is a hostname or IPv4 address.
    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return "[%s]" % address
    except socket.error:
        return address


def is_valid_ip(ip):
    """Return True if the IP is either v4 or v6

    Return False if invalid.
    """
    return netaddr.valid_ipv4(ip) or netaddr.valid_ipv6(ip)


def is_loopback(host):
    """Return True of the IP or the host is a loopback

    Return False if not.
    """
    loopbacks = ['127', '::1']
    for item in loopbacks:
        if host.startswith(item):
            return True
    return False


def get_host_ips(host, socket_type=None):
    """Lookup an host to return a list of IPs.

    :param host: Host to lookup
    :type  host: string

    :param socket_type: Type of a socket (e.g. socket.AF_INET, socket.AF_INET6)
    :type  socket_type: string
    """

    ips = set()
    if socket_type:
        socket_types = (socket_type,)
    else:
        socket_types = (socket.AF_INET, socket.AF_INET6)
    for t in socket_types:
        try:
            res = socket.getaddrinfo(host, None, t, socket.SOCK_STREAM)
        except socket.error:
            continue
        nips = set([x[4][0] for x in res])
        ips.update(nips)
    return list(ips)


def get_single_ip(host, allow_loopback=False, ip_version=4):
    """Translate an hostname into a single IP address if it is a valid IP.

    :param host: IP or hostname or FQDN to lookup
    :type  host: string

    :param allow_loopback: Whether or not a loopback IP can be returned.
    Defaults is False.
    :type  allow_loopback: boolean

    Return the host unchanged if it is already an IPv4 or IPv6 address.
    """

    ip = host
    if not is_valid_ip(host):
        socket_type = socket.AF_INET6 if ip_version == 6 else socket.AF_INET
        ips = get_host_ips(host, socket_type=socket_type)
        if not ips:
            raise exceptions.LookupError('No IP was found for the host: '
                                         '%s' % host)
        else:
            ip = ips[0]
        if len(ips) > 1:
            raise exceptions.LookupError('More than one IP was found for the '
                                         'host %s: %s' % (host, ips))
        if not allow_loopback and is_loopback(ip):
            raise exceptions.LookupError('IP address for host %s is a loopback'
                                         ' IP: %s' % (host, ip))
        if not is_valid_ip(ip):
            raise exceptions.LookupError('IP address for host %s is not a '
                                         'valid IP: %s' % (host, ip))
    return ip


def write_env_file(env_data, env_file, registry_overwrites):
    """Write the tht env file as yaml"""

    data = {'parameter_defaults': env_data}
    if registry_overwrites:
        data['resource_registry'] = registry_overwrites
    with open(env_file, "w") as f:
        dumper = yaml.dumper.SafeDumper
        dumper.ignore_aliases = lambda self, data: True
        yaml.dump(data, f, default_flow_style=False, Dumper=dumper)


def store_cli_param(command_name, parsed_args):
    """write the cli parameters into an history file"""

    # The command name is the part after "openstack" with spaces. Switching
    # to "-" makes it easier to read. "openstack undercloud install" will be
    # stored as "undercloud-install" for example.
    command_name = command_name.replace(" ", "-")

    history_path = os.path.join(constants.CLOUD_HOME_DIR, '.tripleo')
    makedirs(history_path)
    if os.path.isdir(history_path):
        try:
            with open(os.path.join(history_path,
                                   'history'), 'a') as history:
                args = parsed_args.__dict__.copy()
                used_args = ', '.join('%s=%s' % (key, value)
                                      for key, value in args.items())
                history.write(' '.join([str(datetime.datetime.now()),
                                       str(command_name), used_args, "\n"]))
        except IOError as e:
            messages = _("Unable to write into TripleO history file: "
                         "{0}, {1}").format(history_path, e)
            raise IOError(messages)
    else:
        raise exceptions.InvalidConfiguration(_("Target path %s is not a "
                                                "directory") % history_path)


def create_tempest_deployer_input(config_name='tempest-deployer-input.conf',
                                  output_dir=None):
    config = configparser.ConfigParser()

    # Create required sections
    for section in ('auth', 'compute', 'compute-feature-enabled', 'identity',
                    'image', 'network', 'object-storage',
                    'volume', 'volume-feature-enabled'):
        config.add_section(section)

    # Dynamic credentials means tempest will create the required credentials if
    # a test requires a new account to work, tempest will create one just for
    # that test
    config.set('auth', 'use_dynamic_credentials', 'true')

    # Does the test environment support obtaining instance serial console
    # output? (default: true)
    # set in [nova.serial_console]->enabled
    config.set('compute-feature-enabled', 'console_output', 'false')

    # Name of the backend1 (must be declared in cinder.conf)
    # (default: 'BACKEND_1')
    # set in [cinder]->enabled_backends
    config.set('volume', 'backend1_name', 'tripleo_iscsi')

    # Update bootable status of a volume Not implemented on icehouse
    # (default: false)
    # python-cinderclient supports set-bootable
    config.set('volume-feature-enabled', 'bootable', 'true')

    # Fix region value because TripleO is using non-standard value
    for section in ('compute', 'identity', 'image', 'network',
                    'object-storage', 'volume'):
        config.set(section, 'region', 'regionOne')

    if output_dir:
        config_path = os.path.join(output_dir, config_name)
    else:
        config_path = config_name
    with open(config_path, 'w+') as config_file:
        config.write(config_file)


def wait_for_stack_ready(orchestration_client, stack_name, marker=None,
                         action='CREATE', nested_depth=2,
                         max_retries=10):
    """Check the status of an orchestration stack

    Get the status of an orchestration stack and check whether it is complete
    or failed.

    :param orchestration_client: Instance of Orchestration client
    :type  orchestration_client: heatclient.v1.client.Client

    :param stack_name: Name or UUID of stack to retrieve
    :type  stack_name: string

    :param marker: UUID of the last stack event before the current action
    :type  marker: string

    :param action: Current action to check the stack for COMPLETE
    :type action: string

    :param verbose: Whether to print events
    :type verbose: boolean

    :param nested_depth: Max depth to look for events
    :type nested_depth: int

    :param max_retries: Number of retries in the case of server problems
    :type max_retries: int
    """
    log = logging.getLogger(__name__ + ".wait_for_stack_ready")
    stack = get_stack(orchestration_client, stack_name)
    if not stack:
        return False
    stack_name = "%s/%s" % (stack.stack_name, stack.id)

    retries = 0

    while retries <= max_retries:
        try:
            stack_status, msg = event_utils.poll_for_events(
                orchestration_client, stack_name, action=action,
                poll_period=5, marker=marker, out=sys.stdout,
                nested_depth=nested_depth)
            print(msg)
            return stack_status == '%s_COMPLETE' % action
        except hc_exc.HTTPException as e:
            if e.code in [500, 503, 504]:
                retries += 1
                log.warning("Server issue while waiting for stack to be ready."
                            " Attempting retry {} of {}".format(retries,
                                                                max_retries))
                time.sleep(retries * 5)
                continue
            log.error("Error occured while waiting for stack to be ready.")
            raise e

    raise RuntimeError(
        "wait_for_stack_ready: Max retries {} reached".format(max_retries))


def get_stack_output_item(stack, item):
    if not stack:
        return None

    for output in stack.to_dict().get('outputs', {}):
        if output['output_key'] == item:
            return output['output_value']
    # item not found in outputs
    return None


def get_stack_saved_output_item(output, working_dir):
    outputs_dir = os.path.join(working_dir, 'outputs')
    output_path = os.path.join(outputs_dir, output)
    if not os.path.isfile(output_path):
        return None
    with open(output_path) as f:
        return yaml.safe_load(f.read())


def get_overcloud_endpoint(working_dir):
    return get_stack_saved_output_item('KeystoneURL', working_dir)


def get_service_ips(stack):
    service_ips = {}
    for output in stack.to_dict().get('outputs', {}):
        service_ips[output['output_key']] = output['output_value']
    return service_ips


def get_endpoint_map(working_dir):
    endpoint_map = get_stack_saved_output_item('EndpointMap', working_dir)
    if not endpoint_map:
        endpoint_map = {}
    return endpoint_map


def get_excluded_ip_addresses(working_dir):
    return get_stack_saved_output_item(
            'BlacklistedIpAddresses', working_dir)


def get_role_net_ip_map(working_dir):
    return get_stack_saved_output_item(
        'RoleNetIpMap', working_dir)


def get_stack(orchestration_client, stack_name):
    """Get the ID for the current deployed overcloud stack if it exists.

    Caller is responsible for checking if return is None
    """

    try:
        stack = orchestration_client.stacks.get(stack_name)
        return stack
    except HTTPNotFound:
        pass


def get_rc_params(working_dir):
    rc_params = {}
    rc_params['password'] = get_stack_saved_output_item(
        'AdminPassword', working_dir)
    rc_params['region'] = get_stack_saved_output_item(
        'KeystoneRegion', working_dir)
    return rc_params


def check_ceph_ansible(resource_registry, stage):
    """Fail if ceph-ansible is still passed

    If any of the ceph-ansible related resources are part of the
    Ceph services path, then the overcloud deploy (or the stack
    update) should fail, unless they are included in the context
    of Update/Upgrade/Converge, where these environments are still
    relevant and required.
    """

    if not resource_registry or stage not in "DeployOvercloud":
        return

    # for each Ceph related service, fail if ceph-ansible is part
    # of the provided path
    for name, path in resource_registry.items():
        if 'Ceph' in name and 'ceph-ansible' in path:
            raise exceptions.InvalidConfiguration('The Ceph deployment is not '
                                                  'available anymore using '
                                                  'ceph-ansible. If you want '
                                                  'to deploy Ceph, please add '
                                                  'the cephadm environment '
                                                  'file.')


def check_deployed_ceph_stage(environment):
    """Raises an exception if Ceph is being deployed without DeployedCeph:True.

       If Ceph is not being deployed or DeployedCeph is true, then return
       nothing, so the program that calls this function can continue without
       error. This function also looks for the external Ceph Heat resource to
       make sure in this scenario an error is not raised regardless of the
       DeployedCeph boolean value.
    """

    resource_registry = environment.get('resource_registry', {})

    if not resource_registry:
        return

    ceph_external = environment.get('resource_registry', {}).get(
        'OS::TripleO::Services::CephExternal', 'OS::Heat::None')

    if ceph_external != "OS::Heat::None":
        return

    # it's not an external Ceph cluster, let's evaluate the DeployedCeph param
    # and the Ceph resources provided
    deployed_ceph = environment.get('parameter_defaults',
                                    {}).get('DeployedCeph', False)

    # for each ceph resource, if the path contains cephadm and the DeployedCeph
    # boolean is not True, raise an exception and guide the operator through
    # the right path of deploying ceph

    for name, path in resource_registry.items():
        if 'Ceph' in name and 'cephadm' in path and not deployed_ceph:
            raise exceptions.InvalidConfiguration('Ceph deployment is not '
                                                  'available anymore during '
                                                  'overcloud deploy. If you '
                                                  'want to deploy Ceph, '
                                                  'please see "openstack '
                                                  ' overcloud ceph deploy '
                                                  '--help" to deploy ceph '
                                                  ' before deploying the '
                                                  'overcloud and then include '
                                                  'the cephadm environment '
                                                  'file.')


def check_ceph_fsid_matches_env_files(old_env, environment):
    """Check CephClusterFSID against proposed env files

    There have been cases where operators inadvertenly changed the
    CephClusterFSID on a stack update, which is unsupported by both
    Ceph and openstack.
    For this reason we need to check that the existing deployed Ceph
    cluster ID present in the stack is consistent with the value of
    the environment, raising an exception if they are different.
    """
    env_ceph_fsid = environment.get('parameter_defaults',
                                    {}).get('CephClusterFSID', False)
    stack_ceph_fsid = old_env.get('parameter_defaults',
                                  {}).get('CephClusterFSID', False)

    if bool(env_ceph_fsid) and env_ceph_fsid != stack_ceph_fsid:
        raise exceptions.InvalidConfiguration('The CephFSID environment value '
                                              ' ({}) does not match the stack '
                                              ' configuration value ({}).'
                                              ' Ensure the CephClusterFSID '
                                              ' param is properly configured '
                                              ' in the storage environment '
                                              ' files.'
                                              .format(env_ceph_fsid,
                                                      stack_ceph_fsid))


def check_swift_and_rgw(old_env, env, stage):
    """Check that Swift and RGW aren't both enabled in the overcloud

    When Ceph is deployed by TripleO using the default cephadm environment
    file, the RGW component is included by default and deployed on both
    greenfield and brownfield deployments.
    However, if an overcloud upgrade is run and Swift was already deployed,
    the RGW resource shouldn't replace Swift and -e cephadm-rbd-only.yaml
    should be passed.
    For this reason we need to check if Swift was previously enabled, and
    fail if the RGW resource is passed.
    """
    rgw_env = env.get('resource_registry',
                      {}).get('OS::TripleO::Services::CephRgw',
                              'OS::Heat::None')

    allowed_stage = re.compile("(Upgrade|Update)Prepare", re.I)
    # if the RGW resource isn't passed or we're not in the upgrade context
    # there's no need to run this check
    if not re.match(allowed_stage, stage) or rgw_env == 'OS::Heat::None':
        return

    sw = old_env.get('resource_registry',
                     {}).get('OS::TripleO::Services::SwiftProxy',
                             'OS::Heat::None')

    # RGW is present in the env list and swift was previously deployed
    if sw != "OS::Heat::None":
        raise exceptions.InvalidConfiguration('Both Swift and RGW resources '
                                              'detected. '
                                              'Ensure you have only one of '
                                              'them enabled (or provide the '
                                              'cephadm-rbd-only.yaml '
                                              'environment file to exclude '
                                              'RGW)')


def check_network_plugin(output_dir, env):
    """Disallow upgrade if change in network plugin detected

    If the undercloud is upgraded with a change in network plugin
    i.e ovs to ovn or ovn to ovs it will break the undercloud as
    just switching is not enough it needs network resources to be
    migrated, so we detect if there is change in network and block
    the upgrade
    """

    neutron_env = env.get('resource_registry',
                          {}).get('OS::TripleO::Services::NeutronApi',
                                  'OS::Heat::None')

    # Neutron is not deployed so just return
    if neutron_env == "OS::Heat::None":
        return

    parameters = env.get('parameter_defaults', {})

    file_name = constants.TRIPLEO_STATIC_INVENTORY

    inventory_path = os.path.join(output_dir, file_name)

    if not os.path.isfile(inventory_path):
        message = (_("The %s inventory file is missing. Without it "
                     "network plugin change can't be detected, and upgrade "
                     "will have issues if there is a change" % inventory_path))
        LOG.error(message)
        raise exceptions.InvalidConfiguration(message)

    with open(inventory_path, 'r') as f:
        inventory_data = yaml.safe_load(f)

    if ('neutron_ovs_agent' in inventory_data and
            'ovn' in parameters.get('NeutronMechanismDrivers')):
        message = _("Network Plugin mismatch detected, "
                    "Upgrade from ml2 ovs to ml2 ovn is not allowed")
        LOG.error(message)
        raise exceptions.InvalidConfiguration(message)
    elif ("ovn_controller" in inventory_data and
          "openvswitch" in parameters.get('NeutronMechanismDrivers')):
        message = _("Network Plugin mismatch detected, "
                    "Upgrade from ml2 ovn to ml2 ovs is not allowed")
        LOG.error(message)
        raise exceptions.InvalidConfiguration(message)


def check_service_vips_migrated_to_service(environment):
    registry = environment.get('resource_registry', {})
    removed_resources = {'OS::TripleO::Network::Ports::RedisVipPort',
                         'OS::TripleO::Network::Ports::OVNDBsVipPort'}
    msg = ("Resources 'OS::TripleO::Network::Ports::RedisVipPort' and "
           "'OS::TripleO::Network::Ports::OVNDBsVipPort' can no longer be "
           "used. Service VIPs has been moved to the service definition "
           "template. To configure a specific IP address use the parameters "
           "'RedisVirtualFixedIPs' and/or 'OVNDBsVirtualFixedIPs'. To control"
           "the network or subnet for VIP allocation set up the "
           "'ServiceNetMap' and/or 'VipSubnetMap' parameters with the desired "
           "network and/or subnet for the service.")
    for resource in removed_resources:
        if (resource in registry and
                registry.get(resource) != 'OS::Heat::None'):
            raise exceptions.InvalidConfiguration(msg)


def check_neutron_resources(environment):
    registry = environment.get('resource_registry', {})
    msg = ("Resource {} maps to type {} and the Neutron "
           "service is not available when using ephemeral Heat. "
           "The generated environments from "
           "'openstack overcloud baremetal provision' and "
           "'openstack overcloud network provision' must be included "
           "with the deployment command.")
    for rsrc, rsrc_type in registry.items():
        if (type(rsrc_type) == str and
                rsrc_type.startswith("OS::Neutron")):
            raise exceptions.InvalidConfiguration(msg.format(rsrc, rsrc_type))


def remove_known_hosts(overcloud_ip):
    """For a given IP address remove SSH keys from the known_hosts file"""

    known_hosts = os.path.join(constants.CLOUD_HOME_DIR, '.ssh/known_hosts')

    if os.path.exists(known_hosts):
        command = ['ssh-keygen', '-R', overcloud_ip, '-f', known_hosts]
        subprocess.check_call(command)


def file_checksum(filepath, hash_algo='sha512'):
    """Calculate sha512 checksum on file
    :param filepath: Full path to file (e.g. /home/stack/image.qcow2)
    :type  filepath: string
    :param hash_algo: name of the hash algorithm, 'sha512' by default
    :type  hash_algo: string

    :returns: hexadecimal hash of the file

    :raises:
        RuntimeError if the 'hash_algo' value isn't supported.
        ValueError if the path isn't pointing to a regular file.
    """
    if not os.path.isfile(filepath):
        raise ValueError(_("The given file {0} is not a regular "
                           "file").format(filepath))

    if hash_algo not in constants.FIPS_COMPLIANT_HASHES:
        raise RuntimeError(
            "The requested hash algorithm (%s) is not supported." % hash_algo)

    checksum = hashlib.new(hash_algo)

    with open(filepath, 'rb') as f:
        while True:
            fragment = f.read(65536)
            if not fragment:
                break
            checksum.update(fragment)
    return checksum.hexdigest()


def ensure_run_as_normal_user():
    """Check if the command runs under normal user (EUID!=0)"""
    if os.geteuid() == 0:
        raise exceptions.RootUserExecution(_(
            'This command cannot run under root user.'
            ' Switch to a normal user.'))


def get_deployment_user():
    """Return the user name which is used to deploy the cloud"""
    return getpass.getuser()


def capabilities_to_dict(caps):
    """Convert the Node's capabilities into a dictionary."""
    if not caps:
        return {}
    return dict([key.split(':', 1) for key in caps.split(',')])


def dict_to_capabilities(caps_dict):
    """Convert a dictionary into a string with the capabilities syntax."""
    return ','.join(["%s:%s" % (key, value)
                     for key, value in caps_dict.items()
                     if value is not None])


def node_get_capabilities(node):
    """Get node capabilities."""
    return capabilities_to_dict(node.properties.get('capabilities'))


def node_add_capabilities(bm_client, node, **updated):
    """Add or replace capabilities for a node."""
    caps = node_get_capabilities(node)
    caps.update(updated)
    converted_caps = dict_to_capabilities(caps)
    node.properties['capabilities'] = converted_caps
    bm_client.node.update(node.uuid, [{'op': 'add',
                                       'path': '/properties/capabilities',
                                       'value': converted_caps}])
    return caps


def assign_and_verify_profiles(bm_client, flavors,
                               assign_profiles=False, dry_run=False):
    """Assign and verify profiles for given flavors.

    :param bm_client: ironic client instance
    :param flavors: map flavor name -> (flavor object, required count)
    :param assign_profiles: whether to allow assigning profiles to nodes
    :param dry_run: whether to skip applying actual changes (only makes sense
                    if assign_profiles is True)
    :returns: tuple (errors count, warnings count)
    """
    log = logging.getLogger(__name__ + ".assign_and_verify_profiles")
    predeploy_errors = 0
    predeploy_warnings = 0

    # nodes available for deployment and scaling (including active)
    bm_nodes = {node.uuid: node
                for node in bm_client.node.list(maintenance=False,
                                                detail=True)
                if node.provision_state in ('available', 'active')}
    # create a pool of unprocessed nodes and record their capabilities
    free_node_caps = {uu: node_get_capabilities(node)
                      for uu, node in bm_nodes.items()}

    # TODO(dtantsur): use command-line arguments to specify the order in
    # which profiles are processed (might matter for assigning profiles)
    profile_flavor_used = False
    for flavor_name, (flavor, scale) in flavors.items():
        if not scale:
            log.debug("Skipping verification of flavor %s because "
                      "none will be deployed", flavor_name)
            continue

        profile = flavor.get_keys().get('capabilities:profile')
        # If there's only a single flavor, then it's expected for it to have
        # no profile assigned.
        if not profile and len(flavors) > 1:
            predeploy_errors += 1
            log.error(
                'Error: The %s flavor has no profile associated', flavor_name)
            log.error(
                'Recommendation: assign a profile with openstack flavor '
                'set --property "capabilities:profile"="PROFILE_NAME" %s',
                flavor_name)
            continue

        profile_flavor_used = True

        # first collect nodes with known profiles
        assigned_nodes = [uu for uu, caps in free_node_caps.items()
                          if caps.get('profile') == profile]
        required_count = scale - len(assigned_nodes)

        if required_count < 0:
            log.warning('%d nodes with profile %s won\'t be used '
                        'for deployment now', -required_count, profile)
            predeploy_warnings += 1
            required_count = 0
        elif required_count > 0 and assign_profiles:
            # find more nodes by checking XXX_profile capabilities that are
            # set by ironic-inspector or manually
            capability = '%s_profile' % profile
            more_nodes = [
                uu for uu, caps in free_node_caps.items()
                # use only nodes without a know profile
                if not caps.get('profile') and
                caps.get(capability, '').lower() in ('1', 'true') and
                # do not assign profiles for active nodes
                bm_nodes[uu].provision_state == 'available'
            ][:required_count]
            assigned_nodes.extend(more_nodes)
            required_count -= len(more_nodes)

        for uu in assigned_nodes:
            # make sure these nodes are not reused for other profiles
            node_caps = free_node_caps.pop(uu)
            # save profile for newly assigned nodes, but only if we
            # succeeded in finding enough of them
            if not required_count and not node_caps.get('profile'):
                node = bm_nodes[uu]
                if not dry_run:
                    node_add_capabilities(bm_client, node, profile=profile)
                log.info('Node %s was assigned profile %s', uu, profile)
            else:
                log.debug('Node %s has profile %s', uu, profile)

        if required_count > 0:
            log.error(
                "Error: only %s of %s requested ironic nodes are tagged "
                "to profile %s (for flavor %s)",
                scale - required_count, scale, profile, flavor_name
            )
            log.error(
                "Recommendation: tag more nodes using $ openstack baremetal "
                "node set --properties capabilities=profile:%s, <NODE ID>",
                profile)
            predeploy_errors += 1

    nodes_without_profile = [uu for uu, caps in free_node_caps.items()
                             if not caps.get('profile')]
    if nodes_without_profile and profile_flavor_used:
        predeploy_warnings += 1
        log.warning(
            "There are %d ironic nodes with no profile that will "
            "not be used: %s", len(nodes_without_profile),
            ', '.join(nodes_without_profile)
        )

    return predeploy_errors, predeploy_warnings


def add_deployment_plan_arguments(parser):
    """Add deployment plan arguments (flavors and scales) to a parser"""

    # TODO(d0ugal): Deprecated in Newton. Remove these in U.
    parser.add_argument('--control-scale', type=int,
                        help=_('New number of control nodes.'))
    parser.add_argument('--compute-scale', type=int,
                        help=_('New number of compute nodes.'))
    parser.add_argument('--ceph-storage-scale', type=int,
                        help=_('New number of ceph storage nodes.'))
    parser.add_argument('--block-storage-scale', type=int,
                        help=_('New number of cinder storage nodes.'))
    parser.add_argument('--swift-storage-scale', type=int,
                        help=_('New number of swift storage nodes.'))
    parser.add_argument('--control-flavor',
                        help=_('Nova flavor to use for control nodes.'))
    parser.add_argument('--compute-flavor',
                        help=_('Nova flavor to use for compute nodes.'))
    parser.add_argument('--ceph-storage-flavor',
                        help=_('Nova flavor to use for ceph storage nodes.'))
    parser.add_argument('--block-storage-flavor',
                        help=_('Nova flavor to use for cinder storage nodes'))
    parser.add_argument('--swift-storage-flavor',
                        help=_('Nova flavor to use for swift storage nodes'))


def get_roles_info(parsed_args):
    """Get flavor name and scale for all deployment roles.

    :returns: dict role name -> (flavor name, scale)
    """
    return {
        'control': (parsed_args.control_flavor, parsed_args.control_scale),
        'compute': (parsed_args.compute_flavor, parsed_args.compute_scale),
        'ceph-storage': (parsed_args.ceph_storage_flavor,
                         parsed_args.ceph_storage_scale),
        'block-storage': (parsed_args.block_storage_flavor,
                          parsed_args.block_storage_scale),
        'swift-storage': (parsed_args.swift_storage_flavor,
                          parsed_args.swift_storage_scale)
    }


def _csv_to_nodes_dict(nodes_csv):
    """Convert CSV to a list of dicts formatted for os_cloud_config

    Given a CSV file in the format below, convert it into the
    structure expected by os_cloud_config JSON files.

    pm_type, pm_addr, pm_user, pm_password, mac
    """

    data = []

    for row in csv.reader(nodes_csv):
        node = {
            "pm_user": row[2],
            "pm_addr": row[1],
            "pm_password": row[3],
            "pm_type": row[0],
            "mac": [
                row[4]
            ]
        }

        try:
            node['pm_port'] = row[5]
        except IndexError:
            pass

        data.append(node)

    return data


def parse_env_file(env_file, file_type=None):
    if file_type == 'json' or env_file.name.endswith('.json'):
        nodes_config = json.load(env_file)
    elif file_type == 'csv' or env_file.name.endswith('.csv'):
        nodes_config = _csv_to_nodes_dict(env_file)
    elif env_file.name.endswith('.yaml'):
        nodes_config = yaml.safe_load(env_file)
    else:
        raise exceptions.InvalidConfiguration(
            _("Invalid file extension for %s, must be json, yaml or csv") %
            env_file.name)

    if 'nodes' in nodes_config:
        nodes_config = nodes_config['nodes']

    return nodes_config


def prompt_user_for_confirmation(message, logger, positive_response='y'):
    """Prompt user for a y/N confirmation

    Use this function to prompt the user for a y/N confirmation
    with the provided message. The [y/N] should be included in
    the provided message to this function to indicate the expected
    input for confirmation. You can customize the positive response if
    y/N is not a desired input.

    :param message: Confirmation string prompt
    :param logger: logger object used to write info logs
    :param positive_response: Beginning character for a positive user input
    :return: boolean true for valid confirmation, false for all others
    """
    try:
        if not sys.stdin.isatty():
            logger.error(_('User interaction required, cannot confirm.'))
            return False
        sys.stdout.write(message)
        sys.stdout.flush()
        prompt_response = sys.stdin.readline().lower()
        if not prompt_response.startswith(positive_response):
            logger.info(_(
                'User did not confirm action so taking no action.'))
            return False
        logger.info(_('User confirmed action.'))
        return True
    except KeyboardInterrupt:  # ctrl-c
        logger.info(_(
            'User did not confirm action (ctrl-c) so taking no action.'))
    except EOFError:  # ctrl-d
        logger.info(_(
            'User did not confirm action (ctrl-d) so taking no action.'))
    return False


def replace_links_in_template_contents(contents, link_replacement):
    """Replace get_file and type file links in Heat template contents

    If the string contents passed in is a Heat template, scan the
    template for 'get_file' and 'type' occurrences, and replace the
    file paths according to link_replacement dict. (Key/value in
    link_replacement are from/to, respectively.)

    If the string contents don't look like a Heat template, return the
    contents unmodified.
    """

    template = {}
    try:
        template = yaml.safe_load(contents)
    except yaml.YAMLError:
        return contents

    if not (isinstance(template, dict) and
            template.get('heat_template_version')):
        return contents

    template = replace_links_in_template(template, link_replacement)

    return yaml.safe_dump(template)


def replace_links_in_template(template_part, link_replacement):
    """Replace get_file and type file links in a Heat template

    Scan the template for 'get_file' and 'type' occurrences, and
    replace the file paths according to link_replacement
    dict. (Key/value in link_replacement are from/to, respectively.)
    """

    def replaced_dict_value(key, value):
        if ((key == 'get_file' or key == 'type') and
                isinstance(value, str)):
            return link_replacement.get(value, value)
        return replace_links_in_template(value, link_replacement)

    def replaced_list_value(value):
        return replace_links_in_template(value, link_replacement)

    if isinstance(template_part, dict):
        return {k: replaced_dict_value(k, v)
                for k, v in template_part.items()}
    if isinstance(template_part, list):
        return list(map(replaced_list_value, template_part))
    return template_part


def relative_link_replacement(link_replacement, current_dir):
    """Generate a relative version of link_replacement dictionary.

    Get a link_replacement dictionary (where key/value are from/to
    respectively), and make the values in that dictionary relative
    paths with respect to current_dir.
    """

    return {k: os.path.relpath(v, current_dir)
            for k, v in link_replacement.items()}


def load_environment_directories(directories):
    log = logging.getLogger(__name__ + ".load_environment_directories")

    if os.environ.get('TRIPLEO_ENVIRONMENT_DIRECTORY'):
        directories.append(os.environ.get('TRIPLEO_ENVIRONMENT_DIRECTORY'))

    environments = []
    for d in directories:
        if os.path.exists(d) and d != '.':
            log.debug("Environment directory: %s" % d)
            for f in sorted(glob.glob(os.path.join(d, '*.yaml'))):
                log.debug("Environment directory file: %s" % f)
                if os.path.isfile(f):
                    environments.append(f)
    return environments


def get_key(stack, needs_pair=False):
    """Returns the private key from the local file system.

    Searches for and returns the stack private key. If the key is inaccessible
    for any reason, the process will fall back to using the users key. If no
    key is found, this method will return None.

    :params stack: name of the stack to use
    :type stack: String

    :param needs_pair: Enable key pair search
    :type needs_pair: Boolean

    :returns: String || None
    """

    key_files = list()
    stack_dir = get_default_working_dir(stack)
    key_files.append(os.path.join(stack_dir, 'ssh_private_key'))
    user_dir = os.path.join(constants.CLOUD_HOME_DIR, '.ssh')
    key_files.append(os.path.join(user_dir, 'id_rsa_tripleo'))
    key_files.append(os.path.join(user_dir, 'id_rsa'))
    legacy_dir = os.path.join(constants.DEFAULT_WORK_DIR, '.ssh')
    key_files.append(os.path.join(legacy_dir, 'tripleo-admin-rsa'))
    for key_file in key_files:
        try:
            if os.path.exists(key_file):
                if needs_pair:
                    if not os.path.exists('{}.pub'.format(key_file)):
                        continue
                with open(key_file):
                    return key_file
        except IOError:
            pass
    else:
        return


def get_tripleo_ansible_inventory(inventory_file=None,
                                  ssh_user='tripleo-admin',
                                  stack='overcloud',
                                  undercloud_connection='ssh',
                                  return_inventory_file_path=False):
    if not inventory_file:
        inventory_file = os.path.join(
            constants.CLOUD_HOME_DIR,
            'tripleo-ansible-inventory.yaml'
        )

        command = ['/usr/bin/tripleo-ansible-inventory',
                   '--os-cloud', 'undercloud']
        if stack:
            command.extend(['--stack', stack])
            command.extend(['--undercloud-key-file', get_key(stack=stack)])
        if ssh_user:
            command.extend(['--ansible_ssh_user', ssh_user])
        if undercloud_connection:
            command.extend(['--undercloud-connection',
                           undercloud_connection])
        if inventory_file:
            command.extend(['--static-yaml-inventory', inventory_file])
        rc = run_command_and_log(LOG, command)
        if rc != 0:
            message = "Failed to generate inventory"
            raise exceptions.InvalidConfiguration(message)
    if os.path.exists(inventory_file):
        if return_inventory_file_path:
            return inventory_file

        with open(inventory_file, "r") as f:
            inventory = f.read()
        return inventory

    raise exceptions.InvalidConfiguration(_(
        "Inventory file %s can not be found.") % inventory_file)


def cleanup_tripleo_ansible_inventory_file(path):
    """Remove the static tripleo-ansible-inventory file from disk"""
    if os.path.exists(path):
        processutils.execute('/usr/bin/rm', '-f', path)


def get_roles_file_path(working_dir, stack_name):
    roles_file = os.path.join(
        working_dir,
        constants.WD_DEFAULT_ROLES_FILE_NAME.format(stack_name))

    return roles_file


def get_networks_file_path(working_dir, stack_name):
    networks_file = os.path.join(
        working_dir,
        constants.WD_DEFAULT_NETWORKS_FILE_NAME.format(stack_name))

    return networks_file


def get_baremetal_file_path(working_dir, stack_name):
    baremetal_file_name = os.path.join(
        working_dir,
        constants.WD_DEFAULT_BAREMETAL_FILE_NAME.format(stack_name))
    baremetal_file = (baremetal_file_name
                      if os.path.exists(baremetal_file_name) else None)

    return baremetal_file


def get_vip_file_path(working_dir, stack_name):
    vip_file = os.path.join(
        working_dir,
        constants.WD_DEFAULT_VIP_FILE_NAME.format(stack_name))

    return vip_file


def rewrite_ansible_playbook_paths(src, dest):
    """Rewrite relative paths to playbooks in the dest roles file, so that
    the path is the absolute path relative to the src roles file
    """
    with open(dest, 'r') as f:
        wd_roles = yaml.safe_load(f.read())
    for role_idx, role in enumerate(wd_roles):
        for pb_idx, pb_def in enumerate(role.get('ansible_playbooks', [])):
            path = rel_or_abs_path_role_playbook(os.path.dirname(src),
                                                 pb_def['playbook'])
            wd_roles[role_idx]['ansible_playbooks'][pb_idx][
                'playbook'] = path
    with open(dest, 'w') as f:
        f.write(yaml.safe_dump(wd_roles))


def copy_to_wd(working_dir, file, stack, kind):
    src = os.path.abspath(file)
    dest = os.path.join(working_dir,
                        constants.KIND_TEMPLATES[kind].format(stack))
    shutil.copy(src, dest)
    if kind == 'baremetal':
        rewrite_ansible_playbook_paths(src, dest)


def update_working_dir_defaults(working_dir, args):
    stack_name = args.stack
    tht_root = os.path.abspath(args.templates)

    if isinstance(args.baremetal_deployment, str):
        copy_to_wd(working_dir, args.baremetal_deployment, stack_name,
                   'baremetal')

    if args.roles_file:
        copy_to_wd(working_dir, args.roles_file, stack_name, 'roles')
    elif not os.path.exists(
            os.path.join(
                working_dir,
                constants.WD_DEFAULT_ROLES_FILE_NAME.format(stack_name))):
        file = os.path.join(tht_root, constants.OVERCLOUD_ROLES_FILE)
        copy_to_wd(working_dir, file, stack_name, 'roles')

    if args.networks_file:
        copy_to_wd(working_dir, args.networks_file, args.stack, 'networks')
    elif not os.path.exists(
            os.path.join(
                working_dir,
                constants.WD_DEFAULT_NETWORKS_FILE_NAME.format(stack_name))):
        file = os.path.join(tht_root, constants.OVERCLOUD_NETWORKS_FILE)
        copy_to_wd(working_dir, file, stack_name, 'networks')

    if args.vip_file:
        copy_to_wd(working_dir, args.vip_file, args.stack, 'vips')
    elif not os.path.exists(
            os.path.join(
                working_dir,
                constants.WD_DEFAULT_VIP_FILE_NAME.format(stack_name))):
        file = os.path.join(tht_root, constants.OVERCLOUD_VIP_FILE)
        copy_to_wd(working_dir, file, stack_name, 'vips')


def build_stack_data(clients, stack_name, template,
                     files, env_files):
    orchestration_client = clients.orchestration
    fields = {
        'template': template,
        'files': files,
        'environment_files': env_files,
        'show_nested': True
    }
    stack_data = {}
    result = orchestration_client.stacks.validate(**fields)

    if result:
        stack_data['environment_parameters'] = result.get(
            'Environment', {}).get('parameter_defaults')
        flattened = {'resources': {}, 'parameters': {}}
        stack_utils._flat_it(flattened, 'Root', result)
        stack_data['heat_resource_tree'] = flattened

    return stack_data


def archive_deploy_artifacts(log, stack_name, working_dir, ansible_dir=None):
    """Create a tarball of the temporary folders used"""
    log.debug(_("Preserving deployment artifacts"))

    def get_tar_filename():
        return os.path.join(
            working_dir, '%s-install-%s.tar.bzip2' %
            (stack_name,
             datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')))

    def tar_filter(info):
        """Tar filter to remove output dir from path"""
        if info.name.endswith('.bzip2'):
            return None
        leading_path = working_dir[1:] + '/'
        info.name = info.name.replace(leading_path, '')
        return info

    tar_filename = get_tar_filename()
    try:
        tf = tarfile.open(tar_filename, 'w:bz2')
        tf.add(working_dir, recursive=True, filter=tar_filter)
        if ansible_dir:
            tf.add(ansible_dir, recursive=True,
                   filter=tar_filter)
        tf.close()
    except tarfile.TarError as ex:
        msg = _("Unable to create artifact tarball, %s") % str(ex)
        log.warning(msg)
    return tar_filename


def jinja_render_files(log, templates, working_dir,
                       roles_file=None, networks_file=None,
                       base_path=None, output_dir=None):
    python_version = sys.version_info[0]
    python_cmd = "python{}".format(python_version)
    process_templates = os.path.join(
        templates, 'tools/process-templates.py')
    args = [python_cmd, process_templates]
    args.extend(['--roles-data', roles_file])
    args.extend(['--network-data', networks_file])

    if base_path:
        args.extend(['-p', base_path])

    if output_dir:
        args.extend(['-o', output_dir])

    if run_command_and_log(log, args, working_dir) != 0:
        msg = _("Problems generating templates.")
        log.error(msg)
        raise exceptions.DeploymentError(msg)


def rewrite_env_path(env_path, tht_root, user_tht_root, log=None):
    abs_env_path = os.path.abspath(env_path)
    if (abs_env_path.startswith(user_tht_root)
            and ((user_tht_root + '/') in env_path
                 or (user_tht_root + '/') in abs_env_path
                 or user_tht_root == abs_env_path
                 or user_tht_root == env_path)):
        new_env_path = env_path.replace(user_tht_root + '/', tht_root + '/')
        if log:
            log.debug("Redirecting env file %s to %s"
                      % (abs_env_path, new_env_path))
        env_path = new_env_path

    return env_path, abs_env_path


def process_multiple_environments(created_env_files, tht_root,
                                  user_tht_root,
                                  env_files_tracker=None,
                                  cleanup=True):
    log = logging.getLogger(__name__ + ".process_multiple_environments")
    env_files = {}
    localenv = {}
    include_env_in_files = env_files_tracker is not None
    # Normalize paths for full match checks
    user_tht_root = os.path.normpath(user_tht_root)
    tht_root = os.path.normpath(tht_root)
    for env_path in created_env_files:
        log.debug("Processing environment files %s" % env_path)
        env_path, abs_env_path = rewrite_env_path(env_path, tht_root,
                                                  user_tht_root, log=log)
        try:
            files, env = template_utils.process_environment_and_files(
                env_path=env_path, include_env_in_files=include_env_in_files)
            if env_files_tracker is not None:
                env_files_tracker.append(
                    heat_utils.normalise_file_path_to_url(env_path))
        except hc_exc.CommandError as ex:
            # This provides fallback logic so that we can reference files
            # inside the resource_registry values that may be rendered via
            # j2.yaml templates, where the above will fail because the
            # file doesn't exist in user_tht_root, but it is in tht_root
            # See bug https://bugs.launchpad.net/tripleo/+bug/1625783
            # for details on why this is needed (backwards-compatibility)
            log.debug("Error %s processing environment file %s"
                      % (str(ex), env_path))
            # Use the temporary path as it's possible the environment
            # itself was rendered via jinja.
            with open(env_path, 'r') as f:
                env_map = yaml.safe_load(f)
            env_registry = env_map.get('resource_registry', {})
            env_dirname = os.path.dirname(os.path.abspath(env_path))
            for rsrc, rsrc_path in env_registry.items():
                # We need to calculate the absolute path relative to
                # env_path not cwd (which is what abspath uses).
                abs_rsrc_path = os.path.normpath(
                    os.path.join(env_dirname, rsrc_path))
                # If the absolute path matches user_tht_root, rewrite
                # a temporary environment pointing at tht_root instead
                if (abs_rsrc_path.startswith(user_tht_root) and
                    ((user_tht_root + '/') in abs_rsrc_path or
                     abs_rsrc_path == user_tht_root)):
                    new_rsrc_path = abs_rsrc_path.replace(
                        user_tht_root + '/', tht_root + '/')
                    log.debug("Rewriting %s %s path to %s"
                              % (env_path, rsrc, new_rsrc_path))
                    env_registry[rsrc] = new_rsrc_path
                else:
                    # Skip any resources that are mapping to OS::*
                    # resource names as these aren't paths
                    if not rsrc_path.startswith("OS::"):
                        env_registry[rsrc] = abs_rsrc_path
            env_map['resource_registry'] = env_registry
            f_name = os.path.basename(os.path.splitext(abs_env_path)[0])
            with tempfile.NamedTemporaryFile(dir=tht_root,
                                             prefix="env-%s-" % f_name,
                                             suffix=".yaml",
                                             mode="w",
                                             delete=cleanup) as f:
                log.debug("Rewriting %s environment to %s"
                          % (env_path, f.name))
                f.write(yaml.safe_dump(env_map, default_flow_style=False))
                f.flush()
                files, env = template_utils.process_environment_and_files(
                    env_path=f.name, include_env_in_files=include_env_in_files)
                if env_files_tracker is not None:
                    env_files_tracker.append(
                        heat_utils.normalise_file_path_to_url(f.name))
        if files:
            log.debug("Adding files %s for %s" % (files, env_path))
            env_files.update(files)

        # 'env' can be a deeply nested dictionary, so a simple update is
        # not enough
        localenv = template_utils.deep_update(localenv, env)
    return env_files, localenv


def parse_extra_vars(extra_var_strings):
    """Parses extra variables like Ansible would.

    Each element in extra_var_strings is like the raw value of -e
    parameter of ansible-playbook command. It can either be very
    simple 'key=val key2=val2' format or it can be '{ ... }'
    representing a YAML/JSON object.

    The 'key=val key2=val2' format gets processed as if it was
    '{"key": "val", "key2": "val2"}' object, and all YAML/JSON objects
    get shallow-merged together in the order as they appear in
    extra_var_strings, latter objects taking precedence over earlier
    ones.

    :param extra_var_strings: unparsed value(s) of -e parameter(s)
    :type extra_var_strings: list of strings

    :returns dict representing a merged object of all extra vars
    """
    result = {}

    for extra_var_string in extra_var_strings:
        invalid_yaml = False

        try:
            parse_vars = yaml.safe_load(extra_var_string)
        except yaml.YAMLError:
            invalid_yaml = True

        if invalid_yaml or not isinstance(parse_vars, dict):
            try:
                parse_vars = dict(
                    item.split('=') for item in extra_var_string.split())
            except ValueError:
                raise ValueError(
                    'Invalid format for {extra_var_string}'.format(
                        extra_var_string=extra_var_string))

        result.update(parse_vars)

    return result


def prepend_environment(environment_files, templates_dir, environment):
    if not environment_files:
        environment_files = []

    full_path = os.path.join(templates_dir, environment)
    # sanity check it exists before proceeding
    if os.path.exists(full_path):
        # We need to prepend before the files provided by user.
        environment_files.insert(0, full_path)
    else:
        raise exceptions.InvalidConfiguration(_(
            "Expected environment file {0} not found in {1} cannot proceed.")
            .format(environment, templates_dir))

    return environment_files


def get_hostname(short=False):
    """Returns the local hostname

    :param (short): boolean true to run 'hostname -s'
    :return string
    """
    if short:
        cmd = ["hostname", "-s"]
    else:
        cmd = ["hostname"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                         universal_newlines=True)
    return p.communicate()[0].rstrip().lower()


def get_short_hostname():
    """Returns the local short hostname

    :return string
    """
    return get_hostname(short=True)


def wait_api_port_ready(api_port, host='127.0.0.1'):
    """Wait until an http services becomes available

    :param api_port: api service port
    :type  api_port: integer

    :param host: host running the service (default: 127.0.0.1)
    :type host: string

    :return boolean
    """
    log = logging.getLogger(__name__ + ".wait_api_port_ready")
    urlopen_timeout = 1
    max_retries = 30
    count = 0
    while count < max_retries:
        time.sleep(1)
        count += 1
        try:
            request.urlopen(
                "http://%s:%s/" % (host, api_port), timeout=urlopen_timeout)
            return False
        except url_error.HTTPError as he:
            if he.code == 300:
                return True
            pass
        except url_error.URLError:
            pass
        except socket.timeout:
            log.warning(
                "Timeout at attempt {} of {} after {}s waiting for API port..."
                .format(count, max_retries, urlopen_timeout))
            pass
    raise RuntimeError(
        "wait_api_port_ready: Max retries {} reached".format(max_retries))


def bulk_symlink(log, src, dst, tmpd='/tmp'):
    """Create bulk symlinks from a directory

    :param log: logger instance for logging
    :type log: Logger

    :param src: dir of directories to symlink
    :type src: string

    :param dst: dir to create the symlinks
    :type dst: string

    :param tmpd: temporary working directory to use
    :type tmp: string
    """
    log.debug("Symlinking %s to %s, via temp dir %s" %
              (src, dst, tmpd))

    makedirs(dst)
    with TempDirs(dir_path=tmpd) as tmp:
        for obj in os.listdir(src):
            if not os.path.exists(os.path.join(dst, obj)):
                tmpf = os.path.join(tmp, obj)
                os.symlink(os.path.join(src, obj), tmpf)
                os.rename(tmpf, os.path.join(dst, obj))


def run_command_and_log(log, cmd, cwd=None, env=None):
    """Run command and log output

    :param log: logger instance for logging
    :type log: Logger

    :param cmd: command in list form
    :type cmd: List

    :param cwd: current working directory for execution
    :type cmd: String

    :param env: modified environment for command run
    :type env: List
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, shell=False,
                            cwd=cwd, env=env)
    while True:
        try:
            line = proc.stdout.readline()
        except StopIteration:
            break
        if line != b'':
            if isinstance(line, bytes):
                line = line.decode('utf-8')
            log.warning(line.rstrip())
        else:
            break
    proc.stdout.close()
    return proc.wait()


def build_prepare_env(environment_files, environment_directories):
    '''Build the environment for container image prepare

    :param environment_files: List of environment files to build
                             environment from
    :type environment_files: list

    :param environment_directories: List of environment directories to build
                                    environment from
    :type environment_directories: list
    '''
    env_files = []

    if environment_directories:
        env_files.extend(load_environment_directories(
            environment_directories))
    if environment_files:
        env_files.extend(environment_files)

    def get_env_file(method, path):
        if not os.path.exists(path):
            return '{}'
        env_url = heat_utils.normalise_file_path_to_url(path)
        return request.urlopen(env_url).read()

    return (
        template_utils.process_multiple_environments_and_files(
            env_files,
            env_path_is_object=lambda path: True,
            object_request=get_env_file
        )
    )[1]


def rel_or_abs_path(file_path, tht_root):
    '''Find a file, either absolute path or relative to the t-h-t dir'''
    if not file_path:
        return None
    path = os.path.abspath(file_path)
    if not os.path.isfile(path):
        path = os.path.abspath(os.path.join(tht_root, file_path))
    if not os.path.isfile(path):
        raise exceptions.DeploymentError(
            "Can't find path %s %s" % (file_path, path))
    return path


def fetch_roles_file(roles_file, tht_path=constants.TRIPLEO_HEAT_TEMPLATES):
    '''Fetch t-h-t roles data fromm roles_file abs path or rel to tht_path.'''
    if not roles_file:
        return None
    with open(rel_or_abs_path(roles_file, tht_path)) as f:
        return yaml.safe_load(f)


def load_config(osloconf, path):
    '''Load oslo config from a file path. '''
    log = logging.getLogger(__name__ + ".load_config")
    conf_params = []
    if os.path.isfile(path):
        conf_params += ['--config-file', path]
    else:
        log.warning(_('%s does not exist. Using defaults.') % path)
    osloconf(conf_params)


def configure_logging(log, level, log_file):
    '''Mimic oslo_log default levels and formatting for the logger. '''
    fhandler = logging.FileHandler(log_file)
    formatter = logging.Formatter(
        '%(asctime)s.%(msecs)03d %(process)d %(levelname)s '
        '%(name)s [  ] %(message)s',
        '%Y-%m-%d %H:%M:%S')

    if level > 1:
        log.setLevel(logging.DEBUG)
        fhandler.setLevel(logging.DEBUG)
    else:
        # NOTE(bogdando): we are making an exception to the oslo_log'ish
        # default WARN level to have INFO logs as well. Some modules
        # produce INFO msgs we want to see and keep by default, like
        # pre-flight valiation notes.
        log.setLevel(logging.INFO)
        fhandler.setLevel(logging.INFO)

    fhandler.setFormatter(formatter)
    log.addHandler(fhandler)


def _name_helper(basename, arch=None, platform=None, use_subdir=False):
    # NOTE(tonyb): We don't accept a platform with an arch.  This caught when
    # import the nodes / process args, but lets be a little cautious here
    # anyway.
    if use_subdir:
        delim = '/'
    else:
        delim = '-'

    if arch and platform:
        basename = platform + '-' + arch + delim + basename
    elif arch:
        basename = arch + delim + basename
    return basename


def overcloud_kernel(basename, arch=None, platform=None,
                     use_subdir=False):
    return (_name_helper('%s-vmlinuz' % basename, arch=arch,
                         platform=platform, use_subdir=use_subdir),
            '.vmlinuz')


def overcloud_ramdisk(basename, arch=None, platform=None,
                      use_subdir=False):
    return (_name_helper('%s-initrd' % basename, arch=arch,
                         platform=platform, use_subdir=use_subdir),
            '.initrd')


def overcloud_image(basename, arch=None, platform=None,
                    use_subdir=False):
    return (_name_helper(basename, arch=arch, platform=platform,
                         use_subdir=use_subdir),
            '.raw')


def deploy_kernel(basename='agent', arch=None, platform=None,
                  use_subdir=True):
    return _name_helper(basename, arch=arch, platform=platform,
                        use_subdir=use_subdir) + '.kernel'


def deploy_ramdisk(basename='agent', arch=None, platform=None,
                   use_subdir=True):
    return _name_helper(basename, arch=arch, platform=platform,
                        use_subdir=use_subdir) + '.ramdisk'


def _candidate_files(node, call):
    arch = node.get('arch')
    platform = node.get('platform')

    if arch:
        if platform:
            yield call(arch=arch, platform=platform)
        yield call(arch=arch)

    yield call()


def update_nodes_deploy_data(nodes,
                             http_boot=constants.IRONIC_HTTP_BOOT_BIND_MOUNT):
    """Add specific kernel and ramdisk IDs to a node.

    Look at all images and update node data with the most specific
    deploy_kernel and deploy_ramdisk for the architecture/platform combination.
    """
    for node in nodes:

        # NOTE(tonyb): Check to see if we have a specific kernel for this node
        # and use that. Fall back to the generic image.
        if 'kernel_id' not in node:
            kernel_locations = list(_candidate_files(node, deploy_kernel))

            for kernel in kernel_locations:
                path = os.path.join(http_boot, kernel)
                if os.path.exists(path):
                    node['kernel_id'] = 'file://%s/%s' % (
                        http_boot,
                        kernel)
                    break
            else:
                raise RuntimeError('No kernel image provided and none of %s '
                                   'found in %s' % (kernel_locations,
                                                    http_boot))

        # NOTE(tonyb): As above except for ramdisks
        if 'ramdisk_id' not in node:
            ramdisk_locations = list(_candidate_files(node, deploy_ramdisk))

            for ramdisk in ramdisk_locations:
                path = os.path.join(http_boot, ramdisk)
                if os.path.exists(path):
                    node['ramdisk_id'] = 'file://%s/%s' % (
                        http_boot,
                        ramdisk)
                    break
            else:
                raise RuntimeError('No ramdisk image provided and none of %s '
                                   'found in %s' % (ramdisk_locations,
                                                    http_boot))


def get_deployment_python_interpreter(parsed_args):
    """Return correct deployment python interpreter """
    if parsed_args.deployment_python_interpreter:
        return parsed_args.deployment_python_interpreter
    return sys.executable


def run_command(args, env=None, name=None, logger=None):
    """Run the command defined by args and return its output

    :param args: List of arguments for the command to be run.
    :param env: Dict defining the environment variables. Pass None to use
        the current environment.
    :param name: User-friendly name for the command being run. A value of
        None will cause args[0] to be used.
    """
    if logger is None:
        logger = LOG
    if name is None:
        name = args[0]
    try:
        output = subprocess.check_output(args,
                                         stderr=subprocess.STDOUT,
                                         env=env)
        if isinstance(output, bytes):
            output = output.decode('utf-8')
        return output
    except subprocess.CalledProcessError as e:
        message = '%s failed: %s' % (name, e.output)
        logger.error(message)
        raise RuntimeError(message)


def set_hostname(hostname):
    """Set system hostname to provided hostname

    :param hostname: The hostname to set
    """
    args = ['sudo', 'hostnamectl', 'set-hostname', hostname]
    return run_command(args, name='hostnamectl')


def check_hostname(fix_etc_hosts=True, logger=None):
    """Check system hostname configuration

    Rabbit and Puppet require pretty specific hostname configuration. This
    function ensures that the system hostname settings are valid before
    continuing with the installation.

    :param fix_etc_hosts: Boolean to to enable adding hostname to /etc/hosts
        if not found.
    """
    if logger is None:
        logger = LOG
    logger.info('Checking for a FQDN hostname...')
    args = ['hostnamectl', '--static']
    detected_static_hostname = run_command(args, name='hostnamectl').rstrip()
    logger.info('Static hostname detected as %s', detected_static_hostname)
    args = ['hostnamectl', '--transient']
    detected_transient_hostname = run_command(args,
                                              name='hostnamectl').rstrip()
    logger.info('Transient hostname detected as %s',
                detected_transient_hostname)
    if detected_static_hostname != detected_transient_hostname:
        logger.error('Static hostname "%s" does not match transient hostname '
                     '"%s".', detected_static_hostname,
                     detected_transient_hostname)
        logger.error('Use hostnamectl to set matching hostnames.')
        raise RuntimeError('Static and transient hostnames do not match')
    short_hostname = detected_static_hostname.split('.')[0]
    if short_hostname == detected_static_hostname:
        message = _('Configured hostname is not fully qualified.')
        logger.error(message)
        raise RuntimeError(message)
    with open('/etc/hosts') as hosts_file:
        for line in hosts_file:
            # check if hostname is in /etc/hosts
            if (not line.lstrip().startswith('#') and
                    detected_static_hostname in line.split()):
                break
        else:
            # hostname not found, add it to /etc/hosts
            if not fix_etc_hosts:
                return
            sed_cmd = (r'sed -i "s/127.0.0.1\(\s*\)/127.0.0.1\\1%s %s /" '
                       '/etc/hosts' %
                       (detected_static_hostname, short_hostname))
            args = ['sudo', '/bin/bash', '-c', sed_cmd]
            run_command(args, name='hostname-to-etc-hosts')
            logger.info('Added hostname %s to /etc/hosts',
                        detected_static_hostname)


def check_env_for_proxy(no_proxy_hosts=None):
    """Check env proxy settings

    :param no_proxy_hosts: array of hosts to check if in no_proxy env var
    """
    if no_proxy_hosts is None:
        no_proxy_hosts = ['127.0.0.1']
    http_proxy = os.environ.get('http_proxy')
    https_proxy = os.environ.get('https_proxy')
    if os.environ.get('no_proxy'):
        no_proxy = os.environ.get('no_proxy').split(',')
    else:
        no_proxy = []
    missing_hosts = []
    if http_proxy or https_proxy:
        missing_hosts = set(no_proxy_hosts) - set(no_proxy)
    if missing_hosts:
        message = _('http_proxy or https_proxy is set but the following local '
                    'addresses "{}" may be missing from the no_proxy '
                    'environment variable').format(','.join(missing_hosts))
        raise RuntimeError(message)


def get_read_config(cfg):
    """Return the config read from ini config file(s)"""
    config = configparser.ConfigParser()
    config.read(cfg)
    return config


def getboolean_from_cfg(cfg, param, section="DEFAULT"):
    """Return a parameter from Kolla config"""
    return _get_from_cfg(cfg, cfg.getboolean, param, section)


def get_from_cfg(cfg, param, section="DEFAULT"):
    """Return a parameter from Kolla config"""
    return _get_from_cfg(cfg, cfg.get, param, section)


def _get_from_cfg(cfg, accessor, param, section):
    """Return a parameter from Kolla config"""
    try:
        val = accessor(section, param)
    except (ValueError, configparser.Error):
        raise exceptions.NotFound(_("Unable to find {section}/{option} in "
                                    "{config}").format(section=param,
                                                       option=section,
                                                       config=cfg))
    return val


def get_local_timezone():
    info = run_command(['timedatectl'], name='timedatectl')
    timezoneline = [tz for tz in info.split('\n') if 'Time zone:' in tz]
    if not timezoneline:
        LOG.warning('Unable to determine timezone, using UTC')
        return 'UTC'
    # The line returned is "[whitespace]Time zone: [timezone] ([tz], [offset])"
    try:
        timezone = timezoneline[0].strip().split(' ')[2]
    except IndexError:
        LOG.error('Unable to parse timezone from timedatectl, using UTC')
        timezone = 'UTC'
    return timezone


def check_file_for_enabled_service(env_file):
    """Checks environment file for the said service.

    If stack to be to be deployed/updated/upgraded has any deprecated service
    enabled, throw a warning about its deprecation and ask the user
    whether to proceed with deployment despite deprecation.
    For ODL as an example:

    :param env_file: The path of the environment file
    :type env_file: String

    :raises CommandError: If the action is not confirmed
    """
    if os.path.exists(env_file):
        with open(env_file, "r") as f:
            content = yaml.safe_load(f)
        deprecated_services_enabled = []
        for service in constants.DEPRECATED_SERVICES.keys():
            try:
                if content["resource_registry"][service] != "OS::Heat::None":
                    LOG.warning("service " + service + " is enabled in "
                                + str(env_file) + ". " +
                                constants.DEPRECATED_SERVICES[service])
                    deprecated_services_enabled.append(service)
            except (KeyError, TypeError):
                # ignore if content["resource_registry"] is empty
                pass
        if deprecated_services_enabled:
            confirm = prompt_user_for_confirmation(
                message="Do you still wish to continue with deployment [y/N]",
                logger=LOG)
            if not confirm:
                raise oscexc.CommandError("Action not confirmed, exiting.")


def check_deprecated_service_is_enabled(environment_files):
    for env_file in environment_files:
        check_file_for_enabled_service(env_file)


def reset_cmdline():
    """Run reset to cleanup cmdline"""
    # only try to reset if stdout is a terminal, skip if not (e.g. CI)
    if not sys.stdout.isatty():
        return
    output = ''
    try:
        output = run_command(['reset', '-I'])
    except RuntimeError:
        LOG.warning('Unable to reset command line. Try manually running '
                    '"reset" if the command line is broken.')
    sys.stdout.write(output)
    sys.stdout.flush()


def safe_write(path, data):
    '''Write to disk and exit safely if can not write correctly.'''
    log = logging.getLogger(__name__ + ".safe_write")

    if os.path.exists(path):
        log.warning(
            "The output file %s will be overriden",
            path
        )

    try:
        data = data.decode('utf-8', 'ignore')
    except (UnicodeDecodeError, AttributeError):
        pass

    try:
        with os.fdopen(os.open(path,
                       os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o666),
                       'w') as f:
            f.write(data)
    except OSError as error:
        if error.errno != errno.EEXIST:
            msg = _(
                'The output file {file} can not be created. Error: {msg}'
            ).format(file=path, msg=str(error))
            raise oscexc.CommandError(msg)


def copy_clouds_yaml(user):
    """Copy clouds.yaml file from /etc/openstack to deployment user's home

    :param user: deployment user
    """
    clouds_etc_file = '/etc/openstack/clouds.yaml'
    clouds_home_dir = os.path.expanduser("~{}".format(user))
    clouds_config_dir = os.path.join(clouds_home_dir, '.config')
    clouds_openstack_config_dir = os.path.join(clouds_config_dir,
                                               'openstack')
    clouds_config_file = os.path.join(clouds_openstack_config_dir,
                                      'clouds.yaml')
    clouds_user_id = os.stat(clouds_home_dir).st_uid
    clouds_group_id = os.stat(clouds_home_dir).st_gid

    # If the file doesn't exist, we don't need to copy
    # /etc/openstack/clouds.yaml to the user directory.
    if not os.path.isfile(clouds_etc_file):
        return

    if not os.path.exists(clouds_openstack_config_dir):
        try:
            os.makedirs(clouds_openstack_config_dir)
        except OSError as e:
            messages = _("Unable to create credentials directory: "
                         "{0}, {1}").format(clouds_openstack_config_dir, e)
            raise OSError(messages)

    # Using 'sudo' here as for the overcloud the deployment command is run
    # from regular deployment user.
    cp_args = ['sudo', 'cp', clouds_etc_file, clouds_openstack_config_dir]
    if run_command_and_log(LOG, cp_args) != 0:
        msg = _('Error when user %(user)s tried to copy %(src)s to %(dest)s'
                ' with sudo') % {'user': user, 'src': clouds_etc_file,
                                 'dest': clouds_openstack_config_dir}
        LOG.error(msg)
        raise exceptions.DeploymentError(msg)
    chmod_args = ['sudo', 'chmod', '0600', clouds_config_file]
    if run_command_and_log(LOG, chmod_args) != 0:
        msg = _('Error when user %(user)s tried to chmod %(file)s file'
                ' with sudo') % {'user': user, 'file': clouds_config_file}
        LOG.error(msg)
        raise exceptions.DeploymentError(msg)
    chown_args = ['sudo', 'chown', '-R',
                  str(clouds_user_id) + ':' + str(clouds_group_id),
                  clouds_config_dir]
    if run_command_and_log(LOG, chown_args) != 0:
        msg = _('Error when user %(user)s tried to chown %(dir)s directory'
                ' with sudo') % {'user': user, 'dir': clouds_config_dir}
        LOG.error(msg)
        raise exceptions.DeploymentError(msg)


def get_status_yaml(stack_name, working_dir):
    status_yaml = os.path.join(
        working_dir,
        '%s-deployment_status.yaml' % stack_name)
    return status_yaml


def update_deployment_status(stack_name, status, working_dir):
    """Update the deployment status."""

    contents = yaml.safe_dump(
        {'deployment_status': status},
        default_flow_style=False)

    safe_write(get_status_yaml(stack_name, working_dir),
               contents)


def create_breakpoint_cleanup_env(tht_root, stack):
    bp_env = {}
    update.add_breakpoints_cleanup_into_env(bp_env)
    env_path = write_user_environment(
        bp_env,
        'tripleoclient-breakpoint-cleanup.yaml',
        tht_root,
        stack)
    return [env_path]


def create_parameters_env(parameters, tht_root, stack,
                          env_file='tripleoclient-parameters.yaml'):
    parameter_defaults = {"parameter_defaults": parameters}
    env_path = write_user_environment(
        parameter_defaults,
        env_file,
        tht_root,
        stack)
    return [env_path]


def build_user_env_path(abs_env_path, tht_root):
    env_dirname = os.path.dirname(abs_env_path)
    user_env_dir = os.path.join(
        tht_root, 'user-environments', env_dirname[1:])
    user_env_path = os.path.join(
        user_env_dir, os.path.basename(abs_env_path))
    makedirs(user_env_dir)
    return user_env_path


def write_user_environment(env_map, abs_env_path, tht_root,
                           stack):
    # We write the env_map to the local /tmp tht_root and also
    # to the swift plan container.
    contents = yaml.safe_dump(env_map, default_flow_style=False)
    user_env_path = build_user_env_path(abs_env_path, tht_root)
    LOG.debug("user_env_path=%s" % user_env_path)
    with open(user_env_path, 'w') as f:
        LOG.debug("Writing user environment %s" % user_env_path)
        f.write(contents)
    return user_env_path


def launch_heat(launcher=None, restore_db=False, heat_type='pod'):

    global _local_orchestration_client
    global _heat_pid

    if _local_orchestration_client:
        print("returning cached")
        return _local_orchestration_client

    if not launcher:
        launcher = get_heat_launcher(heat_type)

    _heat_pid = 0
    if launcher.heat_type == 'native':
        _heat_pid = os.fork()
    if _heat_pid == 0:
        launcher.check_database()
        launcher.check_message_bus()
        launcher.heat_db_sync(restore_db)
        launcher.launch_heat()

    # Wait for the API to be listening
    heat_api_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_heat_api_port(heat_api_socket, launcher.host, int(launcher.api_port))
    if launcher.heat_type == 'pod':
        launcher.wait_for_message_queue()

    _local_orchestration_client = tc_heat_utils.local_orchestration_client(
        launcher.host, launcher.api_port)
    return _local_orchestration_client


@retry(stop=(stop_after_delay(10) | stop_after_attempt(10)),
       wait=wait_fixed(0.5))
def test_heat_api_port(heat_api_socket, host, port):
    heat_api_socket.connect((host, port))


def get_heat_launcher(heat_type, *args, **kwargs):
    if heat_type == 'native':
        return heat_launcher.HeatNativeLauncher(*args, **kwargs)
    if heat_type == 'container':
        return heat_launcher.HeatContainerLauncher(*args, **kwargs)
    return heat_launcher.HeatPodLauncher(*args, **kwargs)


def kill_heat(launcher):
    global _heat_pid
    if _heat_pid:
        LOG.debug("Attempting to kill heat pid %s" % _heat_pid)
    launcher.kill_heat(_heat_pid)


def rm_heat(launcher, backup_db=True):
    launcher.rm_heat(backup_db)


def get_default_working_dir(stack):
    return os.path.join(
        os.path.expanduser('~'),
        "overcloud-deploy", stack)


def get_ctlplane_attrs():
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


def cleanup_host_entry(entry):
    # remove any tab or space excess
    entry_stripped = re.sub('[ \t]+', ' ', str(entry).rstrip())
    # removes any duplicate identical lines
    unique_lines = list(set(entry_stripped.splitlines()))
    ret = ''
    for line in unique_lines:
        # remove any duplicate word
        hosts_unique = (' '.join(
            collections.OrderedDict((w, w) for w in line.split()).keys()))
        if hosts_unique != '':
            ret += hosts_unique + '\n'
    return ret.rstrip('\n')


def get_undercloud_host_entry():
    """Get hosts entry for undercloud ctlplane network

    The host entry will be added on overcloud nodes
    """
    ctlplane_hostname = '.'.join([get_short_hostname(), 'ctlplane'])
    cmd = ['getent', 'hosts', ctlplane_hostname]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               universal_newlines=True)
    out, err = process.communicate()
    if process.returncode != 0:
        raise exceptions.DeploymentError('No entry for %s in /etc/hosts'
                                         % ctlplane_hostname)
    return cleanup_host_entry(out)


def get_roles_data(working_dir, stack_name):
    abs_roles_file = get_roles_file_path(working_dir, stack_name)
    with open(abs_roles_file, 'r') as fp:
        roles_data = yaml.safe_load(fp)

    return roles_data


def build_enabled_sevices_image_params(env_files, parsed_args,
                                       new_tht_root, user_tht_root,
                                       working_dir):
    params = dict()
    if parsed_args.environment_directories:
        env_files.extend(load_environment_directories(
            parsed_args.environment_directories))
    if parsed_args.environment_files:
        env_files.extend(parsed_args.environment_files)

    _, env = process_multiple_environments(
        env_files, new_tht_root, user_tht_root,
        cleanup=(not parsed_args.no_cleanup))

    roles_data = get_roles_data(working_dir, parsed_args.stack)

    params.update(kolla_builder.get_enabled_services(env, roles_data))
    params.update(plan_utils.default_image_params())

    if parsed_args.disable_container_prepare:
        return params

    params.update(
        kolla_builder.container_images_prepare_multi(
            env, roles_data,
            dry_run=True)
    )

    for role in roles_data:
        # NOTE(tkajinam): If a role-specific container image prepare
        #                 parameter is set, run the image prepare process
        #                 with the overridden environment
        role_param = '%sContainerImagePrepare' % role['name']
        if env.get('parameter_defaults', {}).get(role_param):
            tmp_env = copy.deepcopy(env)
            tmp_env['parameter_defaults']['ContainerImagePrepare'] = (
                env['parameter_defaults'][role_param]
            )

            # NOTE(tkajinam): Put the image parameters as role-specific
            #                 parameters
            params['%sParameters' % role['name']] = (
                kolla_builder.container_images_prepare_multi(
                    tmp_env, [role], dry_run=True)
            )

    return params


def copy_env_files(files_dict, tht_root):
    file_prefix = "file://"

    for full_path in files_dict.keys():
        if not full_path.startswith(file_prefix):
            continue

        path = full_path[len(file_prefix):]

        if path.startswith(tht_root):
            continue

        relocate_path = os.path.join(tht_root, "user-environments",
                                     os.path.basename(path))
        safe_write(relocate_path, files_dict[full_path])


def is_network_data_v2(networks_file_path):
    """Parse the network data, if any network have 'ip_subnet' or
    'ipv6_subnet' keys this is not a network-v2 format file.

    :param networks_file_path:
    :return: boolean
    """
    with open(networks_file_path, 'r') as f:
        network_data = yaml.safe_load(f.read())

    if isinstance(network_data, list):
        for network in network_data:
            if 'ip_subnet' in network or 'ipv6_subnet' in network:
                return False

    return True


def rel_or_abs_path_role_playbook(roles_file_dir, playbook):
    if os.path.isabs(playbook):
        playbook_path = playbook
    else:
        # Load for playbook relative to the roles file
        playbook_path = os.path.join(roles_file_dir, playbook)

    return playbook_path


def validate_roles_playbooks(roles_file_dir, roles):
    not_found = []
    playbooks = []
    for role in roles:
        playbooks.extend(role.get('ansible_playbooks', []))

    for x in playbooks:
        path = rel_or_abs_path_role_playbook(roles_file_dir, x['playbook'])
        if not os.path.exists(path) or not os.path.isfile(path):
            not_found.append(path)

    if not_found:
        raise exceptions.InvalidPlaybook(
            'Invalid Playbook(s) {}, file(s) not found.'.format(
                ', '.join(not_found)))


def run_role_playbook(self, inventory, relative_dir, playbook,
                      limit_hosts=None, extra_vars=dict()):
    playbook_path = rel_or_abs_path_role_playbook(relative_dir, playbook)
    playbook_dir = os.path.dirname(playbook_path)

    with TempDirs() as tmp:
        run_ansible_playbook(
            playbook=playbook_path,
            inventory=inventory,
            workdir=tmp,
            playbook_dir=playbook_dir,
            verbosity=playbook_verbosity(self=self),
            limit_hosts=limit_hosts,
            extra_vars=extra_vars,
        )


def run_role_playbooks(self, working_dir, roles_file_dir, roles,
                       network_config=True):
    inventory_file = os.path.join(working_dir,
                                  'tripleo-ansible-inventory.yaml')
    with open(inventory_file, 'r') as f:
        inventory = yaml.safe_load(f.read())

    growvols_play = 'cli-overcloud-node-growvols.yaml'
    growvols_path = rel_or_abs_path_role_playbook(
        constants.ANSIBLE_TRIPLEO_PLAYBOOKS, growvols_play)

    # Pre-Network Config
    for role in roles:
        if role.get('count', 1) == 0:
            continue

        role_playbooks = []

        for x in role.get('ansible_playbooks', []):
            role_playbooks.append(x['playbook'])

            run_role_playbook(self, inventory, roles_file_dir, x['playbook'],
                              limit_hosts=role['name'],
                              extra_vars=x.get('extra_vars', {}))

        if growvols_path not in role_playbooks:
            # growvols was not run with custom extra_vars, run it with defaults
            run_role_playbook(self, inventory,
                              constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                              growvols_play,
                              limit_hosts=role['name'])

    if network_config:
        # Network Config
        run_role_playbook(self, inventory, constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                          'cli-overcloud-node-network-config.yaml')


def create_archive_dir(archive_dir=constants.TRIPLEO_ARCHIVE_DIR):
    """Create the TripleO archive directory as root. The directory is created
    in a location typically owned by root (/var/lib), and remains owned as root
    to decrease the chance it is accidentally deleted by a normal user.

    :param archive_dir: The archive directory to create
    :type archive_dir: string

    :return: None
    """
    return run_command(['sudo', 'mkdir', '-p', archive_dir])


def extend_protected_overrides(protected_overrides, output_path):
    with open(output_path, 'r') as env_file:
        data = yaml.safe_load(env_file.read())

    protect_registry = protected_overrides['registry_entries']
    resource_registry = data.get('resource_registry', {})

    for reg_entry in resource_registry.keys():
        protect_registry.setdefault(reg_entry, []).append(output_path)


def check_prohibited_overrides(protected_overrides, user_environments):
    found_conflict = False
    protected_registry = protected_overrides['registry_entries']
    msg = ("ERROR: Protected resource registry overrides detected! These "
           "entries are used in internal environments and should not be "
           "overridden in the user environment. Please remove these overrides "
           "from the environment files.\n")
    for env_path, abs_env_path in user_environments:
        with open(env_path, 'r') as file:
            data = yaml.safe_load(file.read())

        _resource_registry = data.get('resource_registry')
        if isinstance(_resource_registry, dict):
            registry = set(_resource_registry.keys())
        else:
            registry = set()

        conflicts = set(protected_registry.keys()).intersection(registry)
        if not conflicts:
            continue

        found_conflict = True
        for x in conflicts:
            msg += ("Conflict detected for resource_registry entry: {}.\n"
                    "\tUser environment: {}.\n"
                    "\tInternal environment: {}\n").format(
                x, abs_env_path, protected_registry[x])

    if found_conflict:
        raise exceptions.DeploymentError(msg)


def parse_container_image_prepare(tht_key='ContainerImagePrepare',
                                  keys=[], source=None,
                                  push_sub_keys=[]):
    """Extracts key/value pairs from list of keys in source file
    If keys=[foo,bar] and source is the following,
    then return {foo: 1, bar: 2}

    parameter_defaults:
      ContainerImagePrepare:
      - tag_from_label: grault
        push_destination: quux.com
        set:
          foo: 1
          bar: 2
          namespace: quay.io/garply
      ContainerImageRegistryCredentials:
        'quay.io': {'quay_username': 'quay_password'}

    If push_destination tag is present as above and push_sub_keys
    contains 'namespace', then the returned dictionary d will
    contain d['namespace'] = 'quux.com/garply'.

    Alternatively, if tht_key='ContainerImageRegistryCredentials' and
    keys=['quay.io/garply'] for the above, then return the following:

    {'registry_url': 'quay.io',
     'registry_username': 'quay_username',
     'registry_password': 'quay_password'}

    If the tht_key is not found, return an empty dictionary

    :param tht_key: string of a THT parameter (only 2 options)
    :param keys: list of keys to extract
    :param source: (string) path to container_image_prepare_defaults.yaml
    :param push_sub_keys: list of keys to have substitutions if push_desination

    :return: dictionary
    """
    image_map = {}
    if source is None:
        source = kolla_builder.DEFAULT_PREPARE_FILE
    if not os.path.exists(source):
        raise RuntimeError(
            "Path to container image prepare defaults file "
            "not found: %s." % os.path.abspath(source))
    with open(source, 'r') as stream:
        try:
            images = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            raise RuntimeError(
                "yaml.safe_load(%s) returned '%s'" % (source, exc))

    if tht_key == 'ContainerImagePrepare':
        try:
            push = ''
            tag_list = images['parameter_defaults'][tht_key]
            for key in keys:
                for tag in tag_list:
                    if 'push_destination' in tag:
                        # substitute discovered registry
                        # if push_destination is set to true
                        if isinstance(tag['push_destination'], bool) and \
                           tag['push_destination']:
                            push = image_uploader.get_undercloud_registry()
                            if len(push_sub_keys) > 0:
                                image_map['push_destination_boolean'] = True
                        elif isinstance(tag['push_destination'], str):
                            push = tag['push_destination']
                            if len(push_sub_keys) > 0:
                                image_map['push_destination_boolean'] = True
                        elif len(push_sub_keys) > 0:
                            image_map['push_destination_boolean'] = False
                    if 'set' in tag:
                        if key in tag['set']:
                            image_map[key] = tag['set'][key]
                            if len(push) > 0 and key in push_sub_keys:
                                # replace the host portion of the imagename
                                # with the push_destination, since that is
                                # where they will be uploaded to
                                image = image_map[key].partition('/')[2]
                                image_map[key] = os.path.normpath(
                                    os.path.join(push, image))
        except KeyError:
            raise RuntimeError(
                "The expected parameter_defaults and %s are not "
                "defined in data file: %s" % (tht_key, source))
    elif tht_key == 'ContainerImageRegistryCredentials':
        try:
            tag_list = images['parameter_defaults'][tht_key]
            for key in keys:
                for tag in tag_list:
                    registry = url_parse.urlparse(key).netloc
                    if len(registry) == 0:
                        registry = url_parse.urlparse('//' + key).netloc
                    if tag == registry:
                        if isinstance(tag_list[registry],
                                      collections.abc.Mapping):
                            credentials = tag_list[registry].popitem()
                            image_map['registry_username'] = credentials[0]
                            image_map['registry_password'] = credentials[1]
                            image_map['registry_url'] = registry
        except KeyError:
            LOG.info("Unable to parse %s from %s. "
                     "Assuming the container registry does not "
                     "require authentication or that the "
                     "registry URL, username and password "
                     "will be passed another way."
                     % (tht_key, source))
    else:
        raise RuntimeError("Unsupported tht_key: %s" % tht_key)
    return image_map


def get_parameter_file(path):
    """Retrieve parameter json file from the supplied path.
    If the file doesn't exist, or if the decoding fails, log the failure
    and return `None`.
    :param path: path to the parameter file
    :dtype path: `string`
    """
    file_data = None
    if os.path.exists(path):
        with open(path, 'r') as parameter_file:
            try:
                file_data = json.load(parameter_file)
            except (TypeError, json.JSONDecodeError) as e:
                LOG.error(
                    _('Could not read file %s') % path)
                LOG.error(e)
    else:
        LOG.warning('File %s was not found during export' %
                    path)
    return file_data


def parse_ansible_inventory(inventory_file, group):
    """ Retrieve a list of hosts from a defined ansible inventory file.
    :param inventory: Ansible inventory file
    :param group: The group to return hosts from, default will be 'all'
    :return: list of hosts in the inventory matching the pattern
    """

    inventory = InventoryManager(loader=DataLoader(),
                                 sources=[inventory_file])

    return(inventory.get_hosts(pattern=group))


def save_stack(stack, working_dir):
    if not stack:
        return
    outputs_dir = os.path.join(working_dir, 'outputs')
    makedirs(outputs_dir)
    for output in constants.STACK_OUTPUTS:
        val = get_stack_output_item(stack, output)
        output_path = os.path.join(outputs_dir, output)
        with open(output_path, 'w') as f:
            f.write(yaml.dump(val))
    env_dir = os.path.join(working_dir, 'environment')
    makedirs(env_dir)
    env = stack.environment()
    env_path = os.path.join(
        env_dir,
        constants.STACK_ENV_FILE_NAME.format(stack.stack_name))
    with open(env_path, 'w') as f:
        f.write(yaml.dump(env))


def get_saved_stack_env(working_dir, stack_name):
    env_path = os.path.join(
        working_dir, 'environment',
        constants.STACK_ENV_FILE_NAME.format(stack_name))
    if not os.path.isfile(env_path):
        return None
    with open(env_path) as f:
        return yaml.safe_load(f.read())


def get_ceph_networks(network_data_path,
                      public_network_name,
                      cluster_network_name):
    """Get {public,cluster}_network{,_name} from network_data_path file
    :param network_data_path: the path to a network_data.yaml file
    :param str public_network_name: name of public_network, e.g. storage
    :param str cluster_network_name: name of cluster_network, e.g. storage_mgmt
    :return: dict mapping two network names and two CIDRs for cluster + public
             with ms_bind_ipv4 and ms_bind_ipv6 booleans set.

    The network_data_path is searched for networks with name_lower values of
    storage and storage_mgmt by default. If none found, then search repeats
    but with service_net_map_replace in place of name_lower. The params
    public_network_name or cluster_network_name override name of the searched
    for network from storage or storage_mgmt so a customized name may be used.
    The public_network and cluster_network (without '_name') are the subnets
    for each network, e.g. 192.168.24.0/24, as mapped by the ip_subnet key.
    If the found network has >1 subnet, all ip_subnets are combined.
    """
    # default to ctlplane if nothing found in network_data
    storage_net_map = {}
    storage_net_map['public_network_name'] = constants.CTLPLANE_NET_NAME
    storage_net_map['cluster_network_name'] = constants.CTLPLANE_NET_NAME
    storage_net_map['public_network'] = constants.CTLPLANE_CIDR_DEFAULT
    storage_net_map['cluster_network'] = constants.CTLPLANE_CIDR_DEFAULT
    storage_net_map['ms_bind_ipv4'] = True
    storage_net_map['ms_bind_ipv6'] = False
    # this dict makes it easier to search for each network type in a loop
    net_type = {}
    net_type['public_network_name'] = public_network_name
    net_type['cluster_network_name'] = cluster_network_name

    def _get_subnet(net, ip_subnet):
        # Return the subnet, e.g. '192.168.24.0/24', as a string
        # The net dict can either have a ip_subnet as a root element
        # or a dict where multiple subnets are specified. If we have
        # a subnets dict, then parse it looking for the ip_subnet key
        if ip_subnet in net:
            return net[ip_subnet]
        if 'subnets' in net:
            ip_subnets = list(map(lambda x: x.get(ip_subnet, ''),
                                  net['subnets'].values()))
            return ','.join(ip_subnets)

    with open(network_data_path, 'r') as stream:
        try:
            net_data = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            raise RuntimeError(
                "yaml.safe_load(%s) returned '%s'" % (network_data_path, exc))

    # 'name_lower' is not mandatory in net_data so give it the standard default
    [net.setdefault('name_lower', net['name'].lower()) for net in net_data]

    for net in net_data:
        if net.get('ipv6', False):
            ip_subnet = 'ipv6_subnet'
        else:
            ip_subnet = 'ip_subnet'
        for net_name, net_value in net_type.items():
            for search_tag in ['name_lower', 'service_net_map_replace']:
                if net.get(search_tag, None) == net_value:
                    # if service_net_map_replace matched, still want name_lower
                    storage_net_map[net_name] = net['name_lower']
                    subnet = _get_subnet(net, ip_subnet)
                    if not subnet:
                        error = ("While searching %s, %s matched %s "
                                 "but that network did not have a %s "
                                 "value set. To use an ipv6_subnet add "
                                 "key 'ipv6: true' to %s in %s."
                                 % (network_data_path, search_tag,
                                    net_value, ip_subnet, net_value,
                                    network_data_path))
                        raise RuntimeError(error)
                    else:
                        subnet_key = net_name.replace('_name', '')
                        storage_net_map[subnet_key] = subnet
                        if ip_subnet == 'ipv6_subnet':
                            # If _any_ storage network has v6, then
                            # disable v4 and enable v6 ceph binding.
                            # public_network v4 and cluster_network v6
                            # is not supported.
                            storage_net_map['ms_bind_ipv4'] = False
                            storage_net_map['ms_bind_ipv6'] = True

    return storage_net_map


def write_ephemeral_heat_clouds_yaml(heat_dir):
    clouds_yaml_path = os.path.join(heat_dir, 'clouds.yaml')
    clouds_dict = {}
    clouds_dict['heat'] = {}
    clouds_dict['heat']['auth_type'] = "none"
    clouds_dict['heat']['endpoint'] = \
        "http://127.0.0.1:8006/v1/admin"
    heat_yaml = dict(clouds=clouds_dict)
    with open(clouds_yaml_path, 'w') as f:
        f.write(yaml.dump(heat_yaml))

    heatrc = textwrap.dedent("""
        # Clear any old environment that may conflict.
        for key in $( set | awk -F= '/^OS_/ {print $1}' ); do
            unset "${key}"
        done
        export OS_CLOUD=heat
        # Add OS_CLOUDNAME to PS1
        if [ -z "${CLOUDPROMPT_ENABLED:-}" ]; then
            export PS1=${PS1:-""}
            export PS1=${OS_CLOUD:+"($OS_CLOUD)"} $PS1
            export CLOUDPROMPT_ENABLED=1
        fi
        """)

    # Also write a heatrc file
    heatrc_path = os.path.join(heat_dir, 'heatrc')
    with open(heatrc_path, 'w') as f:
        f.write(heatrc)


def get_host_groups_from_ceph_spec(ceph_spec_path, prefix='',
                                   key='hostname', get_non_admin=True):
    """Get hosts per group based on labels in ceph_spec_path file
    :param ceph_spec_path: the path to a ceph_spec.yaml file
    :param (prefix) append a prefix of the group, e.g. 'ceph_'
    :param (key) can be set to 'addr' to retrun IP, defaults to 'hostname'
    :param (get_non_admin), get hosts without _admin label, defaults to True
    :return: dict mapping each label to a hosts list
    """
    hosts = {}
    if get_non_admin:
        non_admin_key = prefix + 'non_admin'
        hosts[non_admin_key] = []

    with open(ceph_spec_path, 'r') as stream:
        try:
            for spec in yaml.safe_load_all(stream):
                if spec.get('service_type', None) == 'host' and \
                   'labels' in spec.keys():
                    for label in spec['labels']:
                        group_key = prefix + label
                        if group_key not in hosts.keys():
                            hosts[group_key] = []
                        hosts[group_key].append(spec[key])
                        if get_non_admin and \
                           '_admin' not in spec['labels']:
                            hosts[non_admin_key].append(spec[key])
        except yaml.YAMLError as exc:
            raise RuntimeError(
                "yaml.safe_load_all(%s) returned '%s'" % (ceph_spec_path, exc))

    return hosts


def standalone_ceph_inventory(working_dir):
    """return an ansible inventory for deployed ceph standalone
    :param working_dir: directory where inventory should be written
    :return string: the path to the inventory
    """
    host = get_hostname()
    inv = \
        {'Standalone':
         {'hosts': {host: {},
                    'undercloud': {}},
          'vars': {'ansible_connection': 'local',
                   'ansible_host': host,
                   'ansible_python_interpreter': sys.executable}},
         'allovercloud':
         {'children': {'Standalone': {}}}}

    path = os.path.join(working_dir,
                        constants.TRIPLEO_STATIC_INVENTORY)
    with open(path, 'w') as f:
        f.write(yaml.safe_dump(inv))
    return path


def process_ceph_daemons(daemon_path):
    """Load the ceph daemons related extra_vars and return the associated dict
    :param daemon_path: the path where the daemon definition is stored
    :return: dict mapping each daemon option to a value passes to ansible
    """
    extra_vars = dict()
    with open(daemon_path, 'r') as f:
        ceph_daemons = yaml.safe_load(f.read())
        try:
            for daemon in ceph_daemons.keys():
                extra_vars['tripleo_cephadm_daemon_' + daemon] = True
                # process current daemon paramters/options
                for k, v in ceph_daemons.get(daemon).items():
                    extra_vars[k] = v
        except AttributeError:
            return extra_vars
    return extra_vars


def check_deploy_backups(
        working_dir,
        backup_usage_percent=constants.DEPLOY_BACKUPS_USAGE_PERCENT,
        disk_usage_percent=constants.DISK_USAGE_PERCENT):
    """Check the total space used by all deploy backups in the given
    working_dir. If it exceeds the backup_usage_percent or total disk usage
    exceeds disk_usage_percent, then print a warning.
    """
    backup_files = glob.iglob(
        os.path.join(working_dir, '..', '*', '*.tar.bzip2'))
    backup_table = prettytable.PrettyTable(
        ['Backup file', 'File size (KB)'])

    total_size = 0
    backup_file = None

    for backup_file in backup_files:
        file_size = os.stat(backup_file).st_size
        total_size += file_size
        backup_table.add_row(
            [os.path.realpath(backup_file), round(file_size / 1024, 2)])

    if backup_file:
        statvfs = os.statvfs(backup_file)
        fs_size = statvfs.f_frsize * statvfs.f_blocks
        fs_free = statvfs.f_frsize * statvfs.f_bfree
        fs_usage = 1 - (fs_free / fs_size)
        backup_usage = total_size / fs_size

        if (backup_usage > backup_usage_percent / 100):
            LOG.warning(
                "Deploy backup files disk usage {:.2%} exceeds {:d}% "
                "percent of disk size. Consider deleting some "
                "older deploy backups.".format(fs_usage, backup_usage_percent))
            print(backup_table, file=sys.stdout)
        elif (fs_usage > disk_usage_percent / 100):
            LOG.warning(
                "Disk usage {:.2%} exceeds {:d}% "
                "percent of disk size. Consider deleting some "
                "older deploy backups.".format(fs_usage, disk_usage_percent))
            print(backup_table, file=sys.stdout)


def get_tripleo_cephadm_keys(username, key, pools):
    """Get a tripleo_cephadm_keys structure to be passed to
       the tripleo-ansible role tripleo_cephadm. Assumes only
       one key will be created to write to all pools.
    :param username: string, e.g. 'openstack'
    :param key: string for cephx secret key, e.g. 'AQC+...w=='
    :param pools: list of pool names, e.g. ['vms', 'images']
    :return a list containing a single dictionary
    """
    return [dict(
        name='client.' + username,
        key=key,
        mode='0600',
        caps=dict(
            mgr='allow *',
            mon='profile rbd',
            osd=', '.join(list(
                map(lambda x: 'profile rbd pool=' + x, pools)))))]


def duplicate_param_check(user_environments):
    """Register warnings when duplcate parameters are discovered.

    :param user_environments: List of user defined environment files.
    :type user_environments: Array
    """
    used_params = collections.defaultdict(int)
    duplicate_params = dict()
    for env_file in user_environments:
        _env_file_parsed = url_parse.urlparse(env_file)
        try:
            with open(_env_file_parsed.path, 'r') as f:
                _env_map = yaml.safe_load(f)
        except FileNotFoundError:
            continue
        else:
            LOG.debug('Inspecting "%s"', _env_file_parsed.path)

        for k, v in _env_map.get('parameter_defaults', {}).items():
            used_params[k] += 1
            if used_params[k] > 1:
                duplicate_params[k] = v

    for k, v in duplicate_params.items():
        LOG.warning(
            'Duplicate parameter defined. Key: "%s", Current Value: %s', k,
            yaml.dump(v, default_flow_style=False)
        )


def get_output_dir(output_dir: str, stack_name: str = "undercloud") -> str:
    if not output_dir:
        return os.path.join(constants.UNDERCLOUD_OUTPUT_DIR,
                            'tripleo-deploy', stack_name)
    return output_dir
