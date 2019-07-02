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
import csv
import datetime
import getpass
import glob
import hashlib
import logging
import shutil
from six.moves.configparser import ConfigParser

import json
import netaddr
import os
import os.path
import simplejson
import six
import socket
import subprocess
import sys
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
from six.moves import configparser

from heatclient import exc as hc_exc
from six.moves.urllib import error as url_error
from six.moves.urllib import request

from tripleoclient import constants
from tripleoclient import exceptions

from prettytable import PrettyTable

LOG = logging.getLogger(__name__ + ".utils")


def run_ansible_playbook(logger,
                         workdir,
                         playbook,
                         inventory,
                         ansible_config=None,
                         retries=True,
                         connection='smart',
                         output_callback='json',
                         python_interpreter=None):
    """Simple wrapper for ansible-playbook

    :param logger: logger instance
    :type logger: Logger

    :param workdir: location of the playbook
    :type workdir: String

    :param playbook: playbook filename
    :type playbook: String

    :param inventory: either proper inventory file, or a coma-separated list
    :type inventory: String

    :param ansible_config: Pass either Absolute Path, or None to generate a
    temporary file, or False to not manage configuration at all
    :type ansible_config: String

    :param retries: do you want to get a retry_file?
    :type retries: Boolean

    :param connect: connection type (local, smart, etc)
    :type connect: String

    :param output_callback: Callback for output format. Defaults to "json"
    :type output_callback: String

    :param python_interpreter: Absolute path for the Python interpreter
    on the host where Ansible is run.
    :type python_interpreter: String
    """
    env = os.environ.copy()

    env['ANSIBLE_LIBRARY'] = \
        ('/root/.ansible/plugins/modules:'
         '/usr/share/ansible/plugins/modules:'
         '%s/library' % constants.DEFAULT_VALIDATIONS_BASEDIR)
    env['ANSIBLE_LOOKUP_PLUGINS'] = \
        ('root/.ansible/plugins/lookup:'
         '/usr/share/ansible/plugins/lookup:'
         '%s/lookup_plugins' % constants.DEFAULT_VALIDATIONS_BASEDIR)
    env['ANSIBLE_CALLBACK_PLUGINS'] = \
        ('~/.ansible/plugins/callback:'
         '/usr/share/ansible/plugins/callback:'
         '%s/callback_plugins' % constants.DEFAULT_VALIDATIONS_BASEDIR)
    env['ANSIBLE_ROLES_PATH'] = \
        ('/root/.ansible/roles:'
         '/usr/share/ansible/roles:'
         '/etc/ansible/roles:'
         '%s/roles' % constants.DEFAULT_VALIDATIONS_BASEDIR)

    cleanup = False
    if ansible_config is None:
        _, tmp_config = tempfile.mkstemp(prefix=playbook, suffix='ansible.cfg')
        with open(tmp_config, 'w+') as f:
            f.write("[defaults]\nstdout_callback = %s\n" % output_callback)
            if not retries:
                f.write("retry_files_enabled = False\n")
            f.close()
        env['ANSIBLE_CONFIG'] = tmp_config
        cleanup = True

    elif os.path.isabs(ansible_config):
        if os.path.exists(ansible_config):
            env['ANSIBLE_CONFIG'] = ansible_config
        else:
            raise RuntimeError('No such configuration file: %s' %
                               ansible_config)
    elif os.path.exists(os.path.join(workdir, ansible_config)):
        env['ANSIBLE_CONFIG'] = os.path.join(workdir, ansible_config)

    play = os.path.join(workdir, playbook)

    if os.path.exists(play):
        cmd = ["ansible-playbook-{}".format(sys.version_info[0]),
               '-i', inventory,
               ]
        if python_interpreter is not None:
            cmd.extend(['-e', 'ansible_python_interpreter=%s' %
                              python_interpreter])

        cmd.extend(['-c', connection, play])

        proc = run_command_and_log(logger, cmd, env=env, retcode_only=False)
        proc.wait()
        cleanup and os.unlink(tmp_config)
        if proc.returncode != 0:
            raise RuntimeError(proc.stdout.read())
        return proc.returncode
    else:
        cleanup and os.unlink(tmp_config)
        raise RuntimeError('No such playbook: %s' % play)


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
    for l in loopbacks:
        if host.startswith(l):
            return True
    return False


def get_host_ips(host, type=None):
    """Lookup an host to return a list of IPs.

    :param host: Host to lookup
    :type  host: string

    :param type: Type of socket (e.g. socket.AF_INET, socket.AF_INET6)
    :type  type: string
    """

    ips = set()
    if type:
        types = (type,)
    else:
        types = (socket.AF_INET, socket.AF_INET6)
    for t in types:
        try:
            res = socket.getaddrinfo(host, None, t, socket.SOCK_STREAM)
        except socket.error:
            continue
        nips = set([x[4][0] for x in res])
        ips.update(nips)
    return list(ips)


def get_single_ip(host, allow_loopback=False):
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
        ips = get_host_ips(host)
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


def write_overcloudrc(stack_name, overcloudrcs, config_directory='.'):
    """Write the overcloudrc files"""

    rcpath = os.path.join(config_directory, '%src' % stack_name)

    with open(rcpath, 'w') as rcfile:
        rcfile.write(overcloudrcs['overcloudrc'])
    os.chmod(rcpath, 0o600)

    return os.path.abspath(rcpath)


def store_cli_param(command_name, parsed_args):
    """write the cli parameters into an history file"""

    # The command name is the part after "openstack" with spaces. Switching
    # to "-" makes it easier to read. "openstack undercloud install" will be
    # stored as "undercloud-install" for example.
    command_name = command_name.replace(" ", "-")

    history_path = os.path.join(os.path.expanduser("~"), '.tripleo')
    if not os.path.exists(history_path):
        try:
            os.mkdir(history_path)
        except OSError as e:
            messages = _("Unable to create TripleO history directory: "
                         "{0}, {1}").format(history_path, e)
            raise OSError(messages)
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


def create_tempest_deployer_input(config_name='tempest-deployer-input.conf'):
    config = configparser.ConfigParser()

    # Create required sections
    for section in ('auth', 'compute', 'compute-feature-enabled', 'identity',
                    'image', 'network', 'object-storage', 'orchestration',
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

    # Role required for users to be able to manage stacks
    # (default: 'heat_stack_owner')
    # keystone role-list returns this role
    config.set('orchestration', 'stack_owner_role', 'swiftoperator')

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
                    'object-storage', 'orchestration', 'volume'):
        config.set(section, 'region', 'regionOne')

    with open(config_name, 'w+') as config_file:
        config.write(config_file)


def wait_for_stack_ready(orchestration_client, stack_name, marker=None,
                         action='CREATE', verbose=False, poll_period=5,
                         nested_depth=2, max_retries=10):
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

    :param poll_period: How often to poll for events
    :type poll_period: int

    :param max_retries: Number of retries in the case of server problems
    :type max_retries: int
    """
    log = logging.getLogger(__name__ + ".wait_for_stack_ready")
    stack = get_stack(orchestration_client, stack_name)
    if not stack:
        return False
    stack_name = "%s/%s" % (stack.stack_name, stack.id)

    if verbose:
        out = sys.stdout
    else:
        out = open(os.devnull, "w")
    retries = 0
    while retries <= max_retries:
        try:
            stack_status, msg = event_utils.poll_for_events(
                orchestration_client, stack_name, action=action,
                poll_period=5, marker=marker, out=out,
                nested_depth=nested_depth)
            print(msg)
            return stack_status == '%s_COMPLETE' % action
        except hc_exc.HTTPException as e:
            if e.code in [503, 504]:
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


def wait_for_provision_state(baremetal_client, node_uuid, provision_state,
                             loops=10, sleep=1):
    """Wait for a given Provisioning state in Ironic

    Updating the provisioning state is an async operation, we
    need to wait for it to be completed.

    :param baremetal_client: Instance of Ironic client
    :type  baremetal_client: ironicclient.v1.client.Client

    :param node_uuid: The Ironic node UUID
    :type  node_uuid: str

    :param provision_state: The provisioning state name to wait for
    :type  provision_state: str

    :param loops: How many times to loop
    :type loops: int

    :param sleep: How long to sleep between loops
    :type sleep: int

    :raises exceptions.StateTransitionFailed: if node.last_error is set
    """

    for _l in range(0, loops):

        node = baremetal_client.node.get(node_uuid)

        if node is None:
            # The node can't be found in ironic, so we don't need to wait for
            # the provision state
            return
        if node.provision_state == provision_state:
            return

        # node.last_error should be None after any successful operation
        if node.last_error:
            raise exceptions.StateTransitionFailed(_(
                "Error transitioning node %(uuid)s to provision state "
                "%(state)s: %(error)s. Now in state %(actual)s.") % {
                    'uuid': node_uuid,
                    'state': provision_state,
                    'error': node.last_error,
                    'actual': node.provision_state
                }
            )

        time.sleep(sleep)

    raise exceptions.Timeout(_(
        "Node %(uuid)s did not reach provision state %(state)s. "
        "Now in state %(actual)s.") % {
            'uuid': node_uuid,
            'state': provision_state,
            'actual': node.provision_state
        }
    )


def set_nodes_state(baremetal_client, nodes, transition, target_state,
                    skipped_states=()):
    """Make all nodes available in the baremetal service for a deployment

    For each node, make it available unless it is already available or active.
    Available nodes can be used for a deployment and an active node is already
    in use.

    :param baremetal_client: Instance of Ironic client
    :type  baremetal_client: ironicclient.v1.client.Client

    :param nodes: List of Baremetal Nodes
    :type  nodes: [ironicclient.v1.node.Node]

    :param transition: The state to set for a node. The full list of states
                       can be found in ironic.common.states.
    :type  transition: string

    :param target_state: The expected result state for a node. For example when
                         transitioning to 'manage' the result is 'manageable'
    :type  target_state: string

    :param skipped_states: A set of states to skip, for example 'active' nodes
                           are already deployed and the state can't always be
                           changed.
    :type  skipped_states: iterable of strings

    :param error_states: Node states treated as error for this transition
    :type error_states: collection of strings

    :param error_message: Optional message to append to an error message
    :param error_message: str

    :raises exceptions.StateTransitionFailed: if a node enters any of the
                                              states in error_states

    :raises exceptions.Timeout: if a node takes too long to reach target state
    """

    log = logging.getLogger(__name__ + ".set_nodes_state")

    for node in nodes:

        if node.provision_state in skipped_states:
            continue

        log.debug(_(
            "Setting provision state from '{0}' to '{1}' for Node {2}")
            .format(node.provision_state, transition, node.uuid))

        baremetal_client.node.set_provision_state(node.uuid, transition)
        try:
            wait_for_provision_state(baremetal_client, node.uuid, target_state)
        except exceptions.StateTransitionFailed as e:
            log.error(_("FAIL: State transition failed for Node {0}. {1}")
                      .format(node.uuid, e))
        except exceptions.Timeout as e:
            log.error(_("FAIL: Timeout waiting for Node {0}. {1}")
                      .format(node.uuid, e))
        yield node.uuid


def get_overcloud_endpoint(stack):
    for output in stack.to_dict().get('outputs', {}):
        if output['output_key'] == 'KeystoneURL':
            return output['output_value']


def get_service_ips(stack):
    service_ips = {}
    for output in stack.to_dict().get('outputs', {}):
        service_ips[output['output_key']] = output['output_value']
    return service_ips


def get_endpoint_map(stack):
    endpoint_map = {}
    for output in stack.to_dict().get('outputs', {}):
        if output['output_key'] == 'EndpointMap':
            endpoint_map = output['output_value']
            break
    return endpoint_map


def get_blacklisted_ip_addresses(stack):
    for output in stack.to_dict().get('outputs', {}):
        if output['output_key'] == 'BlacklistedIpAddresses':
            return output['output_value']


def get_role_net_ip_map(stack):
    for output in stack.to_dict().get('outputs', {}):
        if output['output_key'] == 'RoleNetIpMap':
            return output['output_value']


def get_endpoint(key, stack):
    endpoint_map = get_endpoint_map(stack)
    if endpoint_map:
        return endpoint_map[key]['host']
    else:
        return get_service_ips(stack).get(key + 'Vip')


def get_stack(orchestration_client, stack_name):
    """Get the ID for the current deployed overcloud stack if it exists.

    Caller is responsible for checking if return is None
    """

    try:
        stack = orchestration_client.stacks.get(stack_name)
        return stack
    except HTTPNotFound:
        pass


def check_stack_network_matches_env_files(stack, environment):
    """Check stack against proposed env files to ensure non-breaking change

    Historically we have have had issues with folks forgetting the network
    isolation templates in subsequent overcloud actions which have completely
    broken the stack. We need to check that the networks continue to be
    provided on updates and if they aren't, it's likely that the user has
    failed to provide the network-isolation templates. This is a light check
    to only ensure they are defined. A user can still change settings in these
    networks that may break things but this will catch folks who forget
    network-isolation in a subsequent update.
    """
    def _get_networks(registry):
        nets = set()
        for k, v in six.iteritems(registry):
            if (k.startswith('OS::TripleO::Network::')
                and not k.startswith('OS::TripleO::Network::Port')
                    and v != 'OS::Heat::None'):
                nets.add(k)
        return nets

    stack_registry = stack.environment().get('resource_registry', {})
    env_registry = environment.get('resource_registry', {})

    stack_nets = _get_networks(stack_registry)
    env_nets = _get_networks(env_registry)

    env_diff = set(stack_nets) - set(env_nets)
    if env_diff:
        raise exceptions.InvalidConfiguration('Missing networks from '
                                              'environment configuration. '
                                              'Ensure the following networks '
                                              'are properly configured in '
                                              'the provided environment files '
                                              '[{}]'.format(env_diff))


def remove_known_hosts(overcloud_ip):
    """For a given IP address remove SSH keys from the known_hosts file"""

    known_hosts = os.path.expanduser("~/.ssh/known_hosts")

    if os.path.exists(known_hosts):
        command = ['ssh-keygen', '-R', overcloud_ip, '-f', known_hosts]
        subprocess.check_call(command)


def run_shell(cmd):
    return subprocess.call([cmd], shell=True)


def all_unique(x):
    """Return True if the collection has no duplications."""
    return len(set(x)) == len(x)


def file_checksum(filepath):
    """Calculate md5 checksum on file

    :param filepath: Full path to file (e.g. /home/stack/image.qcow2)
    :type  filepath: string

    """
    if not os.path.isfile(filepath):
        raise ValueError(_("The given file {0} is not a regular "
                           "file").format(filepath))
    checksum = hashlib.md5()
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
                "Recommendation: tag more nodes using ironic node-update "
                "<NODE ID> replace properties/capabilities=profile:%s,",
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


def add_deployment_plan_arguments(parser, mark_as_depr=False):
    """Add deployment plan arguments (flavors and scales) to a parser"""

    depr_warning = _(' (DEPRECATED. Use an environment file and set the '
                     'parameter %s. It will be removed after the "P" '
                     'release.)')

    # TODO(d0ugal): Deprecated in Newton. Remove these in P.
    parser.add_argument('--control-scale', type=int,
                        help=_('New number of control nodes.')
                        + (depr_warning % 'ControllerCount'
                           if mark_as_depr else ''))
    parser.add_argument('--compute-scale', type=int,
                        help=_('New number of compute nodes.')
                        + (depr_warning % 'ComputeCount'
                           if mark_as_depr else ''))
    parser.add_argument('--ceph-storage-scale', type=int,
                        help=_('New number of ceph storage nodes.')
                        + (depr_warning % 'CephStorageCount'
                           if mark_as_depr else ''))
    parser.add_argument('--block-storage-scale', type=int,
                        help=_('New number of cinder storage nodes.')
                        + (depr_warning % 'BlockStorageCount'
                           if mark_as_depr else ''))
    parser.add_argument('--swift-storage-scale', type=int,
                        help=_('New number of swift storage nodes.')
                        + (depr_warning % 'ObjectStorageCount'
                           if mark_as_depr else ''))
    parser.add_argument('--control-flavor',
                        help=_('Nova flavor to use for control nodes.')
                        + (depr_warning % 'OvercloudControlFlavor'
                           if mark_as_depr else ''))
    parser.add_argument('--compute-flavor',
                        help=_('Nova flavor to use for compute nodes.')
                        + (depr_warning % 'OvercloudComputeFlavor'
                           if mark_as_depr else ''))
    parser.add_argument('--ceph-storage-flavor',
                        help=_('Nova flavor to use for ceph storage nodes.')
                        + (depr_warning % 'OvercloudCephStorageFlavor'
                           if mark_as_depr else ''))
    parser.add_argument('--block-storage-flavor',
                        help=_('Nova flavor to use for cinder storage nodes')
                        + (depr_warning % 'OvercloudBlockStorageFlavor'
                           if mark_as_depr else ''))
    parser.add_argument('--swift-storage-flavor',
                        help=_('Nova flavor to use for swift storage nodes')
                        + (depr_warning % 'OvercloudSwiftStorageFlavor'
                           if mark_as_depr else ''))


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
        nodes_config = simplejson.load(env_file)
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
        else:
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
                isinstance(value, six.string_types)):
            return link_replacement.get(value, value)
        else:
            return replace_links_in_template(value, link_replacement)

    def replaced_list_value(value):
        return replace_links_in_template(value, link_replacement)

    if isinstance(template_part, dict):
        return {k: replaced_dict_value(k, v)
                for k, v in six.iteritems(template_part)}
    elif isinstance(template_part, list):
        return list(map(replaced_list_value, template_part))
    else:
        return template_part


def relative_link_replacement(link_replacement, current_dir):
    """Generate a relative version of link_replacement dictionary.

    Get a link_replacement dictionary (where key/value are from/to
    respectively), and make the values in that dictionary relative
    paths with respect to current_dir.
    """

    return {k: os.path.relpath(v, current_dir)
            for k, v in six.iteritems(link_replacement)}


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


def get_tripleo_ansible_inventory(inventory_file='',
                                  ssh_user='tripleo-admin',
                                  stack='overcloud'):
    if not inventory_file:
        inventory_file = '%s/%s' % (os.path.expanduser('~'),
                                    'tripleo-ansible-inventory.yaml')
        try:
            processutils.execute(
                '/usr/bin/tripleo-ansible-inventory',
                '--stack', stack,
                '--ansible_ssh_user', ssh_user,
                '--undercloud-connection', 'ssh',
                '--static-yaml-inventory', inventory_file)
        except processutils.ProcessExecutionError as e:
                message = _("Failed to generate inventory: %s") % str(e)
                raise exceptions.InvalidConfiguration(message)
    if os.path.exists(inventory_file):
        inventory = open(inventory_file, 'r').read()
        return inventory
    else:
        raise exceptions.InvalidConfiguration(_(
            "Inventory file %s can not be found.") % inventory_file)


def process_multiple_environments(created_env_files, tht_root,
                                  user_tht_root, cleanup=True):
    log = logging.getLogger(__name__ + ".process_multiple_environments")
    env_files = {}
    localenv = {}
    # Normalize paths for full match checks
    user_tht_root = os.path.normpath(user_tht_root)
    tht_root = os.path.normpath(tht_root)
    for env_path in created_env_files:
        log.debug("Processing environment files %s" % env_path)
        abs_env_path = os.path.abspath(env_path)
        if (abs_env_path.startswith(user_tht_root) and
            ((user_tht_root + '/') in env_path or
             (user_tht_root + '/') in abs_env_path or
             user_tht_root == abs_env_path or
             user_tht_root == env_path)):
            new_env_path = env_path.replace(user_tht_root + '/',
                                            tht_root + '/')
            log.debug("Redirecting env file %s to %s"
                      % (abs_env_path, new_env_path))
            env_path = new_env_path
        try:
            files, env = template_utils.process_environment_and_files(
                env_path=env_path)
        except hc_exc.CommandError as ex:
            # This provides fallback logic so that we can reference files
            # inside the resource_registry values that may be rendered via
            # j2.yaml templates, where the above will fail because the
            # file doesn't exist in user_tht_root, but it is in tht_root
            # See bug https://bugs.launchpad.net/tripleo/+bug/1625783
            # for details on why this is needed (backwards-compatibility)
            log.debug("Error %s processing environment file %s"
                      % (six.text_type(ex), env_path))
            # Use the temporary path as it's possible the environment
            # itself was rendered via jinja.
            with open(env_path, 'r') as f:
                env_map = yaml.safe_load(f)
            env_registry = env_map.get('resource_registry', {})
            env_dirname = os.path.dirname(os.path.abspath(env_path))
            for rsrc, rsrc_path in six.iteritems(env_registry):
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
                    env_path=f.name)
        if files:
            log.debug("Adding files %s for %s" % (files, env_path))
            env_files.update(files)

        # 'env' can be a deeply nested dictionary, so a simple update is
        # not enough
        localenv = template_utils.deep_update(localenv, env)
    return env_files, localenv


def run_update_ansible_action(log, clients, nodes, inventory, playbook,
                              all_playbooks, action, ssh_user, tags='',
                              skip_tags='', verbosity='1', extra_vars=None):
    playbooks = [playbook]
    if playbook == "all":
        playbooks = all_playbooks
    for book in playbooks:
        log.debug("Running ansible playbook %s " % book)
        action.update_ansible(clients, nodes=nodes, inventory_file=inventory,
                              playbook=book, node_user=ssh_user, tags=tags,
                              skip_tags=skip_tags, verbosity=verbosity,
                              extra_vars=extra_vars)


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


def get_short_hostname():
    """Returns the local short hostname

    :return string
    """
    p = subprocess.Popen(["hostname", "-s"], stdout=subprocess.PIPE,
                         universal_newlines=True)
    return p.communicate()[0].rstrip().lower()


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
    tmp = None
    try:
        if not os.path.exists(tmpd):
            raise exceptions.NotFound("{} does not exist. Cannot create a "
                                      "temp folder using this path".format(
                                          tmpd))
        tmp = tempfile.mkdtemp(dir=tmpd)
        subprocess.check_call(['mkdir', '-p', dst])
        os.chmod(tmp, 0o755)
        for obj in os.listdir(src):
            tmpf = os.path.join(tmp, obj)
            os.symlink(os.path.join(src, obj), tmpf)
            os.rename(tmpf, os.path.join(dst, obj))
    except Exception:
        raise
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def run_command_and_log(log, cmd, cwd=None, env=None, retcode_only=True):
    """Run command and log output

    :param log: logger instance for logging
    :type log: Logger

    :param cmd: command in list form
    :type cmd: List

    :param cwd: current worknig directory for execution
    :type cmd: String

    :param env: modified environment for command run
    :type env: List

    :param retcode_only: Returns only retcode instead or proc objec
    :type retcdode_only: Boolean
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, shell=False,
                            cwd=cwd, env=env)
    if retcode_only:
        # TODO(aschultz): this should probably goto a log file
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
    else:
        return proc


def ffwd_upgrade_operator_confirm(parsed_args_yes, log):
    print("\nWarning! The TripleO Fast Forward Upgrade "
          "workflow is a critical operation against the deployed "
          "environment.\nOnce and if you decide to use ffwd-upgrade "
          "in production, ensure you are adequately prepared "
          "with valid backup of your current deployment state.\n")
    if parsed_args_yes:
        log.debug(_("Fast forward upgrade --yes continuing"))
        print(_("Continuing fast forward upgrade"))
        return
    else:
        # Fix Python 2.x.
        try:
            input = raw_input
        except NameError:
            pass
        response = input("Proceed with the fast forward upgrade? "
                         "Type 'yes' to continue and anything else to "
                         "cancel.\nConsider using the --yes parameter if "
                         "you wish to skip this warning in future. ")
        if response != 'yes':
            log.debug(_("Fast forward upgrade cancelled on user request"))
            print(_("Cancelling fast forward upgrade"))
            sys.exit(1)


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

    env_f, env = (
        template_utils.process_multiple_environments_and_files(
            env_files, env_path_is_object=lambda path: True,
            object_request=get_env_file))

    return env


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


def _name_helper(basename, arch=None, platform=None):
    # NOTE(tonyb): We don't accept a platform with an arch.  This caught when
    # import the nodes / process args, but lets be a little cautious here
    # anyway.
    if arch and platform:
        basename = platform + '-' + arch + '-' + basename
    elif arch:
        basename = arch + '-' + basename
    return basename


def overcloud_kernel(basename, arch=None, platform=None):
    return (_name_helper('%s-vmlinuz' % basename, arch=arch,
                         platform=platform),
            '.vmlinuz')


def overcloud_ramdisk(basename, arch=None, platform=None):
    return (_name_helper('%s-initrd' % basename, arch=arch,
                         platform=platform),
            '.initrd')


def overcloud_image(basename, arch=None, platform=None):
    return (_name_helper(basename, arch=arch, platform=platform),
            '.qcow2')


def deploy_kernel(arch=None, platform=None):
    return (_name_helper('bm-deploy-kernel', arch=arch, platform=platform),
            '.kernel')


def deploy_ramdisk(arch=None, platform=None):
    return (_name_helper('bm-deploy-ramdisk', arch=arch, platform=platform),
            '.initramfs')


def update_nodes_deploy_data(imageclient, nodes):
    """Add specific kernel and ramdisk IDs to a node.

    Look at all images and update node data with the most specific
    deploy_kernel and deploy_ramdisk for the architecture/platform comination
    platform.
    """
    img_map = {}
    for image in imageclient.images.list():
        name = image.name
        # NOTE(tonyb): We don't want to include the default kernel or ramdisk
        # in the map as that will short-circuit logic elesewhere.
        if name != deploy_kernel()[0] and name != deploy_ramdisk()[0]:
            img_map[image.name] = image.id

    for node in nodes:
        arch = node.get('arch')
        platform = node.get('platform')

        # NOTE(tonyb): Check to see if we have a specific kernel for this node
        # and use that.
        for kernel in [deploy_kernel(arch=arch, platform=platform)[0],
                       deploy_kernel(arch=arch)[0]]:
            if 'kernel_id' not in node and kernel in img_map:
                node['kernel_id'] = img_map[kernel]
                break

        # NOTE(tonyb): As above except for ramdisks
        for ramdisk in [deploy_ramdisk(arch=arch, platform=platform)[0],
                        deploy_ramdisk(arch=arch)[0]]:
            if 'ramdisk_id' not in node and ramdisk in img_map:
                node['ramdisk_id'] = img_map[ramdisk]
                break


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
    http_proxy = os.environ.get('http_proxy', None)
    https_proxy = os.environ.get('https_proxy', None)
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
    config = ConfigParser()
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
    except Exception:
        raise exceptions.NotFound(_("Unable to find {section}/{option} in "
                                    "{config}").format(section=param,
                                                       option=section,
                                                       config=cfg))
    return val


def get_validations_table(validations_data):
    """Return the validations information as a pretty printed table """
    t = PrettyTable(border=True, header=True, padding_width=1)
    t.title = "TripleO validations"
    t.field_names = ["ID", "Name", "Description", "Groups", "Metadata"]
    for validation in validations_data['validations']:
        t.add_row([validation['id'],
                   validation['name'],
                   "\n".join(textwrap.wrap(validation['description'])),
                   "\n".join(textwrap.wrap(' '.join(validation['groups']))),
                   validation['metadata']])

    t.sortby = "ID"
    t.align["ID"] = "l"
    t.align["Name"] = "l"
    t.align["Description"] = "l"
    t.align["Groups"] = "l"
    t.align["Metadata"] = "l"
    return t


def get_validations_json(validations_data):
    """Return the validations information as a pretty printed json """
    return json.dumps(validations_data, indent=4, sort_keys=True)


def get_validations_yaml(validations_data):
    """Return the validations information as a pretty printed yaml """
    return yaml.safe_dump(validations_data,
                          allow_unicode=True,
                          default_flow_style=False,
                          indent=2)


def indent(text):
    '''Indent the given text by four spaces.'''
    return ''.join('    {}\n'.format(line) for line in text.splitlines())


def get_local_timezone():
    info = run_command(['timedatectl'], name='timedatectl')
    timezoneline = [tz for tz in info.split('\n') if 'Time zone:' in tz]
    if not timezoneline:
        LOG.warning('Unable to determine timezone, using UTC')
        return 'UTC'
    # The line returned is "[whitespace]Time zone: [timezone] ([tz], [offset])"
    try:
        timezone = timezoneline[0].strip().split(' ')[2]
    except Exception:
        LOG.error('Unable to parse timezone from timedatectl, using UTC')
        timezone = 'UTC'
    return timezone


def ansible_symlink():
    # https://bugs.launchpad.net/tripleo/+bug/1812837
    python_version = sys.version_info[0]
    ansible_playbook_cmd = "ansible-playbook-{}".format(python_version)
    cmd = ['sudo', 'ln', '-s']
    if not os.path.exists('/usr/bin/ansible-playbook'):
        if os.path.exists('/usr/bin/' + ansible_playbook_cmd):
            cmd.extend(['/usr/bin/' + ansible_playbook_cmd,
                       '/usr/bin/ansible-playbook'])
            run_command(cmd, name='ansible-playbook-symlink')
    else:
        if not os.path.exists('/usr/bin/' + ansible_playbook_cmd):
            cmd.extend(['/usr/bin/ansible-playbook',
                       '/usr/bin/' + ansible_playbook_cmd])
            run_command(cmd, name='ansible-playbook-3-symlink')


def check_file_for_enabled_service(env_file):
    # This function checks environment file for the said service.
    # If stack to be deployed/updated/upgraded has any deprecated service
    # enabled, throw a warning about its deprecation and ask the user
    # whether to proceed with deployment despite deprecation.
    # For ODL as an example:
    # If "OS::TripleO::Services::OpenDaylightApi" service is included
    # in any of the parsed env_files, then check its value.
    # OS::TripleO::Services::OpenDaylightApi NOT OS::Heat::None
    # ODL is enabled.

    if os.path.exists(env_file):
        content = yaml.load(open(env_file))
        deprecated_services_enabled = []
        for service in constants.DEPRECATED_SERVICES.keys():
            if ("resource_registry" in content and
                    service in content["resource_registry"]):
                if content["resource_registry"][service] != "OS::Heat::None":
                    LOG.warn("service " + service + " is enabled in "
                             + str(env_file) + ". " +
                             constants.DEPRECATED_SERVICES[service])
                    deprecated_services_enabled.append(service)

        if deprecated_services_enabled:
            confirm = prompt_user_for_confirmation(
                message="Do you still wish to continue with deployment [y/N]",
                logger=LOG)
            if not confirm:
                raise oscexc.CommandError("Action not confirmed, exiting.")


def check_deprecated_service_is_enabled(environment_files):
    for env_file in environment_files:
        check_file_for_enabled_service(env_file)


def send_cmdline_erase_sequence():
    # Send's an erase in line sequence to the output
    # https://www.vt100.net/docs/vt100-ug/chapter3.html#EL
    sys.stdout.write(u'\u001b[0K')
    sys.stdout.flush()
