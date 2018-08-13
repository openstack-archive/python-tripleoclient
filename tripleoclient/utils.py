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

import os
import os.path
import simplejson
import six
import socket
import subprocess
import sys
import tempfile
import time
import yaml

from heatclient.common import event_utils
from heatclient.common import template_utils
from heatclient.common import utils as heat_utils
from heatclient.exc import HTTPNotFound
from osc_lib.i18n import _
from oslo_concurrency import processutils
from six.moves import configparser

from heatclient import exc as hc_exc
from six.moves.urllib import error as url_error
from six.moves.urllib import request

from tripleoclient import constants
from tripleoclient import exceptions


def run_ansible_playbook(logger,
                         workdir,
                         playbook,
                         inventory,
                         ansible_config=None,
                         retries=True,
                         connection='smart',
                         output_callback='json'):
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
    """
    env = os.environ.copy()
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
        cmd = ['ansible-playbook',
               '-i', inventory,
               '-c', connection, play
               ]
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
    rcv3path = os.path.join(config_directory, '%src.v3' % stack_name)

    with open(rcpath, 'w') as rcfile:
        rcfile.write(overcloudrcs['overcloudrc'])
    os.chmod(rcpath, 0o600)

    with open(rcv3path, 'w') as rcv3file:
        rcv3file.write(overcloudrcs['overcloudrc.v3'])
    os.chmod(rcv3path, 0o600)
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
                         action='CREATE', verbose=False):
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
    """
    stack = get_stack(orchestration_client, stack_name)
    if not stack:
        return False
    stack_name = "%s/%s" % (stack.stack_name, stack.id)

    if verbose:
        out = sys.stdout
    else:
        out = open(os.devnull, "w")
    stack_status, msg = event_utils.poll_for_events(
        orchestration_client, stack_name, action=action,
        poll_period=5, marker=marker, out=out, nested_depth=2)
    print(msg)
    return stack_status == '%s_COMPLETE' % action


def nodes_in_states(baremetal_client, states):
    """List the introspectable nodes with the right provision_states."""
    nodes = baremetal_client.node.list(maintenance=False, associated=False)
    return [node for node in nodes if node.provision_state in states]


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


def get_role_data(stack):
    role_data = {}
    for output in stack.to_dict().get('outputs', {}):
        if output['output_key'] == 'RoleData':
            for role in output['output_value']:
                role_data[role] = output['output_value'][role]
    return role_data


def get_role_config(stack):
    role_data = {}
    for output in stack.to_dict().get('outputs', {}):
        if output['output_key'] == 'RoleConfig':
            for role in output['output_value']:
                role_data[role] = output['output_value'][role]
    return role_data


def get_role_net_hostname_map(stack):
    for output in stack.to_dict().get('outputs', {}):
        if output['output_key'] == 'RoleNetHostnameMap':
            return output['output_value']


def get_role_net_ip_map(stack):
    for output in stack.to_dict().get('outputs', {}):
        if output['output_key'] == 'RoleNetIpMap':
            return output['output_value']


def get_hosts_entry(stack):
    for output in stack.to_dict().get('outputs', {}):
        if output['output_key'] == 'HostsEntry':
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
                "<NODE ID> replace properties/capabilities=profile:%s,"
                "boot_option:local", profile)
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
    template for 'get_file' and 'type' occurences, and replace the
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

    Scan the template for 'get_file' and 'type' occurences, and
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
        return map(replaced_list_value, template_part)
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
                                  ssh_user='heat-admin',
                                  stack='overcloud'):
    if not inventory_file:
        inventory_file = '%s/%s' % (os.path.expanduser('~'),
                                    'tripleo-ansible-inventory.yaml')
        try:
            processutils.execute(
                '/usr/bin/tripleo-ansible-inventory',
                '--stack', stack,
                '--ansible_ssh_user', ssh_user,
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
                              queue, all_playbooks, action, ssh_user,
                              tags='', skip_tags=''):
    playbooks = [playbook]
    if playbook == "all":
        playbooks = all_playbooks
    for book in playbooks:
        log.debug("Running ansible playbook %s " % book)
        action.update_ansible(clients, nodes=nodes, inventory_file=inventory,
                              playbook=book, ansible_queue_name=queue,
                              node_user=ssh_user, tags=tags,
                              skip_tags=skip_tags)


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
    p = subprocess.Popen(["hostname", "-s"], stdout=subprocess.PIPE)
    return p.communicate()[0].rstrip()


def wait_api_port_ready(api_port, host='127.0.0.1'):
    """Wait until an http services becomes available

    :param api_port: api service port
    :type  api_port: integer

    :param host: host running the service (default: 127.0.0.1)
    :type host: string

    :return boolean
    """
    count = 0
    while count < 30:
        time.sleep(1)
        count += 1
        try:
            request.urlopen("http://%s:%s/" % (host, api_port), timeout=1)
        except url_error.HTTPError as he:
            if he.code == 300:
                return True
            pass
        except url_error.URLError:
            pass
    return False


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
    try:
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
                            bufsize=1, cwd=cwd, env=env)

    if retcode_only:
        for line in iter(proc.stdout.readline, b''):
            # TODO(aschultz): this should probably goto a log file
            log.warning(line.rstrip())
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
