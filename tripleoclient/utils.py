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
import base64
import hashlib
import json
import logging
import os
import os.path
import passlib.utils as passutils
import six
import socket
import struct
import subprocess
import time

from heatclient.common import event_utils
from heatclient.exc import HTTPNotFound
from openstackclient.i18n import _
from six.moves import configparser
from six.moves import urllib

from tripleoclient import exceptions

_MIN_PASSWORD_SIZE = 25
_PASSWORD_NAMES = (
    "OVERCLOUD_ADMIN_PASSWORD",
    "OVERCLOUD_ADMIN_TOKEN",
    "OVERCLOUD_AODH_PASSWORD",
    "OVERCLOUD_CEILOMETER_PASSWORD",
    "OVERCLOUD_CEILOMETER_SECRET",
    "OVERCLOUD_CINDER_PASSWORD",
    "OVERCLOUD_DEMO_PASSWORD",
    "OVERCLOUD_GLANCE_PASSWORD",
    "OVERCLOUD_GNOCCHI_PASSWORD",
    "OVERCLOUD_HAPROXY_STATS_PASSWORD",
    "OVERCLOUD_HEAT_PASSWORD",
    "OVERCLOUD_HEAT_STACK_DOMAIN_PASSWORD",
    "OVERCLOUD_MYSQL_CLUSTERCHECK_PASSWORD",
    "OVERCLOUD_NEUTRON_PASSWORD",
    "OVERCLOUD_NOVA_PASSWORD",
    "OVERCLOUD_RABBITMQ_PASSWORD",
    "OVERCLOUD_REDIS_PASSWORD",
    "OVERCLOUD_SAHARA_PASSWORD",
    "OVERCLOUD_SWIFT_HASH",
    "OVERCLOUD_SWIFT_PASSWORD",
    "OVERCLOUD_TROVE_PASSWORD",
    "NEUTRON_METADATA_PROXY_SHARED_SECRET"
)


def generate_overcloud_passwords(output_file="tripleo-overcloud-passwords",
                                 create_password_file=False):
    """Create the passwords needed for the overcloud

    This will create the set of passwords required by the overcloud, store
    them in the output file path and return a dictionary of passwords. If the
    file already exists the existing passwords will be returned instead,
    """

    log = logging.getLogger(__name__ + ".generate_overcloud_passwords")

    log.debug("Using password file: {0}".format(os.path.abspath(output_file)))

    passwords = {}
    if os.path.isfile(output_file):
        with open(output_file) as f:
            passwords = dict(line.split('=') for line in f.read().splitlines())
    elif not create_password_file:
        raise exceptions.PasswordFileNotFound(
            "The password file could not be found!")

    for name in _PASSWORD_NAMES:
        if not passwords.get(name):
            passwords[name] = passutils.generate_password(
                size=_MIN_PASSWORD_SIZE)

    with open(output_file, 'w') as f:
        for name, password in passwords.items():
            f.write("{0}={1}\n".format(name, password))

    return passwords


def bracket_ipv6(address):
    """Put a bracket around address if it is valid IPv6

    Return it unchanged if it is a hostname or IPv4 address.
    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return "[%s]" % address
    except socket.error:
        return address


def create_overcloudrc(stack, no_proxy, config_directory='.'):
    """Given proxy settings and stack, create the overcloudrc

    stack: Heat stack containing the deployed overcloud
    no_proxy: a comma-separated string of hosts that shouldn't be proxied
    """
    overcloud_endpoint = get_overcloud_endpoint(stack)
    overcloud_host = urllib.parse.urlparse(overcloud_endpoint).hostname
    overcloud_admin_vip = get_endpoint('KeystoneAdmin', stack)

    no_proxy_list = map(bracket_ipv6,
                        [no_proxy, overcloud_host, overcloud_admin_vip])

    rc_params = {
        'NOVA_VERSION': '1.1',
        'COMPUTE_API_VERSION': '1.1',
        'OS_USERNAME': 'admin',
        'OS_TENANT_NAME': 'admin',
        'OS_NO_CACHE': 'True',
        'OS_CLOUDNAME': stack.stack_name,
        'no_proxy': ','.join(no_proxy_list),
        'PYTHONWARNINGS': ('"ignore:Certificate has no, ignore:A true '
                           'SSLContext object is not available"'),
    }
    rc_params.update({
        'OS_PASSWORD': get_password('OVERCLOUD_ADMIN_PASSWORD'),
        'OS_AUTH_URL': overcloud_endpoint,
    })

    config_path = os.path.join(config_directory, '%src' % stack.stack_name)

    with open(config_path, 'w') as f:
        for key, value in rc_params.items():
            f.write("export %(key)s=%(value)s\n" %
                    {'key': key, 'value': value})


def create_tempest_deployer_input(config_name='tempest-deployer-input.conf'):
    config = configparser.ConfigParser()

    config.add_section('compute-feature-enabled')
    # Does the test environment support obtaining instance serial console
    # output? (default: true)
    # set in [nova.serial_console]->enabled
    config.set('compute-feature-enabled', 'console_output', 'false')

    config.add_section('object-storage')
    # Role to add to users created for swift tests to enable creating
    # containers (default: 'Member')
    # keystone role-list returns this role
    config.set('object-storage', 'operator_role', 'swiftoperator')

    config.add_section('orchestration')
    # Role required for users to be able to manage stacks
    # (default: 'heat_stack_owner')
    # keystone role-list returns this role
    config.set('orchestration', 'stack_owner_role', 'heat_stack_user')

    config.add_section('volume')
    # Name of the backend1 (must be declared in cinder.conf)
    # (default: 'BACKEND_1')
    # set in [cinder]->enabled_backends
    config.set('volume', 'backend1_name', 'tripleo_iscsi')

    config.add_section('volume-feature-enabled')
    # Update bootable status of a volume Not implemented on icehouse
    # (default: false)
    # python-cinderclient supports set-bootable
    config.set('volume-feature-enabled', 'bootable', 'true')

    with open(config_name, 'w+') as config_file:
        config.write(config_file)


def check_hypervisor_stats(compute_client, nodes=1, memory=0, vcpu=0):
    """Check the Hypervisor stats meet a minimum value

    Check the hypervisor stats match the required counts. This is an
    implementation of a command in TripleO with the same name.

    :param compute_client: Instance of Nova client
    :type  compute_client: novaclient.client.v2.Client

    :param nodes: The number of nodes to wait for, defaults to 1.
    :type  nodes: int

    :param memory: The amount of memory to wait for in MB, defaults to 0.
    :type  memory: int

    :param vcpu: The number of vcpus to wait for, defaults to 0.
    :type  vcpu: int
    """

    statistics = compute_client.hypervisors.statistics().to_dict()

    if all([statistics['count'] >= nodes,
            statistics['memory_mb'] >= memory,
            statistics['vcpus'] >= vcpu]):
        return statistics
    else:
        return None


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
    stack_name = stack.stack_name

    while True:

        events = event_utils.get_events(orchestration_client,
                                        stack_id=stack_name, nested_depth=2,
                                        event_args={'sort_dir': 'asc',
                                                    'marker': marker})

        if len(events) >= 1:
            # set marker to last event that was received.
            marker = getattr(events[-1], 'id', None)

            if verbose:
                events_log = event_log_formatter(events)
                print(events_log)

        stack = get_stack(orchestration_client, stack_name)
        stack_status = stack.stack_status
        if stack_status == '%s_COMPLETE' % action:
            print("Stack %(name)s %(status)s" % dict(
                name=stack_name, status=stack_status))
            return True
        elif stack_status == '%s_FAILED' % action:
            print("Stack %(name)s %(status)s" % dict(
                name=stack_name, status=stack_status))
            return False

        time.sleep(5)


def event_log_formatter(events):
    """Return the events in log format."""
    event_log = []
    log_format = ("%(event_time)s "
                  "[%(rsrc_name)s]: %(rsrc_status)s %(rsrc_status_reason)s")
    for event in events:
        event_time = getattr(event, 'event_time', '')
        log = log_format % {
            'event_time': event_time.replace('T', ' '),
            'rsrc_name': getattr(event, 'resource_name', ''),
            'rsrc_status': getattr(event, 'resource_status', ''),
            'rsrc_status_reason': getattr(event, 'resource_status_reason', '')
        }
        event_log.append(log)

    return "\n".join(event_log)


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
            raise exceptions.StateTransitionFailed(
                "Error transitioning node %(uuid)s to provision state "
                "%(state)s: %(error)s. Now in state %(actual)s." % {
                    'uuid': node_uuid,
                    'state': provision_state,
                    'error': node.last_error,
                    'actual': node.provision_state
                }
            )

        time.sleep(sleep)

    raise exceptions.Timeout(
        "Node %(uuid)s did not reach provision state %(state)s. "
        "Now in state %(actual)s." % {
            'uuid': node_uuid,
            'state': provision_state,
            'actual': node.provision_state
        }
    )


def create_environment_file(path="~/overcloud-env.json",
                            control_scale=1, compute_scale=1,
                            ceph_storage_scale=0, block_storage_scale=0,
                            swift_storage_scale=0):
    """Create a heat environment file

    Create the heat environment file with the scale parameters.

    :param control_scale: Scale value for control roles.
    :type control_scale: int

    :param compute_scale: Scale value for compute roles.
    :type compute_scale: int

    :param ceph_storage_scale: Scale value for ceph storage roles.
    :type ceph_storage_scale: int

    :param block_storage_scale: Scale value for block storage roles.
    :type block_storage_scale: int

    :param swift_storage_scale: Scale value for swift storage roles.
    :type swift_storage_scale: int
    """

    env_path = os.path.expanduser(path)
    with open(env_path, 'w+') as f:
        f.write(json.dumps({
            "parameter_defaults": {
                "ControllerCount": control_scale,
                "ComputeCount": compute_scale,
                "CephStorageCount": ceph_storage_scale,
                "BlockStorageCount": block_storage_scale,
                "ObjectStorageCount": swift_storage_scale}
        }))

    return env_path


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

        log.debug(
            "Setting provision state from '{0}' to '{1}' for Node {2}"
            .format(node.provision_state, transition, node.uuid))

        baremetal_client.node.set_provision_state(node.uuid, transition)
        try:
            wait_for_provision_state(baremetal_client, node.uuid, target_state)
        except exceptions.StateTransitionFailed as e:
            log.error("FAIL: State transition failed for Node {0}. {1}"
                      .format(node.uuid, e))
        except exceptions.Timeout as e:
            log.error("FAIL: Timeout waiting for Node {0}. {1}"
                      .format(node.uuid, e))
        yield node.uuid


def get_hiera_key(key_name):
    """Retrieve a key from the hiera store

    :param password_name: Name of the key to retrieve
    :type  password_name: type

    """
    command = ["hiera", key_name]
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    out, err = p.communicate()
    return out


def get_config_value(section, option):
    # TODO(beagles): get_config_value is an odd name for this function as the
    # hard coding of undercloud-passwords makes this a
    # "get_undercloud_password" function. It appears to only be used in one
    # place as well so the name.
    p = six.moves.configparser.ConfigParser()
    password_filename = os.path.expanduser("~/undercloud-passwords.conf")
    if not os.path.exists(password_filename):
        raise exceptions.PasswordFileNotFound(
            "Undercloud password file (%s) not found" % password_filename)

    p.read(password_filename)
    return p.get(section, option)


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


def get_endpoint(key, stack):
    endpoint_map = get_endpoint_map(stack)
    if endpoint_map:
        return endpoint_map[key]['host']
    else:
        return get_service_ips(stack).get(key + 'Vip')


__password_cache = None


def get_password(pass_name):
    """Retrieve a password by name, such as 'OVERCLOUD_ADMIN_PASSWORD'.

    Raises KeyError if password does not exist.
    """
    global __password_cache
    if __password_cache is None:
        __password_cache = generate_overcloud_passwords()
    return __password_cache[pass_name]


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


def create_cephx_key():
    # NOTE(gfidente): Taken from
    # https://github.com/ceph/ceph-deploy/blob/master/ceph_deploy/new.py#L21
    key = os.urandom(16)
    header = struct.pack("<hiih", 1, int(time.time()), 0, len(key))
    return base64.b64encode(header + key)


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
        raise ValueError("The given file {0} is not a regular "
                         "file".format(filepath))
    checksum = hashlib.md5()
    with open(filepath, 'rb') as f:
        while True:
            fragment = f.read(65536)
            if not fragment:
                break
            checksum.update(fragment)
    return checksum.hexdigest()


def check_nodes_count(baremetal_client, stack, parameters, defaults):
    """Check if there are enough available nodes for creating/scaling stack"""
    count = 0
    if stack:
        for param in defaults:
            try:
                current = int(stack.parameters[param])
            except KeyError:
                raise ValueError(
                    "Parameter '%s' was not found in existing stack" % param)
            count += parameters.get(param, current)
    else:
        for param, default in defaults.items():
            count += parameters.get(param, default)

    # We get number of nodes usable for the stack by getting already
    # used (associated) nodes and number of nodes which can be used
    # (not in maintenance mode).
    # Assumption is that associated nodes are part of the stack (only
    # one overcloud is supported).
    associated = len(baremetal_client.node.list(associated=True))
    available = len(baremetal_client.node.list(associated=False,
                                               maintenance=False))
    ironic_nodes_count = associated + available

    if count > ironic_nodes_count:
        raise exceptions.DeploymentError(
            "Not enough nodes - available: {0}, requested: {1}".format(
                ironic_nodes_count, count))
    else:
        return True


def ensure_run_as_normal_user():
    """Check if the command runs under normal user (EUID!=0)"""
    if os.geteuid() == 0:
        raise exceptions.RootUserExecution(
            'This command cannot run under root user.'
            ' Switch to a normal user.')


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


def add_deployment_plan_arguments(parser):
    """Add deployment plan arguments (flavors and scales) to a parser"""
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
                        help=_("Nova flavor to use for control nodes."))
    parser.add_argument('--compute-flavor',
                        help=_("Nova flavor to use for compute nodes."))
    parser.add_argument('--ceph-storage-flavor',
                        help=_("Nova flavor to use for ceph storage "
                               "nodes."))
    parser.add_argument('--block-storage-flavor',
                        help=_("Nova flavor to use for cinder storage "
                               "nodes."))
    parser.add_argument('--swift-storage-flavor',
                        help=_("Nova flavor to use for swift storage "
                               "nodes."))


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
