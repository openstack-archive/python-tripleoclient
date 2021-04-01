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
import glob
import hashlib
import logging
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
from heatclient import exc as hc_exc
from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from oslo_concurrency import processutils
from six.moves import configparser

from tripleo_common.utils import config
from tripleoclient import constants
from tripleoclient import exceptions


LOG = logging.getLogger(__name__ + ".utils")


def run_ansible_playbook(logger,
                         workdir,
                         playbook,
                         inventory,
                         ansible_config=None,
                         retries=True,
                         connection='smart',
                         output_callback='json',
                         python_interpreter=None,
                         ssh_user='root',
                         key=None,
                         module_path=None,
                         limit_hosts=None,
                         tags='',
                         skip_tags='',
                         verbosity=1):
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

    :param connection: connection type (local, smart, etc)
    :type connection: String

    :param output_callback: Callback for output format. Defaults to "json"
    :type output_callback: String

    :param python_interpreter: Absolute path for the Python interpreter
    on the host where Ansible is run.
    :type python_interpreter: String

    :param ssh_user: user for the ssh connection
    :type ssh_user: String

    :param key: private key to use for the ssh connection
    :type key: String

    :param module_path: location of the ansible module and library
    :type module_path: String

    :param limit_hosts: limit the execution to the hosts
    :type limit_hosts: String

    :param tags: run specific tags
    :type tags: String

    :param skip_tags: skip specific tags
    :type skip_tags: String

    :param verbosity: verbosity level for Ansible execution
    :type verbosity: Interger
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
    env['ANSIBLE_LOG_PATH'] = os.path.join(workdir, 'ansible.log')
    env['ANSIBLE_HOST_KEY_CHECKING'] = 'False'

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
               '-u', ssh_user,
               '-i', inventory
               ]

        if 0 < verbosity < 6:
            cmd.extend(['-' + ('v' * verbosity)])

        if key is not None:
            cmd.extend(['--private-key=%s' % key])

        if module_path is not None:
            cmd.extend(['--module-path=%s' % module_path])

        if limit_hosts is not None:
            cmd.extend(['-l %s' % limit_hosts])

        if tags is not '':
            cmd.extend(['-t %s' % tags])

        if skip_tags is not '':
            cmd.extend(['--skip_tags %s' % skip_tags])

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


def download_ansible_playbooks(client, stack_name, output_dir='/tmp'):

    log = logging.getLogger(__name__ + ".download_ansible_playbooks")
    stack_config = config.Config(client)
    tmp_ansible_dir = tempfile.mkdtemp(prefix='tripleo-ansible-',
                                       dir=output_dir)

    log.warning(_('Downloading {0} ansible playbooks...').format(stack_name))
    stack_config.write_config(stack_config.fetch_config(stack_name),
                              stack_name,
                              tmp_ansible_dir)
    return tmp_ansible_dir


def bracket_ipv6(address):
    """Put a bracket around address if it is valid IPv6

    Return it unchanged if it is a hostname or IPv4 address.
    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return "[%s]" % address
    except socket.error:
        return address


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
            messages = "Unable to create TripleO history directory: " \
                       "{0}, {1}".format(history_path, e)
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
            messages = "Unable to write into TripleO history file: "
            "{0}, {1}".format(history_path, e)
            raise IOError(messages)
    else:
        raise exceptions.InvalidConfiguration("Target path %s is not a "
                                              "directory" % history_path)


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
    stack_name = stack.stack_name

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
    except hc_exc.HTTPNotFound:
        pass


def check_ceph_fsid_matches_env_files(stack, environment):
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
    stack_ceph_fsid = stack.environment().get('parameter_defaults',
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
                message = "Failed to generate inventory: %s" % str(e)
                raise exceptions.InvalidConfiguration(message)
    if os.path.exists(inventory_file):
        inventory = open(inventory_file, 'r').read()
        return inventory
    else:
        raise exceptions.InvalidConfiguration(
            "Inventory file %s can not be found." % inventory_file)


def run_update_ansible_action(log, clients, nodes, inventory,
                              playbook, all_playbooks, ssh_user,
                              action=None, skip_tags='',
                              verbosity='1', workdir='', priv_key=''):

    playbooks = [playbook]
    if playbook == "all":
        playbooks = all_playbooks
    for book in playbooks:
        log.debug("Running ansible playbook %s " % book)
        if action:
            action.update_ansible(clients, nodes=nodes,
                                  inventory_file=inventory,
                                  playbook=book, node_user=ssh_user,
                                  skip_tags=skip_tags,
                                  verbosity=verbosity)
        else:
            run_ansible_playbook(logger=LOG,
                                 workdir=workdir,
                                 playbook=book,
                                 inventory=inventory,
                                 ssh_user=ssh_user,
                                 key=ssh_private_key(workdir, priv_key),
                                 module_path='/usr/share/ansible-modules',
                                 limit_hosts=nodes,
                                 skip_tags=skip_tags)


def ssh_private_key(workdir, key):
    if not key:
        return None
    if (isinstance(key, six.string_types) and
            os.path.exists(key)):
        return key

    path = os.path.join(workdir, 'ssh_private_key')
    with open(path, 'w') as ssh_key:
        ssh_key.write(key)
    os.chmod(path, 0o600)
    return path


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
        raise exceptions.InvalidConfiguration(
            "Expected environment file %s not found in %s cannot proceed."
            % (environment, templates_dir))

    return environment_files


def ffwd_upgrade_operator_confirm(parsed_args_yes, log):
    print("\nWarning! The TripleO Fast Forward Upgrade "
          "workflow is a critical operation against the deployed "
          "environment.\nOnce and if you decide to use ffwd-upgrade "
          "in production, ensure you are adequately prepared "
          "with valid backup of your current deployment state.\n")
    if parsed_args_yes:
        log.debug("Fast forward upgrade --yes continuing")
        print("Continuing fast forward upgrade")
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
            log.debug("Fast forward upgrade cancelled on user request")
            print("Cancelling fast forward upgrade")
            sys.exit(1)


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

    log = logging.getLogger(__name__ + ".check_file_for_enabled_service")

    if os.path.exists(env_file):
        content = yaml.load(open(env_file))
        deprecated_services_enabled = []
        for service in constants.DEPRECATED_SERVICES.keys():
            try:
                if content["resource_registry"][service] != "OS::Heat::None":
                    log.warning("service " + service + " is enabled in "
                                + str(env_file) + ". " +
                                constants.DEPRECATED_SERVICES[service])
                    deprecated_services_enabled.append(service)
            except (KeyError, TypeError):
                # ignore if content["resource_registry"] is empty
                pass
        if deprecated_services_enabled:
            confirm = prompt_user_for_confirmation(
                message="Do you still wish to continue with deployment [y/N]",
                logger=log)
            if not confirm:
                raise oscexc.CommandError("Action not confirmed, exiting.")


def check_deprecated_service_is_enabled(environment_files):
    for env_file in environment_files:
        check_file_for_enabled_service(env_file)


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
