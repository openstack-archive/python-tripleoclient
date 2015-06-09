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

import base64
import hashlib
import json
import logging
import os
import re
import six
import struct
import subprocess
import sys
import time
import uuid


SERVICE_LIST = {
    'ceilometer': {'password_field': 'OVERCLOUD_CEILOMETER_PASSWORD'},
    'cinder': {'password_field': 'OVERCLOUD_CINDER_PASSWORD'},
    'ec2': {},
    'glance': {'password_field': 'OVERCLOUD_GLANCE_PASSWORD'},
    'heat': {'password_field': 'OVERCLOUD_HEAT_PASSWORD'},
    'neutron': {'password_field': 'OVERCLOUD_NEUTRON_PASSWORD'},
    'nova': {'password_field': 'OVERCLOUD_NOVA_PASSWORD'},
    'novav3': {'password_field': 'OVERCLOUD_NOVA_PASSWORD'},
    'swift': {'password_field': 'OVERCLOUD_SWIFT_PASSWORD'},
}


def _generate_password():
    """Create a random password

    The password is made by taking a uuid and passing it though sha1sum.
    We may change this in future to gain more entropy.

    This is based on the tripleo command os-make-password
    """
    uuid_str = six.text_type(uuid.uuid4()).encode("UTF-8")
    return hashlib.sha1(uuid_str).hexdigest()


def generate_overcloud_passwords(output_file="tripleo-overcloud-passwords"):
    """Create the passwords needed for the overcloud

    This will create the set of passwords required by the overcloud, store
    them in the output file path and return a dictionary of passwords. If the
    file already exists the existing passwords will be returned instead,
    """

    if os.path.isfile(output_file):
        with open(output_file) as f:
            return dict(line.split('=') for line in f.read().splitlines())

    password_names = (
        "OVERCLOUD_ADMIN_PASSWORD",
        "OVERCLOUD_ADMIN_TOKEN",
        "OVERCLOUD_CEILOMETER_PASSWORD",
        "OVERCLOUD_CEILOMETER_SECRET",
        "OVERCLOUD_CINDER_PASSWORD",
        "OVERCLOUD_DEMO_PASSWORD",
        "OVERCLOUD_GLANCE_PASSWORD",
        "OVERCLOUD_HEAT_PASSWORD",
        "OVERCLOUD_HEAT_STACK_DOMAIN_PASSWORD",
        "OVERCLOUD_NEUTRON_PASSWORD",
        "OVERCLOUD_NOVA_PASSWORD",
        "OVERCLOUD_SWIFT_HASH",
        "OVERCLOUD_SWIFT_PASSWORD",
    )

    passwords = dict((p, _generate_password()) for p in password_names)

    with open(output_file, 'w') as f:
        for name, password in passwords.items():
            f.write("{0}={1}\n".format(name, password))

    return passwords


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


def wait_for_stack_ready(
        orchestration_client, stack_name, loops=220, sleep=10):
    """Check the status of an orchestration stack

    Get the status of an orchestration stack and check whether it is complete
    or failed.

    :param orchestration_client: Instance of Orchestration client
    :type  orchestration_client: heatclient.v1.client.Client

    :param stack_name: Name or UUID of stack to retrieve
    :type  stack_name: string

    :param loops: How many times to loop
    :type loops: int

    :param sleep: How long to sleep between loops
    :type sleep: int
    """
    SUCCESSFUL_MATCH_OUTPUT = "(CREATE|UPDATE)_COMPLETE"
    FAIL_MATCH_OUTPUT = "(CREATE|UPDATE)_FAILED"

    for _ in range(0, loops):
        stack = orchestration_client.stacks.get(stack_name)

        if not stack:
            return False

        status = stack.stack_status

        if re.match(SUCCESSFUL_MATCH_OUTPUT, status):
            return True
        if re.match(FAIL_MATCH_OUTPUT, status):
            return False

        time.sleep(sleep)

    return False


def wait_for_provision_state(baremetal_client, node_uuid, provision_state,
                             loops=10, sleep=1):
    """Wait for a given Provisioning state in Ironic Discoverd

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
    """

    for _ in range(0, loops):

        node = baremetal_client.node.get(node_uuid)

        if node is None:
            # The node can't be found in ironic, so we don't need to wait for
            # the provision state
            return True

        if node.provision_state == provision_state:
            return True

        time.sleep(sleep)

    return False


def wait_for_node_discovery(discoverd_client, auth_token, discoverd_url,
                            node_uuids, loops=220, sleep=10):
    """Check the status of Node discovery in Ironic discoverd

    Gets the status and waits for them to complete.

    :param discoverd_client: Ironic Discoverd client
    :type  discoverd_client: ironic_discoverd.client

    :param auth_token: Authorisation token used by discoverd client
    :type auth_token: string

    :param discoverd_url: URL used by the discoverd client
    :type discoverd_url: string

    :param node_uuids: List of Node UUID's to wait for discovery
    :type node_uuids: [string, ]

    :param loops: How many times to loop
    :type loops: int

    :param sleep: How long to sleep between loops
    :type sleep: int
    """

    log = logging.getLogger(__name__ + ".wait_for_node_discovery")
    node_uuids = node_uuids[:]

    for _ in range(0, loops):

        for node_uuid in node_uuids:

            status = discoverd_client.get_status(
                node_uuid,
                base_url=discoverd_url,
                auth_token=auth_token)

            if status['finished']:
                log.debug("Discover finished for node {0} (Error: {1})".format(
                    node_uuid, status['error']))
                node_uuids.remove(node_uuid)
                yield node_uuid, status

        if not len(node_uuids):
            raise StopIteration
        time.sleep(sleep)

    if len(node_uuids):
        log.error("Discovery didn't finish for nodes {0}".format(
            ','.join(node_uuids)))


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
            "parameters": {
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
    """

    log = logging.getLogger(__name__ + ".set_nodes_state")

    for node in nodes:

        if node.provision_state in skipped_states:
            continue

        log.debug(
            "Setting provision state from {0} to '{1} for Node {2}"
            .format(node.provision_state, transition, node.uuid))

        baremetal_client.node.set_provision_state(node.uuid, transition)

        if not wait_for_provision_state(baremetal_client, node.uuid,
                                        target_state):
            print("FAIL: State not updated for Node {0}".format(
                  node.uuid, file=sys.stderr))


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

    p = six.moves.configparser.ConfigParser()
    p.read(os.path.expanduser("~/undercloud-passwords.conf"))
    return p.get(section, option)


def remove_known_hosts(overcloud_ip):
    """For a given IP address remove SSH keys from the known_hosts file"""

    known_hosts = os.path.expanduser("~/.ssh/known_hosts")

    if os.path.exists(known_hosts):
        command = ['ssh-keygen', '-R', overcloud_ip]
        subprocess.check_call(command)


def create_cephx_key():
    # NOTE(gfidente): Taken from
    # https://github.com/ceph/ceph-deploy/blob/master/ceph_deploy/new.py#L21
    key = os.urandom(16)
    header = struct.pack("<hiih", 1, int(time.time()), 0, len(key))
    return base64.b64encode(header + key)


def run_shell(cmd):
    return subprocess.check_call([cmd], shell=True)
