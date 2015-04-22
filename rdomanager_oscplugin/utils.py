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

import hashlib
import logging
import re
import six
import time
import uuid


def _generate_password():
    """Create a random password

    The password is made by taking a uuid and passing it though sha1sum.
    echo "We may change this in future to gain more entropy.

    This is based on the tripleo command os-make-password
    """
    uuid_str = six.text_type(uuid.uuid1()).encode("UTF-8")
    return hashlib.sha1(uuid_str).hexdigest()


def generate_overcloud_passwords():

    passwords = (
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

    return dict((password, _generate_password()) for password in passwords)


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

    for _ in range(0, loops):

        node = baremetal_client.node.get(node_uuid)

        if node.provision_state == provision_state:
            return True

        time.sleep(sleep)

    return False


def wait_for_node_discovery(discoverd_client, auth_token, discoverd_url,
                            node_uuids, loops=220, sleep=10):
    """Check the status of Node discovery in Ironic discoverd

    Gets the status and waits for them to complete.

    :param discoverd_client: Instance of Orchestration client
    :type  discoverd_client: heatclient.v1.client.Client

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
