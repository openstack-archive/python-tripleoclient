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
import json
import logging
import os
import re
import six
import subprocess
import sys
import time
import uuid

from rdomanager_oscplugin import exceptions


def _generate_password():
    """Create a random password

    The password is made by taking a uuid and passing it though sha1sum.
    echo "We may change this in future to gain more entropy.

    This is based on the tripleo command os-make-password
    """
    uuid_str = six.text_type(uuid.uuid4()).encode("UTF-8")
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


def remove_known_hosts(overcloud_ip):
    """For a given IP address remove SSH keys from the known_hosts file"""

    known_hosts = os.path.expanduser("~/.ssh/known_hosts")

    if os.path.exists(known_hosts):
        command = ['ssh-keygen', '-R', overcloud_ip]
        subprocess.check_call(command)


def register_endpoint(name,
                      endpoint_type,
                      public_url,
                      identity_client,
                      password=None,
                      description=None,
                      admin_url=None,
                      internal_url=None,
                      region="regionOne"):
    SUFFIXES = {
        'baremetal': {'suffix': '/'},
        'compute': {'suffix': "/v2/$(tenant_id)s"},
        'computev3': {'suffix': "/v3"},
        'dashboard': {'suffix': "/",
                      'admin_suffix': "/admin"},
        'ec2': {'suffix': '/services/Cloud',
                'admin_suffix': '/service/Admin'},
        'identity': {'suffix': "/v2.0"},
        'image': {'suffix': '/'},
        'management': {'suffix': "/v2"},
        'metering': {'suffix': '/'},
        'network': {'suffix': '/'},
        'object-store': {'suffix': "/v1/AUTH_%%(tenant_id)s",
                         'admin_suffix': "/v1"},
        'orchestration': {'suffix': "/v1/%%(tenant_id)s"},
        'volume': {'suffix': "/v1/%%(tenant_id)s"},
        'volumev2': {'suffix': "/v2/%%(tenant_id)s"},
    }

    service = SUFFIXES.get(endpoint_type)

    if not service:
        raise exceptions.UnknownService

    suffix = service['suffix']
    admin_suffix = service.get('admin_suffix', suffix)

    if not internal_url:
        internal_url = public_url

    if not admin_url:
        admin_url = internal_url

    roles = identity_client.roles.list()
    admin_role_id = next((role.id for role in roles if role.name in 'admin'),
                         None)
    if not admin_role_id:
        raise exceptions.NotFound

    if endpoint_type not in 'dashboard':
        projects = identity_client.projects.list()
        service_project_id = next(project.id for project in
                                  projects if project.name in 'service')

        if not password:
            password = _generate_password()

        # Some services have multiple endpoints, the user doesn't need to
        # be recreated
        users = identity_client.users.list()
        user_id = next((user.id for user in users if user.name in name), None)
        if not user_id:
            user = identity_client.users.create(
                name,
                password,
                'nobody@example.com',
                tenant_id=service_project_id,
                enabled=True
            )
            user_id = user.id

        role = identity_client.roles.roles_for_user(
            user_id, service_project_id)

        if not role:
            # Log "Creating user-role assignment for user $NAME, role admin,
            # tenant service"
            identity_client.roles.grant(
                admin_role_id,
                user=user_id,
                project=service_project_id
            )

        # Add the admin tenant role for ceilometer user to enable polling
        # services
        if endpoint_type in 'metering':
            admin_project_id = next(project.id for project in
                                    projects if project.name in 'admin')
            # Log "Creating user-role assignment for user $NAME, role admin,
            # tenant admin"
            role = identity_client.roles.roles_for_user(
                user_id, admin_project_id)
            if not role:
                identity_client.roles.grant(
                    admin_role_id,
                    user=user_id,
                    project=admin_project_id
                )

                # swift polling requires ResellerAdmin role to be added to the
                # Ceilometer user
                reseller_admin_role_id = next(role.id for role in roles if
                                              role.name in 'ResellerAdmin')
                identity_client.roles.grant(
                    reseller_admin_role_id,
                    user=user_id,
                    project=admin_project_id
                )

    service = identity_client.services.create(
        name,
        endpoint_type,
        description)
    identity_client.endpoints.create(
        region,
        service.id,
        "%s%s" % (public_url, suffix),
        "%s%s" % (admin_url, admin_suffix),
        "%s%s" % (internal_url, suffix)
    )
    # Log "Service $TYPE created"


def setup_endpoints(overcloud_ip,
                    passwords,
                    identity_client,
                    region='regionOne',
                    enable_horizon=False,
                    ssl=None,
                    public=None):
    """Perform initial setup of a cloud running on <overcloud_ip>

    This will register ec2, image, orchestration, identity, network,
    volume (optional), dashboard (optional), metering (optional) and
    compute services as running on the default ports on controlplane-ip.
    """

    SERVICE_LIST = [
        {'name': 'ceilometer', 'type': 'metering',
         'description': 'Ceilometer Service',
         'port': 8777, 'ssl_port': 13777,
         'password_field': 'OVERCLOUD_CEILOMETER_PASSWORD'},
        {'name': 'cinder', 'type': 'volume',
         'description': 'Cinder Volume Service',
         'port': 8776, 'ssl_port': 13776,
         'password_field': 'OVERCLOUD_CINDER_PASSWORD'},
        {'name': 'cinderv2', 'type': 'volumev2',
         'description': 'Cinder Volume Service V2',
         'port': 8776, 'ssl_port': 13776,
         'password_field': 'OVERCLOUD_CINDER_PASSWORD'},
        {'name': 'ec2', 'type': 'ec2',
         'description': 'EC2 Compatibility Layer',
         'port': 8773, 'ssl_port': 13773},
        {'name': 'glance', 'type': 'image',
         'description': 'Glance Image Service',
         'port': 9292, 'ssl_port': 13292,
         'password_field': 'OVERCLOUD_GLANCE_PASSWORD'},
        {'name': 'heat', 'type': 'orchestration',
         'description': 'Heat Service',
         'port': 8004, 'ssl_port': 13004,
         'password_field': 'OVERCLOUD_HEAT_PASSWORD'},
        {'name': 'ironic', 'type': 'baremetal',
         'description': 'Ironic Service',
         'port': 6385, 'ssl_port': 6385,
         'password_field': 'OVERCLOUD_IRONIC_PASSWORD'},
        {'name': 'neutron', 'type': 'network',
         'description': 'Neutron Service',
         'port': 9696, 'ssl_port': 13696,
         'password_field': 'OVERCLOUD_NEUTRON_PASSWORD'},
        {'name': 'nova', 'type': 'compute',
         'description': 'Nova Compute Service',
         'port': 8774, 'ssl_port': 13774,
         'password_field': 'OVERCLOUD_NOVA_PASSWORD'},
        {'name': 'nova', 'type': 'computev3',
         'description': 'Nova Compute Service v3',
         'port': 8774, 'ssl_port': 13774,
         'password_field': 'OVERCLOUD_NOVA_PASSWORD'},
        {'name': 'swift', 'type': 'object-store',
         'description': 'Swift Object Storage Service',
         'port': 8080, 'ssl_port': 13080,
         'password_field': 'OVERCLOUD_SWIFT_PASSWORD'},
        {'name': 'tuskar', 'type': 'management',
         'description': 'Tuskar Service',
         'port': 8585, 'ssl_port': 8585,
         'password_field': 'OVERCLOUD_TUSKAR_PASSWORD'},
    ]

    skip_no_password = [
        'metering',
        'volume',
        'volumev2',
        'object-store',
        'baremetal',
        'management'
    ]

    internal_host = 'http://%s:' % overcloud_ip

    if ssl:
        public_host = "https://%s:" % ssl
    elif public:
        public_host = "http://%s:" % public
    else:
        public_host = internal_host

    for service in SERVICE_LIST:
        password_field = service.get('password_field', None)
        password = passwords.get(password_field, None)

        if not password and service['type'] in skip_no_password:
            continue

        port = service['port']
        ssl_port = service['ssl_port'] if ssl else port
        args = (
            service['name'],
            service['type'],
            "%s%d" % (public_host, port),
            identity_client,
        )
        kwargs = {
            'description': service['description'],
            'region': region,
            'internal_url': "%s%d" % (internal_host, ssl_port),
        }

        if password:
            kwargs.update({'password': password})

        register_endpoint(*args, **kwargs)

    if enable_horizon:
        # Horizon is different enough to warrant a separate case
        register_endpoint('horizon', 'dashboard', internal_host,
                          identity_client, description="OpenStack Dashboard",
                          internal_url=internal_host,
                          region=region)
