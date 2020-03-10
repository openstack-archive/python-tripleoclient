# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import print_function

import six

from tripleo_common.actions import baremetal
from tripleo_common.actions import baremetal_deploy

from tripleoclient import exceptions
from tripleoclient.workflows import base


def validate_nodes(clients, nodes_json):
    """Validate nodes.

    :param clients: Application client object.
    :type clients: Object

    :param nodes_json:
    :type nodes_json: Object

    :returns: Boolean
    """

    context = clients.tripleoclient.create_mistral_context()
    nodes = baremetal.ValidateNodes(nodes_json=nodes_json)
    validated_nodes = nodes.run(context=context)
    if not validated_nodes:
        return True
    else:
        raise exceptions.RegisterOrUpdateError(validated_nodes)


def register_or_update(clients, nodes_json, kernel_name=None,
                       ramdisk_name=None, instance_boot_option=None):
    """Node Registration or Update

    :param clients: Application client object.
    :type clients: Object

    :param nodes_json:
    :type nodes_json: Object

    :param kernel_name: Kernel to use
    :type kernel_name: String

    :param ramdisk_name: RAMDISK to use
    :type ramdisk_name: String

    :param instance_boot_option: Whether to set instances for booting from
                                 local hard drive (local) or network
                                 (netboot).
    :type instance_boot_option: String

    :returns: List
    """

    context = clients.tripleoclient.create_mistral_context()
    nodes = baremetal.RegisterOrUpdateNodes(
        nodes_json=nodes_json,
        ramdisk_name=ramdisk_name,
        kernel_name=kernel_name,
        instance_boot_option=instance_boot_option
    )

    registered_nodes = nodes.run(context=context)
    if not isinstance(registered_nodes, list):
        raise exceptions.RegisterOrUpdateError(registered_nodes)
    else:
        for node in registered_nodes:
            if node.provision_state == 'enroll':
                clients.baremetal.node.set_provision_state(
                    node_uuid=node.uuid,
                    state='manage'
                )
                print('Successfully registered node UUID {}'.format(node.uuid))
            else:
                print('Node UUID {} is already registered'.format(node.uuid))

    return registered_nodes


def _format_errors(payload):
    errors = []
    messages = payload.get('message', [])
    for msg in messages:
        # Adapt for different formats
        if isinstance(msg, six.string_types):
            text = msg
        else:
            text = msg.get('result') or msg.get('message', '')
        try:
            # With multiple workflows, the error message can become
            # quite large and unreadable as it gets passed from task to
            # task. This attempts to keep only the last, and hopefully
            # useful part.
            errors.append(text.rstrip('\n').split('\n')[-1])
        except Exception:
            errors.append(text)
    return '\n'.join(errors)


def provide(clients, **workflow_input):
    """Provide Baremetal Nodes

    Run the tripleo.baremetal.v1.provide Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.provide',
            workflow_input={'node_uuids': workflow_input['node_uuids']}
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if 'message' in payload:
                print(payload['message'])

    if payload['status'] != 'SUCCESS':
        try:
            message = _format_errors(payload)
        except Exception:
            message = 'Failed.'
        raise exceptions.NodeProvideError(
            'Failed to set nodes to available state: {}'.format(message))


def introspect(clients, **workflow_input):
    """Introspect Baremetal Nodes

    Run the tripleo.baremetal.v1.introspect Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    print("Waiting for introspection to finish...")

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.introspect',
            workflow_input={
                'node_uuids': workflow_input['node_uuids'],
                'run_validations': workflow_input['run_validations'],
                'concurrency': workflow_input.get('concurrency', 20)
            }
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if 'message' in payload:
                print(payload['message'])

        if payload['status'] != 'SUCCESS':
            raise exceptions.IntrospectionError(
                "Introspection completed with errors: {}"
                .format(payload['message']))


def introspect_manageable_nodes(clients, **workflow_input):
    """Introspect all manageable nodes

    Run the tripleo.baremetal.v1.introspect_manageable_nodes Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    print("Waiting for introspection to finish...")

    errors = []

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.introspect_manageable_nodes',
            workflow_input={
                'run_validations': workflow_input['run_validations'],
                'concurrency': workflow_input.get('concurrency', 20)
            }
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if 'message' in payload:
                print(payload['message'])

    if payload['status'] == 'SUCCESS':
        introspected_nodes = payload['introspected_nodes'] or {}
        for node_uuid, status in introspected_nodes.items():
            if status['error'] is not None:
                errors.append("%s: %s" % (node_uuid, status['error']))
    else:
        raise exceptions.IntrospectionError(
            'Exception introspecting nodes: {}'.format(payload['message']))

    if errors:
        raise exceptions.IntrospectionError(
            "Introspection completed with errors:\n%s" % '\n'
            .join(errors))

    print("Introspection completed.")


def provide_manageable_nodes(clients, **workflow_input):
    """Provide all manageable Nodes

    Run the tripleo.baremetal.v1.provide_manageable_nodes Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.provide_manageable_nodes',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if 'message' in payload:
                print(payload['message'])

    if payload['status'] != 'SUCCESS':
        raise exceptions.NodeProvideError(
            'Exception providing nodes:{}'.format(payload['message']))

    print(payload['message'])


def configure(clients, **workflow_input):
    """Configure Node boot options.

    Run the tripleo.baremetal.v1.configure Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    ooo_client = clients.tripleoclient

    with ooo_client.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.configure',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if 'message' in payload:
                print(payload['message'])

    if payload['status'] != 'SUCCESS':
        raise exceptions.NodeConfigurationError(
            'Failed to configure nodes: {}'.format(payload['message']))


def configure_manageable_nodes(clients, **workflow_input):
    """Configure all manageable Nodes.

    Run the tripleo.baremetal.v1.configure_manageable_nodes Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    ooo_client = clients.tripleoclient

    with ooo_client.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.configure_manageable_nodes',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if 'message' in payload:
                print(payload['message'])

    if payload['status'] != 'SUCCESS':
        raise exceptions.NodeConfigurationError(
            'Exception configuring nodes: {}'.format(payload['message']))

    print(payload['message'])


def create_raid_configuration(clients, **workflow_input):
    """Create RAID configuration on nodes.

    Run the tripleo.baremetal.v1.create_raid_configuration Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    ooo_client = clients.tripleoclient

    print('Creating RAID configuration for given nodes, this may take time')

    with ooo_client.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.create_raid_configuration',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if 'message' in payload:
                print(payload['message'])

    if payload['status'] == 'SUCCESS':
        print('Success')
    else:
        raise RuntimeError(
            'Failed to create RAID: {}'.format(payload['message']))


def discover_and_enroll(clients, ip_addresses, credentials, kernel_name,
                        ramdisk_name, instance_boot_option,
                        existing_nodes=None, ports=None):
    """Discover nodes and enroll baremetal nodes.

    :param clients: application client object.
    :type clients: Object

    :param ip_addresses: List of IP addresses.
    :type ip_addresses: List || String

    :param credentials: Credential information object
    :type credentials: Tuple

    :param kernel_name: Kernel to use
    :type kernel_name: String

    :param ramdisk_name: RAMDISK to use
    :type ramdisk_name: String

    :param instance_boot_option: Boot options to use
    :type instance_boot_option: String

    :param existing_nodes: List of nodes already discovered. If this is
                           undefined this object will be set to an empty
                           array.
    :type existing_nodes: List

    :param ports: List of ports, if no ports are provided the list of ports
                  will be limted to [623].
    :type ports: List

    :returns: List
    """

    if not ports:
        ports = [623]

    if not existing_nodes:
        existing_nodes = list()

    context = clients.tripleoclient.create_mistral_context()

    get_candiate_nodes = baremetal.GetCandidateNodes(
        ip_addresses,
        ports,
        credentials,
        existing_nodes
    )
    probed_nodes = list()
    for node in get_candiate_nodes.run(context=context):
        probed_nodes.append(
            baremetal.ProbeNode(**node).run(context=context)
        )
        print('Successfully probed node IP {}'.format(node['ip']))

    return register_or_update(
        clients=clients,
        nodes_json=probed_nodes,
        instance_boot_option=instance_boot_option,
        kernel_name=kernel_name,
        ramdisk_name=ramdisk_name
    )


def clean_nodes(clients, **workflow_input):
    """Clean Baremetal Nodes

    Run the tripleo.baremetal.v1.clean_nodes Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.clean_nodes',
            workflow_input={'node_uuids': workflow_input['node_uuids']}
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if payload.get('message'):
                print(payload['message'])

    if payload['status'] != 'SUCCESS':
        message = _format_errors(payload)
        raise exceptions.NodeConfigurationError(
            'Error(s) cleaning nodes:\n{}'.format(message))

    print('Successfully cleaned nodes')


def clean_manageable_nodes(clients, **workflow_input):
    """Clean all manageable Nodes

    Run the tripleo.baremetal.v1.clean_manageable_nodes Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.clean_manageable_nodes',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if payload.get('message'):
                print(payload['message'])

    if payload['status'] != 'SUCCESS':
        raise exceptions.NodeConfigurationError(
            'Error cleaning nodes: {}'.format(payload['message']))

    print('Cleaned %d node(s)' % len(payload['cleaned_nodes']))


def apply_bios_configuration(clients, **workflow_input):
    """Apply BIOS settings on nodes.

    Run the tripleo.baremetal.v1.apply_bios_settings Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    ooo_client = clients.tripleoclient

    print('Applying BIOS settings for given nodes, this may take time')

    with ooo_client.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.apply_bios_settings',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if payload.get('message'):
                print(payload['message'])

    if payload['status'] == 'SUCCESS':
        print('Success')
    else:
        raise RuntimeError(
            'Failed to apply BIOS settings: {}'.format(payload['message']))


def apply_bios_configuration_on_manageable_nodes(clients, **workflow_input):
    """Apply BIOS settings on manageable nodes.

    Run the tripleo.baremetal.v1.apply_bios_settings_on_manageable_nodes
    Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    ooo_client = clients.tripleoclient

    print('Applying BIOS settings for manageable nodes, this may take time')

    with ooo_client.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.apply_bios_settings_on_manageable_nodes',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if payload.get('message'):
                print(payload['message'])

    if payload['status'] == 'SUCCESS':
        print('Success')
    else:
        raise RuntimeError(
            'Failed to apply BIOS settings: {}'.format(payload['message']))


def reset_bios_configuration(clients, **workflow_input):
    """Reset BIOS settings on nodes.

    Run the tripleo.baremetal.v1.reset_bios_settings Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    ooo_client = clients.tripleoclient

    print('Reset BIOS settings on given nodes, this may take time')

    with ooo_client.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.reset_bios_settings',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if payload.get('message'):
                print(payload['message'])

    if payload['status'] == 'SUCCESS':
        print('Success')
    else:
        raise RuntimeError(
            'Failed to reset BIOS settings: {}'.format(payload['message']))


def reset_bios_configuration_on_manageable_nodes(clients, **workflow_input):
    """Reset BIOS settings on manageable nodes.

    Run the tripleo.baremetal.v1.reset_bios_settings_on_manageable_nodes
    Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    ooo_client = clients.tripleoclient

    print('Reset BIOS settings on manageable nodes, this may take time')

    with ooo_client.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.reset_bios_settings_on_manageable_nodes',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if payload.get('message'):
                print(payload['message'])

    if payload['status'] == 'SUCCESS':
        print('Success')
    else:
        raise RuntimeError(
            'Failed to reset BIOS settings: {}'.format(payload['message']))


def deploy_roles(clients, **workflow_input):
    """Deploy provided roles using Ironic.

    Run the tripleo.baremetal_deploy.v1.deploy_roles Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal_deploy.v1.deploy_roles',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if payload.get('message'):
                print(payload['message'])

    if payload['status'] != 'SUCCESS':
        raise exceptions.NodeConfigurationError(
            'Error deploying nodes: {}'.format(payload['message']))

    return payload


def undeploy_roles(clients, **workflow_input):
    """Undeploy provided roles using Ironic.

    Run the tripleo.baremetal_deploy.v1.undeploy_roles Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal_deploy.v1.undeploy_roles',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if payload.get('message'):
                print(payload['message'])

    if payload['status'] != 'SUCCESS':
        raise exceptions.NodeConfigurationError(
            'Error undeploying nodes: {}'.format(payload['message']))

    return payload


def expand_roles(clients, roles, stackname, provisioned):
    context = clients.tripleoclient.create_mistral_context()
    expand_roles = baremetal_deploy.ExpandRolesAction(
        roles=roles,
        stackname=stackname,
        provisioned=provisioned
    )
    return expand_roles.run(context=context)
