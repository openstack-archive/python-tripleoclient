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

from tripleoclient import exceptions
from tripleoclient.workflows import base


def validate_nodes(clients, **workflow_input):
    """Node Registration or Update

    Run the tripleo.baremetal.v1.validate_nodes Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.validate_nodes',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if 'message' in payload:
                print(payload['message'])

    if payload['status'] == 'SUCCESS':
        print('Successfully validated environment file')
        return True
    else:
        raise exceptions.RegisterOrUpdateError(
            'Exception validating environment file: {}'.format(
                payload['message'])
        )


def register_or_update(clients, **workflow_input):
    """Node Registration or Update

    Run the tripleo.baremetal.v1.register_or_update Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.register_or_update',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if 'message' in payload:
                print(payload['message'])

    if payload['status'] == 'SUCCESS':
        registered_nodes = payload['registered_nodes']
        for nd in registered_nodes:
            print('Successfully registered node UUID %s' % nd['uuid'])
        return registered_nodes
    else:
        raise exceptions.RegisterOrUpdateError(
            'Exception registering nodes: {}'.format(payload['message']))


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
                'run_validations': workflow_input['run_validations']}
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if 'message' in payload:
                print(payload['message'])

        if payload['status'] != 'SUCCESS':
            raise exceptions.IntrospectionError(
                "Introspection completed with errors:\n%s" % '\n'
                .join(msg for msg in payload['message'] if msg))


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
                'run_validations': workflow_input['run_validations']}
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


def discover_and_enroll(clients, **workflow_input):
    """Discover nodes.

    Run the tripleo.baremetal.v1.discover_and_enroll_nodes Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.baremetal.v1.discover_and_enroll_nodes',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if payload.get('message'):
                print(payload['message'])

    if payload['status'] == 'SUCCESS':
        registered_nodes = payload['registered_nodes']
        for nd in registered_nodes:
            print('Successfully registered node UUID %s' % nd['uuid'])
        return registered_nodes
    else:
        raise exceptions.RegisterOrUpdateError(
            'Exception discovering nodes: {}'.format(payload['message']))


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
