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

from tripleoclient import exceptions


def register_or_update(clients, **workflow_input):
    """Node Registration or Update

    Run the tripleo.baremetal.v1.register_or_update Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']

    execution = workflow_client.executions.create(
        'tripleo.baremetal.v1.register_or_update',
        workflow_input=workflow_input
    )

    with tripleoclients.messaging_websocket(queue_name) as ws:
        payload = ws.wait_for_message(execution.id)

    if payload['status'] == 'SUCCESS':
        registered_nodes = payload['registered_nodes']
        for nd in registered_nodes:
            print('Successfully registered node UUID %s' % nd['uuid'])
        return registered_nodes
    else:
        raise exceptions.RegisterOrUpdateError(
            'Exception registering nodes: {}'.format(payload['message']))


def provide(clients, **workflow_input):
    """Provide Baremetal Nodes

    Run the tripleo.baremetal.v1.provide Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']

    execution = workflow_client.executions.create(
        'tripleo.baremetal.v1.provide',
        workflow_input={'node_uuids': workflow_input['node_uuids'],
                        'queue_name': queue_name}
    )

    with tripleoclients.messaging_websocket(queue_name) as ws:
        payload = ws.wait_for_message(execution.id)

        if payload['status'] == 'SUCCESS':
            print('Successfully set all nodes to available.')
        else:
            raise exceptions.NodeProvideError(
                'Failed to set nodes to available state: {}'.format(
                    payload['message']))


def introspect_manageable_nodes(clients, **workflow_input):
    """Introspect all manageable nodes

    Run the tripleo.baremetal.v1.introspect_manageable_nodes Mistral workflow.
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']

    execution = workflow_client.executions.create(
        'tripleo.baremetal.v1.introspect_manageable_nodes',
        workflow_input={"queue_name": queue_name, }
    )

    print("Waiting for introspection to finish...")

    errors = []
    successful_node_uuids = set()

    with tripleoclients.messaging_websocket(queue_name) as ws:
        payload = ws.wait_for_message(execution.id)

    if payload['status'] == 'SUCCESS':
        introspected_nodes = payload['introspected_nodes']
        for node_uuid, status in introspected_nodes.items():
            if status['error'] is None:
                print(("Introspection for UUID {0} finished "
                       "successfully.").format(node_uuid))
                successful_node_uuids.add(node_uuid)
            else:
                print(("Introspection for UUID {0} finished with error"
                       ": {1}").format(node_uuid, status['error']))
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
    queue_name = workflow_input['queue_name']

    execution = workflow_client.executions.create(
        'tripleo.baremetal.v1.provide_manageable_nodes',
        workflow_input={"queue_name": queue_name, }
    )

    with tripleoclients.messaging_websocket(queue_name) as ws:
        payload = ws.wait_for_message(execution.id)

    if payload['status'] != 'SUCCESS':
        raise exceptions.NodeProvideError(
            'Exception providing nodes:{}'.format(payload['message']))

    print(payload['message'])
