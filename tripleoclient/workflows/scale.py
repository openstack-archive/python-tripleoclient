# Copyright 2016 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from __future__ import print_function

from tripleoclient import exceptions
from tripleoclient.workflows import base


def ansible_tear_down(clients, **workflow_input):

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    workflow_input['playbook_name'] = 'scale_playbook.yaml'

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.deployment.v1.config_download_deploy',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            print(payload['message'])

    if payload['status'] == 'SUCCESS':
        print("Scale-down configuration completed.")
    else:
        raise exceptions.DeploymentError("Scale-down configuration failed.")


def delete_node(clients, timeout, **workflow_input):

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    if timeout is not None:
        workflow_input['timeout'] = timeout

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.scale.v1.delete_node',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            status = payload['status']
            if status == 'RUNNING':
                continue
            if status != 'SUCCESS':
                raise exceptions.InvalidConfiguration(payload['message'])


def scale_down(clients, plan_name, nodes, timeout=None):
    """Unprovision and deletes overcloud nodes from a heat stack.

    :param clients: openstack clients
    :param plan_name: name of the container holding the plan data
    :param nodes: list of node id's to remove from the stack
    :param timeout: timeout for stack update operation
    """

    workflow_input = {
        "plan_name": plan_name,
        "nodes": nodes,
    }

    ansible_tear_down(clients, **workflow_input)
    delete_node(clients, timeout, **workflow_input)
