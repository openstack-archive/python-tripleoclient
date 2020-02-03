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

from tripleo_common.actions import scale

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


def scale_down(clients, plan_name, nodes, timeout=None):
    """Unprovision and deletes overcloud nodes from a heat stack.

    :param clients: Application client object.
    :type clients: Object

    :param timeout: Timeout to use when deleting nodes. If timeout is None
                    it will be set to 240.
    :type timeout: Integer

    :param plan: Plan name.
    :type plan: String

    :param nodes: List of nodes to delete.
    :type nodes: List
    """

    workflow_input = {
        "plan_name": plan_name,
        "nodes": nodes,
    }

    ansible_tear_down(clients, **workflow_input)

    if not timeout:
        timeout = 240

    context = clients.tripleoclient.create_mistral_context()
    scale_down_action = scale.ScaleDownAction(nodes=nodes, timeout=timeout)
    scale_down_action.run(context=context)
