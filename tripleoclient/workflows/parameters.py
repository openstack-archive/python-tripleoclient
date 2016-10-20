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

from tripleoclient.workflows import base


def update_parameters(workflow_client, **input_):
    return base.call_action(workflow_client, 'tripleo.parameters.update',
                            **input_)


def reset_parameters(workflow_client, **input_):
    return base.call_action(workflow_client, 'tripleo.parameters.reset',
                            **input_)


def get_overcloud_passwords(clients, **workflow_input):
    """Retrieves overcloud passwords from a plan via a workflow

    :param clients:
    :param workflow_input:
    :return:
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']

    execution = base.start_workflow(
        workflow_client,
        'tripleo.plan_management.v1.get_passwords',
        workflow_input=workflow_input
    )

    with tripleoclients.messaging_websocket(queue_name) as ws:
        message = ws.wait_for_message(execution.id)
        assert message['status'] == "SUCCESS"
        return message['message']
