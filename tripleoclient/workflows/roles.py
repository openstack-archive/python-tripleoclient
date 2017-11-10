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

import logging

from tripleoclient import exceptions
from tripleoclient.workflows import base

LOG = logging.getLogger(__name__)


def list_roles(workflow_client, **input_):
    return base.call_action(workflow_client, 'tripleo.role.list', **input_)


def list_available_roles(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    available_roles = []
    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.plan_management.v1.list_available_roles',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if payload['status'] == 'SUCCESS':
                available_roles = payload['available_roles']
            else:
                raise exceptions.WorkflowServiceError(
                    'Error retrieving available roles: {}'.format(
                        payload.get('message')))

    return available_roles
