# Copyright 2017 Red Hat, Inc.
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

import uuid

from tripleoclient.exceptions import InvalidConfiguration
from tripleoclient.workflows import base


def delete_stack(clients, stack):
    """Deletes the stack named in the workflow_input.

    :param workflow_client: Workflow client
    :param stack: Name or ID of stack to delete
    """

    workflow_client = clients.workflow_engine
    tripleoclient = clients.tripleoclient

    workflow_input = {
        'stack': stack,
        'queue_name': str(uuid.uuid4()),
    }

    queue_name = workflow_input['queue_name']

    execution = base.start_workflow(
        workflow_client,
        'tripleo.stack.v1.delete_stack',
        workflow_input=workflow_input
    )

    with tripleoclient.messaging_websocket(queue_name) as ws:
        rtn_message = ws.wait_for_message(execution.id)
        if rtn_message['status'] != "SUCCESS":
            raise InvalidConfiguration(rtn_message['message'])
