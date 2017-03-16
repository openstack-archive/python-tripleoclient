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

import pprint
import uuid

from tripleo_common import update as update_common

from tripleoclient import utils as oooutils
from tripleoclient.workflows import base


def update(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']

    execution = base.start_workflow(
        workflow_client,
        'tripleo.package_update.v1.package_update_plan',
        workflow_input=workflow_input
    )

    with tripleoclients.messaging_websocket(queue_name) as ws:
        for payload in base.wait_for_messages(workflow_client, ws, execution):
            assert payload['status'] == "SUCCESS", pprint.pformat(payload)


def update_and_wait(log, clients, stack, plan_name, verbose_level,
                    timeout=None):
    """Start the update and wait for it to give breakpoints or finish"""

    log.info("Performing Heat stack update")
    queue_name = str(uuid.uuid4())

    workflow_input = {
        "container": plan_name,
        "queue_name": queue_name,
    }

    if timeout is not None:
        workflow_input['timeout'] = timeout

    update(clients, **workflow_input)

    update_manager = update_common.PackageUpdateManager(
        heatclient=clients.orchestration,
        novaclient=clients.compute,
        stack_id=plan_name,
        stack_fields={})

    update_manager.do_interactive_update()

    stack = oooutils.get_stack(clients.orchestration,
                               plan_name)

    return stack.status


def abort_update(clients, **workflow_input):

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    workflow_input['queue_name'] = str(uuid.uuid4())
    queue_name = workflow_input['queue_name']

    execution = base.start_workflow(
        workflow_client,
        'tripleo.package_update.v1.cancel_stack_update',
        workflow_input=workflow_input
    )

    with tripleoclients.messaging_websocket(queue_name) as ws:
        for payload in base.wait_for_messages(workflow_client, ws, execution):
            assert payload['status'] == "SUCCESS", pprint.pformat(payload)


def clear_breakpoints(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    workflow_input['queue_name'] = str(uuid.uuid4())
    queue_name = workflow_input['queue_name']

    execution = base.start_workflow(
        workflow_client,
        'tripleo.package_update.v1.clear_breakpoints',
        workflow_input=workflow_input
    )

    with tripleoclients.messaging_websocket(queue_name) as ws:
        for payload in base.wait_for_messages(workflow_client, ws, execution):
            assert payload['status'] == "SUCCESS", pprint.pformat(payload)
