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
import time

from heatclient.common import event_utils
from openstackclient import shell
from tripleoclient import exceptions
from tripleoclient import utils

from tripleoclient.workflows import base
from zaqarclient.transport import errors as zaqar_errors


def update(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']
    plan_name = workflow_input['container']

    with tripleoclients.messaging_websocket(queue_name) as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.package_update.v1.package_update_plan',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            assert payload['status'] == "SUCCESS", pprint.pformat(payload)

    orchestration_client = clients.orchestration

    events = event_utils.get_events(orchestration_client,
                                    stack_id=plan_name,
                                    event_args={'sort_dir': 'desc',
                                                'limit': 1})
    marker = events[0].id if events else None

    time.sleep(10)
    create_result = utils.wait_for_stack_ready(
        orchestration_client, plan_name, marker, 'UPDATE', 1)
    if not create_result:
        shell.OpenStackShell().run(["stack", "failures", "list", plan_name])
        raise exceptions.DeploymentError("Heat Stack update failed.")


def get_config(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.package_update.v1.get_config',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            assert payload['status'] == "SUCCESS", pprint.pformat(payload)

    if payload['status'] == 'SUCCESS':
        print('Success')
    else:
        raise RuntimeError('Minor update failed with: {}'.format(payload))


def update_ansible(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']
    zaqar = clients.messaging
    queue = zaqar.queue(workflow_input['ansible_queue_name'])

    with tripleoclients.messaging_websocket(queue_name) as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.package_update.v1.update_nodes',
            workflow_input=workflow_input
        )
        timeout = time.time() + 600
        # First we need to wait for the first item in the queue
        while queue.stats['messages']['total'] == 0 or time.time() == timeout:
            pass
        # Then we can start to claim the queue
        while workflow_client.executions.get(execution.id).state == 'RUNNING':
            try:
                claim = queue.claim(ttl=600, grace=600)
                for message in claim:
                    pprint.pprint(
                        message.body['payload']['message'].splitlines())
                    message.delete()
            except zaqar_errors.ServiceUnavailableError:
                pass
        # clean the Queue
        queue.delete()

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if payload.get('message'):
                print(payload)

    if payload['status'] == 'SUCCESS':
        print('Success')
    else:
        raise RuntimeError('Minor update failed with: {}'.format(payload))
