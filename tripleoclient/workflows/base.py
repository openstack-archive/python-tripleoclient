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
import json
import logging

from tripleoclient import exceptions

LOG = logging.getLogger(__name__)


def call_action(workflow_client, action, **input_):
    """Trigger a Mistral action and parse the JSON response"""

    result = workflow_client.action_executions.create(
        action, input_,
        save_result=True, run_sync=True)

    # Parse the JSON output. Mistral client should do this for us really.
    output = json.loads(result.output)['result']

    if result.state == 'ERROR':
        raise exceptions.WorkflowActionError(action, output)
    return output


def start_workflow(workflow_client, identifier, workflow_input):

    execution = workflow_client.executions.create(
        identifier,
        workflow_input=workflow_input
    )

    print("Started Mistral Workflow {}. Execution ID: {}".format(
          identifier, execution.id))

    return execution


def wait_for_messages(mistral, websocket, execution, timeout=None):
    """Wait for messages on a websocket.

    Given an instance of mistral client, a websocket and a Mistral execution
    wait for messages on that websocket queue that match the execution ID until
    the timeout is reached.

    If no timeout is provided, this method will block forever.

    If a timeout is reached, called check_execution_status which will look up
    the execution on Mistral and log information about it.
    """
    try:
        for payload in websocket.wait_for_messages(timeout=timeout):
            yield payload
            # If the message is from a sub-workflow, we just need to pass it
            # on to be displayed. This should never be the last message - so
            # continue and wait for the next.
            if payload['execution']['id'] != execution.id:
                continue
            # Check the status of the payload, if we are not given one
            # default to running and assume it is just an "in progress"
            # message from the workflow.
            # Workflows should end with SUCCESS or ERROR statuses.
            if payload.get('status', 'RUNNING') != "RUNNING":
                raise StopIteration
    except exceptions.WebSocketTimeout:
        check_execution_status(mistral, execution.id)
        raise


def check_execution_status(workflow_client, execution_id):
    """Check the status of a workflow that timeout when waiting for messages

    The status will be logged.
    """

    execution = workflow_client.executions.get(execution_id)
    state = execution.state

    if state == 'RUNNING':
        message = "The WebSocket timed out before the Workflow completed."
    elif state == 'SUCCESS':
        message = ("The Workflow finished successfully but no messages were "
                   "received before the WebSocket timed out.")
    elif state == 'ERROR':
        message = "The Workflow errored and no messages were received."
    else:
        message = "Unknown Execution state."

    LOG.error(("Timed out waiting for messages from Execution "
               "(ID: {}, State: {}). {}").format(execution_id, state, message))
