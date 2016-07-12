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


def call_action(workflow_client, action, **input_):
    """Trigger a Mistral action and parse the JSON response"""

    result = workflow_client.action_executions.create(action, input_)

    # Parse the JSON output. Mistral client should do this for us really.
    return json.loads(result.output)['result']


def start_workflow(workflow_client, identifier, workflow_input):

    execution = workflow_client.executions.create(
        identifier,
        workflow_input=workflow_input
    )

    print("Started Mistral Workflow. Execution ID: {}".format(
          execution.id))

    return execution
