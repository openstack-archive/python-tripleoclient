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

from tripleoclient.workflows import base


def deploy(clients, **workflow_input):

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']

    execution = base.start_workflow(
        workflow_client,
        'tripleo.deployment.v1.deploy_plan',
        workflow_input=workflow_input
    )

    with tripleoclients.messaging_websocket(queue_name) as ws:
        message = ws.wait_for_message(execution.id)
        assert message['status'] == "SUCCESS", pprint.pformat(message)
