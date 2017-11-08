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


def check_predeployment_validations(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    execution = base.start_workflow(
        workflow_client,
        'tripleo.validations.v1.check_pre_deployment_validations',
        workflow_input=workflow_input
    )

    errors = []
    warnings = []
    with tripleoclients.messaging_websocket() as ws:
        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if payload.get('message'):
                print(payload['message'])
            if 'errors' in payload:
                errors += payload['errors']
            if 'warnings' in payload:
                warnings += payload['warnings']

    if errors:
        print('ERRORS')
        print(errors)
    if warnings:
        print('WARNINGS')
        print(warnings)

    return len(errors), len(warnings)
