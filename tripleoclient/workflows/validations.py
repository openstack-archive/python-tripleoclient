#   Copyright 2019 Red Hat, Inc.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#
import pprint

from tripleoclient.workflows import base


def list_validations(clients, workflow_input):

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.validations.v1.list',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if 'message' in payload:
                assert payload['status'] == "SUCCESS", pprint.pformat(payload)
                return payload['validations']


def run_validations(clients, workflow_input):

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    results = []

    with tripleoclients.messaging_websocket() as ws:

        if 'group_names' in workflow_input:
            print('Running group validations')
            execution = base.start_workflow(
                workflow_client,
                'tripleo.validations.v1.run_groups',
                workflow_input=workflow_input
            )
        else:
            print('Running single validations')
            execution = base.start_workflow(
                workflow_client,
                'tripleo.validations.v1.run_validations',
                workflow_input=workflow_input
            )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            if payload.get('message') is None:
                if payload.get('status') in ['SUCCESS', 'FAILED']:
                    results.append(payload)

        return results
