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
import yaml

from tripleoclient import exceptions
from tripleoclient.workflows import base


LOG = logging.getLogger(__name__)


def update_parameters(workflow_client, **input_):
    return base.call_action(workflow_client, 'tripleo.parameters.update',
                            **input_)


def get_overcloud_passwords(clients, **workflow_input):
    """Retrieves overcloud passwords from a plan via a workflow

    :param clients:
    :param workflow_input:
    :return:
    """

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.plan_management.v1.get_passwords',
            workflow_input=workflow_input
        )

        # Getting the passwords is a quick operation, but to allow space for
        # delays or heavy loads, timeout after 60 seconds.
        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              60):
            assert payload['status'] == "SUCCESS"

        return payload['message']


def invoke_plan_env_workflows(clients, stack_name, plan_env_file):
    """Invokes the workflows in plan environment file"""

    try:
        with open(plan_env_file) as pf:
            plan_env_data = yaml.safe_load(pf.read())
    except IOError as exc:
        raise exceptions.PlanEnvWorkflowError('File (%s) is not found: '
                                              '%s' % (plan_env_file, exc))

    if plan_env_data and "workflow_parameters" in plan_env_data:
        for wf_name, wf_inputs in plan_env_data["workflow_parameters"].items():
            print('Invoking workflow (%s) specified in plan-environment '
                  'file' % wf_name)
            inputs = {'plan': stack_name, 'user_inputs': wf_inputs}
            workflow_client = clients.workflow_engine
            tripleoclients = clients.tripleoclient
            with tripleoclients.messaging_websocket() as ws:
                execution = base.start_workflow(
                    workflow_client,
                    wf_name,
                    workflow_input=inputs
                )

                # Getting the derive parameters timeout after 600 seconds.
                for payload in base.wait_for_messages(workflow_client,
                                                      ws, execution, 600):
                    if ('message' in payload and
                            (payload.get('status', 'RUNNING') == "RUNNING")):
                        print(payload['message'])

            if payload.get('status', 'FAILED') == 'SUCCESS':
                result = payload.get('result', '')
                # Prints the workflow result
                if result:
                    print('Workflow execution is completed. result:')
                    print(yaml.safe_dump(result, default_flow_style=False))
            else:
                message = payload.get('message', '')
                msg = ('Workflow execution is failed: %s' % (message))
                raise exceptions.PlanEnvWorkflowError(msg)


def check_deprecated_parameters(clients, container):
    """Checks for deprecated parameters in plan and adds warning if present"""

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    workflow_input = {
        'container': container
    }

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.plan_management.v1.get_deprecated_parameters',
            workflow_input=workflow_input
        )

        messages = base.wait_for_messages(workflow_client, ws, execution, 120)

        deprecated_params = []
        unused_params = []
        invalid_role_specific_params = []
        for message in messages:
            if message['status'] == 'SUCCESS':
                for param in message.get('deprecated', []):
                    if param.get('user_defined'):
                        deprecated_params.append(param['parameter'])
                unused_params = message.get('unused', [])
                invalid_role_specific_params = message.get(
                    'invalid_role_specific', [])

        if deprecated_params:
            deprecated_join = ', '.join(
                ['{param}'.format(param=param) for param in deprecated_params])
            LOG.warning(
                  'WARNING: Following parameter(s) are deprecated and still '
                  'defined. Deprecated parameters will be removed soon!'
                  ' {deprecated_join}'.format(
                      deprecated_join=deprecated_join))

        if unused_params:
            unused_join = ', '.join(
                ['{param}'.format(param=param) for param in unused_params])
            LOG.warning(
                  'WARNING: Following parameter(s) are defined but not used '
                  'in plan. Could be possible that parameter is valid but '
                  'currently not used.'
                  ' {unused_join}'.format(unused_join=unused_join))

        if invalid_role_specific_params:
            invalid_join = ', '.join(
                ['{param}'.format(
                    param=param) for param in invalid_role_specific_params])
            LOG.warning(
                  'WARNING: Following parameter(s) are not supported as '
                  'role-specific inputs. {invalid_join}'.format(
                      invalid_join=invalid_join))


def generate_fencing_parameters(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.parameters.v1.generate_fencing_parameters',
            workflow_input=workflow_input)

        for payload in base.wait_for_messages(workflow_client,
                                              ws, execution, 600):
            if payload['status'] != 'SUCCESS':
                raise exceptions.WorkflowServiceError(
                    'Exception generating fencing parameters: {}'.format(
                        payload['message']))
            if ('fencing_parameters' in payload and
                    (payload.get('status', 'FAILED') == "SUCCESS")):
                return payload['fencing_parameters']
