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
import os
import re
import yaml

from tripleoclient.constants import UNUSED_PARAMETER_EXCLUDES_RE
from tripleoclient import exceptions
from tripleoclient.workflows import base


LOG = logging.getLogger(__name__)


def update_parameters(workflow_client, **input_):
    return base.call_action(workflow_client, 'tripleo.parameters.update',
                            **input_)


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
        has_messages = False

        for message in messages:
            if message['status'] != 'SUCCESS':
                return

            has_messages = True
            deprecated_params = [
                param['parameter'] for param in message.get('deprecated', [])
                if param.get('user_defined')
            ]
            unused_params = message.get('unused', [])
            invalid_role_specific_params = message.get(
                'invalid_role_specific', [])

        if not has_messages:
            return

        if deprecated_params:
            deprecated_join = ', '.join(
                ['{param}'.format(param=param) for param in deprecated_params])
            LOG.warning(
                  'WARNING: Following parameter(s) are deprecated and still '
                  'defined. Deprecated parameters will be removed soon!'
                  ' {deprecated_join}'.format(
                      deprecated_join=deprecated_join))

        # exclude our known params that may not be used
        ignore_re = re.compile('|'.join(UNUSED_PARAMETER_EXCLUDES_RE))
        unused_params = [p for p in unused_params if not ignore_re.search(p)]

        if unused_params:
            unused_join = ', '.join(
                ['{param}'.format(param=param) for param in unused_params])
            LOG.warning(
                  'WARNING: Following parameter(s) are defined but not '
                  'currently used in the deployment plan. These parameters '
                  'may be valid but not in use due to the service or '
                  'deployment configuration.'
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


def check_forbidden_params(log, env_files, forbidden):
    """Looks for undesired parameters in the environment files.

    Each of the environment files pass in env_files will be parsed
    and if the parameters_default key is found, then all the keys
    from the nested dictionary found under will be converted into
    a list, for example:

    parameters_default:
        key1: value1
        key2: value2
        key3:
          - value3
          - key31:
              key311: value311
              key312: value312
            key32: value32

    Will be converted by get_all_keys into:
    [key1, key2, key3, key31, key311, key312, key32]

    This list provides us with all the parameters used in the environment
    file, without the values, in the format of a list. So we can use sets
    to find occurrences of the forbbiden paramenters.

    The variable matched_params will get all the ocurrences of forbidden
    parameters stored, so we can parse all the environment files and show
    all the parameters which should get removed from the environment files
    at once (saving the user to run the command, modify a template, run it
    again, modify another, etc...). If matched_params list is not empty,
    an exception will be raised, stopping the execution of the command and
    displaying the commands which need to be removed.

    :param log: logging object passed from the calling method
    :type log: Logging object
    :param env_files: list of the environment files passed in the command
    :type env_files: list of strings
    :param forbidden: list of the undesired parameters
    :type forbidden: list of strings

    :returns exception if some of the forbidden parameters are found in
    the environment files.
    """

    # Iterates over a nested dict and returns all the
    # keys from the dict in a list
    # example:
    #   * input: {'a': '1', 'b': ['c': '2', 'd': {'e': '3'}]}
    #   * output: ['a', 'b', 'c', 'd', 'e']
    def get_all_keys(obj, keys_list):
        if isinstance(obj, dict):
            keys_list += obj.keys()
            for value in obj.values():
                get_all_keys(value, keys_list)
        elif isinstance(obj, list):
            for value in obj:
                get_all_keys(value, keys_list)

    matched_params = []

    for file in env_files:
        if os.path.exists(file):
            with open(file, 'r') as env_file:
                contents = yaml.safe_load(env_file)
                pd = contents.get('parameter_defaults', {})
                if pd:
                    # Intersection of values and forbidden params
                    list_of_keys = []
                    get_all_keys(pd, list_of_keys)
                    found_in_pd = list(set(list_of_keys) & set(forbidden))

                    # Combine them without duplicates
                    matched_params = list(set(matched_params + found_in_pd))

    if matched_params:
        raise exceptions.BannedParameters("The following parameters should be "
                                          "removed from the environment files:"
                                          "\n{}\n"
                                          .format('\n'.join(matched_params)))
