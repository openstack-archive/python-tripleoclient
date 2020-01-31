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

import os
import pprint
import time


from heatclient.common import event_utils
from openstackclient import shell
from tripleo_common.actions import config

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils
from tripleoclient.workflows import base

_WORKFLOW_TIMEOUT = 120 * 60  # 2h


def update(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    plan_name = workflow_input['container']

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.package_update.v1.package_update_plan',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              _WORKFLOW_TIMEOUT):
            status = payload.get('status', 'RUNNING')
            message = payload.get('message')
            if message and status == "RUNNING":
                print(message)

        if payload['status'] == "FAILED":
            raise RuntimeError('Upgrade failed with: {}'
                               ''.format(payload['message']))

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


def get_config(clients, container):
    """Get cloud config.

    :param clients: Application client object.
    :type clients: Object

    :param container: Container name to pull from.
    :type container: String.
    """

    context = clients.tripleoclient.create_mistral_context()
    config_action = config.GetOvercloudConfig(container=container)
    config_action.run(context=context)


def get_key(stack):
    """Returns the private key from the local file system.

    Searches for and returns the stack private key. If the key is inaccessible
    for any reason, the process will fall back to using the users key. If no
    key is found, this method will return None.

    :params stack: name of the stack to use
    :type stack: String

    :returns: String || None
    """

    stack_dir = os.path.join(constants.DEFAULT_WORK_DIR, stack)
    stack_key_file = os.path.join(stack_dir, 'ssh_private_key')
    user_dir = os.path.join(os.path.expanduser("~"), '.ssh')
    user_key_file = os.path.join(user_dir, 'id_rsa_tripleo')
    for key_file in [stack_key_file, user_key_file]:
        try:
            if os.path.exists(key_file):
                with open(key_file):
                    return key_file
        except IOError:
            pass
    else:
        return


def update_ansible(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.package_update.v1.update_nodes',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            print(payload['message'])

    if payload['status'] == 'SUCCESS':
        print("Success")
    else:
        raise RuntimeError('Update failed with: {}'.format(payload['message']))


def run_on_nodes(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.deployment.v1.deploy_on_servers',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              _WORKFLOW_TIMEOUT):
            assert payload['status'] == "SUCCESS", pprint.pformat(payload)

    if payload['status'] == "SUCCESS":
        print('Success')
    else:
        raise RuntimeError('run on nodes failed: {}'.format(payload))
