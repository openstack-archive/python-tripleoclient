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
import tempfile
import uuid

from tripleo_common.utils import tarball

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient.workflows import base


def _upload_templates(swift_client, container_name, tht_root, roles_file=None):
    """tarball up a given directory and upload it to Swift to be extracted"""

    with tempfile.NamedTemporaryFile() as tmp_tarball:
        tarball.create_tarball(tht_root, tmp_tarball.name)
        tarball.tarball_extract_to_swift_container(
            swift_client, tmp_tarball.name, container_name)

    # Allow optional override of the roles_data.yaml file
    if roles_file:
        with open(roles_file) as rf:
            swift_client.put_object(container_name,
                                    constants.OVERCLOUD_ROLES_FILE,
                                    rf)


def create_default_plan(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']

    execution = base.start_workflow(
        workflow_client,
        'tripleo.plan_management.v1.create_default_deployment_plan',
        workflow_input=workflow_input
    )

    with tripleoclients.messaging_websocket(queue_name) as ws:
        payload = ws.wait_for_message(execution.id)

    if payload['status'] == 'SUCCESS':
        print ("Default plan created")
    else:
        raise exceptions.WorkflowServiceError(
            'Exception creating plan: {}'.format(payload['message']))


def _create_update_deployment_plan(clients, workflow, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']

    execution = base.start_workflow(
        workflow_client, workflow,
        workflow_input=workflow_input
    )

    with tripleoclients.messaging_websocket(queue_name) as ws:
        return ws.wait_for_message(execution.id)


def create_deployment_plan(clients, **workflow_input):
    payload = _create_update_deployment_plan(
        clients, 'tripleo.plan_management.v1.create_deployment_plan',
        **workflow_input)

    if payload['status'] == 'SUCCESS':
        print ("Plan created")
    else:
        raise exceptions.WorkflowServiceError(
            'Exception creating plan: {}'.format(payload['message']))


def update_deployment_plan(clients, **workflow_input):
    payload = _create_update_deployment_plan(
        clients, 'tripleo.plan_management.v1.update_deployment_plan',
        **workflow_input)

    if payload['status'] == 'SUCCESS':
        print ("Plan updated")
    else:
        raise exceptions.WorkflowServiceError(
            'Exception updating plan: {}'.format(payload['message']))


def list_deployment_plans(workflow_client, **input_):
    return base.call_action(workflow_client, 'tripleo.plan.list', **input_)


def create_container(workflow_client, **input_):
    return base.call_action(workflow_client, 'tripleo.plan.create_container',
                            **input_)


def create_plan_from_templates(clients, name, tht_root, roles_file=None):
    workflow_client = clients.workflow_engine
    swift_client = clients.tripleoclient.object_store

    print("Creating Swift container to store the plan")
    result = create_container(workflow_client, container=name)
    if result:
        # create_container returns 'None' on success and a string with
        # the error message when failing.
        raise exceptions.PlanCreationError(
            "Unable to create plan. {}".format(result))

    print("Creating plan from template files in: {}".format(tht_root))
    _upload_templates(swift_client, name, tht_root, roles_file)
    create_deployment_plan(clients, container=name,
                           queue_name=str(uuid.uuid4()))


def update_plan_from_templates(clients, name, tht_root, roles_file=None):
    swift_client = clients.tripleoclient.object_store

    # TODO(dmatthews): Removing the existing plan files should probably be
    #                  a Mistral action.
    print("Removing the current plan files")
    headers, objects = swift_client.get_container(name)
    for object_ in objects:
        swift_client.delete_object(name, object_['name'])

    # Until we have a well defined plan update workflow in tripleo-common we
    # need to manually reset the environments here. This is to ensure that
    # no environments are in the mistral environment but not in swift.
    # See bug: https://bugs.launchpad.net/tripleo/+bug/1623431
    mistral = clients.workflow_engine
    mistral_env = mistral.environments.get(name)
    mistral_env.variables['environments'] = []
    mistral_env.variables['parameter_defaults'] = {}
    mistral.environments.update(
        name=name,
        variables=mistral_env.variables
    )

    print("Uploading new plan files")
    _upload_templates(swift_client, name, tht_root, roles_file)
    update_deployment_plan(clients, container=name,
                           queue_name=str(uuid.uuid4()))
