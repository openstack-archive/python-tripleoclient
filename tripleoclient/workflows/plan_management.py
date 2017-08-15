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
import tempfile
import uuid
import yaml

from swiftclient import exceptions as swift_exc
from tripleo_common.utils import swift as swiftutils
from tripleo_common.utils import tarball

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient.workflows import base

LOG = logging.getLogger(__name__)
# Plan management workflows should generally be quick. However, the creation
# of the default plan in instack has demonstrated that sometimes it can take
# several minutes. This timeout value of 6 minutes is the same as the timeout
# used in Instack.
_WORKFLOW_TIMEOUT = 360  # 6 * 60 seconds


def _upload_templates(swift_client, container_name, tht_root, roles_file=None,
                      plan_env_file=None, networks_file=None):
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

    # Allow optional override of the network_data.yaml file
    if networks_file:
        with open(networks_file) as rf:
            swift_client.put_object(container_name,
                                    constants.OVERCLOUD_NETWORKS_FILE,
                                    rf)

    # Optional override of the plan-environment.yaml file
    if plan_env_file:
        # TODO(jpalanis): Instead of overriding default file,
        # merging the user override plan-environment with default
        # plan-environment file will avoid explict merging issues.
        with open(plan_env_file) as pf:
            swift_client.put_object(container_name,
                                    constants.PLAN_ENVIRONMENT,
                                    pf)


def create_default_plan(clients, **workflow_input):

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']

    with tripleoclients.messaging_websocket(queue_name) as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.plan_management.v1.create_default_deployment_plan',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              _WORKFLOW_TIMEOUT):
            if 'message' in payload:
                print(payload['message'])

    if payload['status'] != 'SUCCESS':
        raise exceptions.WorkflowServiceError(
            'Exception creating plan: {}'.format(payload['message']))


def _create_update_deployment_plan(clients, workflow, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']

    with tripleoclients.messaging_websocket(queue_name) as ws:
        execution = base.start_workflow(
            workflow_client, workflow,
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              _WORKFLOW_TIMEOUT):
            if 'message' in payload:
                print(payload['message'])

    return payload


def create_deployment_plan(clients, **workflow_input):
    payload = _create_update_deployment_plan(
        clients, 'tripleo.plan_management.v1.create_deployment_plan',
        **workflow_input)

    if payload['status'] != 'SUCCESS':
        raise exceptions.WorkflowServiceError(
            'Exception creating plan: {}'.format(payload['message']))


def delete_deployment_plan(workflow_client, **input_):
    try:
        results = base.call_action(workflow_client,
                                   'tripleo.plan.delete',
                                   **input_)
        if results is not None:
            print(results)
    except Exception as err:
        raise exceptions.WorkflowServiceError(
            'Exception deleting plan: {}'.format(err))


def update_deployment_plan(clients, **workflow_input):
    payload = _create_update_deployment_plan(
        clients, 'tripleo.plan_management.v1.update_deployment_plan',
        **workflow_input)

    if payload['status'] != 'SUCCESS':
        raise exceptions.WorkflowServiceError(
            'Exception updating plan: {}'.format(payload['message']))


def list_deployment_plans(workflow_client, **input_):
    return base.call_action(workflow_client, 'tripleo.plan.list', **input_)


def create_container(workflow_client, **input_):
    return base.call_action(workflow_client, 'tripleo.plan.create_container',
                            **input_)


def create_plan_from_templates(clients, name, tht_root, roles_file=None,
                               generate_passwords=True, plan_env_file=None,
                               networks_file=None):
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
    _upload_templates(swift_client, name, tht_root, roles_file, plan_env_file,
                      networks_file)

    try:
        create_deployment_plan(clients, container=name,
                               queue_name=str(uuid.uuid4()),
                               generate_passwords=generate_passwords)
    except exceptions.WorkflowServiceError:
        swiftutils.delete_container(swift_client, name)
        raise


def update_plan_from_templates(clients, name, tht_root, roles_file=None,
                               generate_passwords=True, plan_env_file=None,
                               networks_file=None):
    swift_client = clients.tripleoclient.object_store

    # If the plan environment was migrated to Swift, save the generated
    # 'passwords' if they exist as they can't be recreated from the
    # templates content.
    passwords = []
    try:
        env = yaml.safe_load(swift_client.get_object(
            name, constants.PLAN_ENVIRONMENT)[1])
        passwords = env.get('passwords', [])
    except swift_exc.ClientException:
        pass

    # TODO(dmatthews): Removing the existing plan files should probably be
    #                  a Mistral action.
    print("Removing the current plan files")
    swiftutils.empty_container(swift_client, name)

    # Until we have a well defined plan update workflow in
    # tripleo-common we need to manually reset the environments and
    # parameter_defaults here. This is to ensure that no environments
    # are in the plan environment but not actually in swift.
    # See bug: https://bugs.launchpad.net/tripleo/+bug/1623431
    #
    # Currently this is being done incidentally because we overwrite
    # the existing plan-environment.yaml with the skeleton one in THT
    # when updating the templates. Once LP#1623431 is resolved we may
    # need to special-case plan-environment.yaml to avoid this.

    print("Uploading new plan files")
    _upload_templates(swift_client, name, tht_root, roles_file, plan_env_file,
                      networks_file)
    _update_passwords(swift_client, name, passwords)
    update_deployment_plan(clients, container=name,
                           queue_name=str(uuid.uuid4()),
                           generate_passwords=generate_passwords,
                           source_url=None)


def _update_passwords(swift_client, name, passwords):
    # Update the plan environment with the generated passwords. This
    # will be solved more elegantly once passwords are saved in a
    # separate environment (https://review.openstack.org/#/c/467909/)
    if passwords:
        try:
            env = yaml.safe_load(swift_client.get_object(
                name, constants.PLAN_ENVIRONMENT)[1])
            env['passwords'] = passwords
            swift_client.put_object(name,
                                    constants.PLAN_ENVIRONMENT,
                                    yaml.safe_dump(env,
                                                   default_flow_style=False))
        except swift_exc.ClientException:
            # The plan likely has not been migrated to using Swift yet.
            LOG.debug("Could not find plan environment %s in %s",
                      constants.PLAN_ENVIRONMENT, name)


def export_deployment_plan(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']

    execution = base.start_workflow(
        workflow_client,
        'tripleo.plan_management.v1.export_deployment_plan',
        workflow_input=workflow_input
    )

    with tripleoclients.messaging_websocket(queue_name) as ws:
        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              _WORKFLOW_TIMEOUT):
            if 'message' in payload:
                print(payload['message'])

    if payload['status'] == 'SUCCESS':
        return payload['tempurl']
    else:
        raise exceptions.WorkflowServiceError(
            'Exception exporting plan: {}'.format(payload['message']))
