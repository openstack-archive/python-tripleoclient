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

import time

from heatclient.common import event_utils
from tripleo_common.actions import container_images
from tripleo_common.actions import package_update

from tripleoclient import exceptions
from tripleoclient import utils


_WORKFLOW_TIMEOUT = 120 * 60  # 2h


def update(clients, container):
    """Update the heat stack outputs for purposes of update/upgrade.

    This workflow assumes that previously the
    plan_management.update_deployment_plan workflow has already been
    run to process the templates and environments (the same way as
    'deploy' command processes them).

    :param clients: Application client object.
    :type clients: Object

    :param container: Container name to pull from.
    :type container: String.
    """

    def _check_response(response):
        """This test checks if a response is mistral based.

        Some responses are constructed using the mistral Result class, but
        because the returns from methods within tripleo-common are not
        type safe, this static method will check for success using the
        mistral attribute, but if it does not exist the raw response will
        be returned.

        :param response: Object
        :Type response: Object

        :returns: Boolean || Object
        """
        try:
            return response.is_success()
        except AttributeError:
            return response

    context = clients.tripleoclient.create_mistral_context()
    container_action = container_images.PrepareContainerImageParameters(
        container=container
    )
    success = _check_response(container_action.run(context=context))
    if success is False:
        raise RuntimeError(
            'Prepare container image parameters failed: {}'.format(
                success.to_dict()
            )
        )

    update_action = package_update.UpdateStackAction(
        timeout=240,
        container=container
    )
    success = _check_response(update_action.run(context=context))
    if success is False:
        raise RuntimeError(
            'Upgrade failed: {}'.format(
                success.to_dict()
            )
        )

    events = event_utils.get_events(
        clients.orchestration,
        stack_id=container,
        event_args={
            'sort_dir': 'desc',
            'limit': 1
        }
    )
    marker = events[0].id if events else None
    time.sleep(10)
    create_result = utils.wait_for_stack_ready(
        clients.orchestration,
        container,
        marker,
        'UPDATE',
        1
    )
    if not create_result:
        raise exceptions.DeploymentError(
            'Heat Stack update failed, run the following command'
            ' `openstack --os-cloud undercloud stack failures list {}`'
            ' to investigate these failures further.'.format(container)
        )
