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

from heatclient.common import event_utils
from tripleo_common.utils import plan
from tripleo_common.utils import stack

from tripleoclient import exceptions
from tripleoclient import utils

_STACK_TIMEOUT = 120  # 2h


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

    tripleoclients = clients.tripleoclient

    orchestration_client = clients.orchestration
    object_client = tripleoclients.object_store
    plan.update_plan_environment_with_image_parameters(
       object_client, container)

    events = event_utils.get_events(orchestration_client,
                                    stack_id=container,
                                    event_args={'sort_dir': 'desc',
                                                'limit': 1})
    marker = events[0].id if events else None

    stack.stack_update(object_client, orchestration_client,
                       _STACK_TIMEOUT, container)

    create_result = utils.wait_for_stack_ready(
        clients.orchestration,
        container,
        marker,
        'UPDATE',
    )
    if not create_result:
        raise exceptions.DeploymentError(
            'Heat Stack update failed, run the following command'
            ' `openstack --os-cloud undercloud stack failures list {}`'
            ' to investigate these failures further.'.format(container)
        )
