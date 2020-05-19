# Copyright 2016 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from __future__ import print_function

from heatclient.common import event_utils
from tripleo_common.actions import scale

from tripleoclient import utils
from tripleoclient.workflows import deployment


def scale_down(log, clients, stack, nodes, timeout=None, verbosity=0,
               connection_timeout=None):
    """Unprovision and deletes overcloud nodes from a heat stack.

    :param log: Logging object
    :type log: Object

    :param clients: Application client object.
    :type clients: Object

    :param stack: Heat Stack object
    :type stack: Object

    :param nodes: List of nodes to delete. If the node UUID is used the
                  UUID will be used to lookup the node name before being
                  passed through to the cleanup playbook.
    :type nodes: List

    :param timeout: Timeout to use when deleting nodes. If timeout is None
                    it will be set to 240 minutes.
    :type timeout: Integer

    :param verbosity: Verbosity level
    :type verbosity: Integer

    :param connection_timeout: Ansible connection timeout in seconds.
    :type connection_timeout: Integer
    """

    if not timeout:
        timeout = 240

    limit_list = list()
    for node in nodes:
        try:
            _node = clients.compute.servers.get(node)
            limit_list.append(_node.name)
        except Exception:
            limit_list.append(node)

    if limit_list:
        limit_list = ':'.join(limit_list)
    else:
        limit_list = None

    deployment.config_download(
        log=log,
        clients=clients,
        stack=stack,
        timeout=connection_timeout,
        ansible_playbook_name='scale_playbook.yaml',
        limit_hosts=limit_list,
        verbosity=verbosity,
        deployment_timeout=timeout
    )
    events = event_utils.get_events(clients.orchestration,
                                    stack_id=stack.stack_name,
                                    event_args={'sort_dir': 'desc',
                                                'limit': 1})
    marker = events[0].id if events else None

    print('Running scale down')
    context = clients.tripleoclient.create_mistral_context()
    scale_down_action = scale.ScaleDownAction(nodes=nodes, timeout=timeout,
                                              container=stack.stack_name)
    scale_down_action.run(context=context)
    utils.wait_for_stack_ready(
        orchestration_client=clients.orchestration,
        stack_name=stack.stack_name,
        action='UPDATE',
        marker=marker
    )
