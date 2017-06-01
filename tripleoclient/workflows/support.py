#   Copyright 2017 Red Hat, Inc.
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

import os
import uuid

from osc_lib.i18n import _

from tripleoclient.exceptions import ContainerDeleteFailed
from tripleoclient.exceptions import DownloadError
from tripleoclient.exceptions import LogFetchError
from tripleoclient.workflows import base


def check_local_space(path, object_list):
    required_space = sum([x['bytes'] for x in object_list])
    stats = os.statvfs(path)
    free_space = stats.f_bavail * stats.f_frsize
    return free_space >= required_space


def download_files(clients, container_name, destination):
    """Downloads log files from a container action

    :param clients: openstack clients
    :param container: name of the container to put the logs
    :param destination: folder to download files to
     """
    oc = clients.object_store
    object_list = oc.object_list(container=container_name, all_data=True)

    # handle relative destination path
    if not os.path.dirname(destination):
        destination = os.path.join(os.sep, os.getcwd(), destination)

    if not os.path.exists(destination):
        print('Creating destination path: {}'.format(destination))
        os.makedirs(destination)

    if not check_local_space(destination, object_list):
        raise DownloadError(_('Not enough local space to download files.'))

    for data in object_list:
        print('Downloading file: {}'.format(data['name']))
        file_path = os.path.join(os.sep, destination, data['name'])
        oc.object_save(container=container_name,
                       object=data['name'],
                       file=file_path)


def fetch_logs(clients, container, server_name, timeout=None,
               concurrency=None):
    """Executes fetch log action

    :param clients: openstack clients
    :param container: name of the container to put the logs
    :param server_name: server name to restrict where logs are pulled from
    :param timeout: timeout for the log fetch operation
    :param concurrency: max number of concurrent log collection tasks
    """

    workflow_input = {
        "container": container,
        "server_name": server_name,
        "queue_name": str(uuid.uuid4()),
    }

    if timeout is not None:
        workflow_input['timeout'] = timeout
    if concurrency is not None:
        workflow_input['concurrency'] = concurrency

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']

    execution = base.start_workflow(
        workflow_client,
        'tripleo.support.v1.fetch_logs',
        workflow_input=workflow_input
    )

    websocket = tripleoclients.messaging_websocket(queue_name)
    messages = base.wait_for_messages(workflow_client,
                                      websocket,
                                      execution,
                                      timeout)

    for message in messages:
        if message['status'] != 'SUCCESS':
            raise LogFetchError(message['message'])
        if message['message']:
            print('{}'.format(message['message']))


def delete_container(clients, container, timeout=None, concurrency=None):
    """Deletes container from swift

    :param clients: openstack clients
    :param container: name of the container where the logs were stored
    :param timeout: timeout for the delete operations
    :param concurrency: max number of object deletion tasks to run at one time
    """
    workflow_input = {
        "container": container,
        "queue_name": str(uuid.uuid4()),
    }

    if timeout is not None:
        workflow_input['timeout'] = timeout
    if concurrency is not None:
        workflow_input['concurrency'] = concurrency

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    queue_name = workflow_input['queue_name']

    execution = base.start_workflow(
        workflow_client,
        'tripleo.support.v1.delete_container',
        workflow_input=workflow_input
    )

    websocket = tripleoclients.messaging_websocket(queue_name)
    messages = base.wait_for_messages(workflow_client,
                                      websocket,
                                      execution,
                                      timeout)

    for message in messages:
        if message['status'] != 'SUCCESS':
            raise ContainerDeleteFailed(message['message'])
        if message['message']:
            print('{}'.format(message['message']))
