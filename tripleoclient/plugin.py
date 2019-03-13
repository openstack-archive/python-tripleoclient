#   Copyright 2013 Nebula Inc.
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

"""OpenStackClient Plugin interface"""

import json
import logging
import socket
import uuid

from osc_lib import utils
from swiftclient import client as swift_client
import websocket

from tripleoclient import exceptions

LOG = logging.getLogger(__name__)

DEFAULT_TRIPLEOCLIENT_API_VERSION = '1'

# Required by the OSC plugin interface
API_NAME = 'tripleoclient'
API_VERSION_OPTION = 'os_tripleoclient_api_version'
API_VERSIONS = {
    '1': 'tripleoclient.plugin'
}


def make_client(instance):
    return ClientWrapper(instance)


# Required by the OSC plugin interface
def build_option_parser(parser):
    """Hook to add global options

    Called from openstackclient.shell.OpenStackShell.__init__()
    after the builtin parser has been initialized.  This is
    where a plugin can add global options such as an API version setting.

    :param argparse.ArgumentParser parser: The parser object that has been
        initialized by OpenStackShell.
    """
    parser.add_argument(
        '--os-tripleoclient-api-version',
        metavar='<tripleoclient-api-version>',
        default=utils.env(
            'OS_TRIPLEOCLIENT_API_VERSION',
            default=DEFAULT_TRIPLEOCLIENT_API_VERSION),
        help='TripleO Client API version, default=' +
             DEFAULT_TRIPLEOCLIENT_API_VERSION +
             ' (Env: OS_TRIPLEOCLIENT_API_VERSION)')
    return parser


class WebsocketClient(object):

    def __init__(self, instance, queue_name="tripleo", cacert=None):
        self._project_id = None
        self._ws = None
        self._websocket_client_id = None
        self._queue_name = queue_name

        endpoint = instance.get_endpoint_for_service_type(
            'messaging-websocket')
        token = instance.auth.get_token(instance.session)

        self._project_id = instance.auth_ref.project_id

        self._websocket_client_id = str(uuid.uuid4())

        LOG.debug('Instantiating messaging websocket client: %s', endpoint)
        try:
            if 'wss:' in endpoint and cacert:
                OS_CACERT = {"ca_certs": cacert}
                self._ws = websocket.create_connection(endpoint,
                                                       sslopt=OS_CACERT)
            else:
                self._ws = websocket.create_connection(endpoint)
        except socket.error:
            LOG.error("Could not establish a connection to the Zaqar "
                      "websocket. The command was sent but the answer "
                      "could not be read.")
            raise

        self.send('authenticate', extra_headers={'X-Auth-Token': token})

        # create and subscribe to a queue
        # NOTE: if the queue exists it will 204
        self.send('queue_create', {'queue_name': queue_name})
        self.send('subscription_create', {
            'queue_name': queue_name,
            'ttl': 10000
        })

    def cleanup(self):
        self._ws.close()

    def send(self, action, body=None, extra_headers=None):

        headers = {
            'Client-ID': self._websocket_client_id,
            'X-Project-ID': self._project_id
        }

        if extra_headers is not None:
            headers.update(extra_headers)

        msg = {'action': action, 'headers': headers}
        if body:
            msg['body'] = body
        self._ws.send(json.dumps(msg))
        data = self.recv()
        if data['headers']['status'] not in (200, 201, 204):
            raise RuntimeError(data)
        return data

    def recv(self):
        return json.loads(self._ws.recv())

    def wait_for_messages(self, timeout=None):
        """Wait for messages on a Zaqar queue

        A timeout can be provided in seconds, if no timeout is provided it
        will block forever until a message is received. If no message is
        received (for example, Zaqar is down) then it will block until manually
        killed.

        If no timeout is provided this method will never stop waiting for new
        messages. It is the responsibility of the consumer to stop consuming
        messages.
        """

        if timeout is None:
            LOG.warning("Waiting for messages on queue '{}' with no timeout."
                        .format(self._queue_name))

        try:
            self._ws.settimeout(timeout)
            while True:
                message = self.recv()
                LOG.debug(message)
                yield message['body']['payload']

        except websocket.WebSocketTimeoutException:
            raise exceptions.WebSocketTimeout()
        except websocket.WebSocketConnectionClosedException:
            raise exceptions.WebSocketConnectionClosed()

    def __enter__(self):
        """Return self to allow usage as a context manager"""
        return self

    def __exit__(self, *exc):
        """Call cleanup when exiting the context manager"""
        try:
            self.cleanup()
        except websocket.WebSocketConnectionClosedException:
            pass


class ClientWrapper(object):

    def __init__(self, instance):
        self._instance = instance
        self._object_store = None
        self._local_orchestration = None

    def local_orchestration(self, api_port):
        """Returns an local_orchestration service client"""

        if self._local_orchestration is not None:
            return self._local_orchestration

        API_VERSIONS = {
            '1': 'heatclient.v1.client.Client',
        }

        heat_client = utils.get_client_class(
            API_NAME,
            '1',
            API_VERSIONS)
        LOG.debug('Instantiating local_orchestration client: %s', heat_client)

        client = heat_client(
            endpoint='http://127.0.0.1:%s/v1/admin' % api_port,
            username='admin',
            password='fake',
            region_name='regionOne',
            token='fake',
        )

        self._local_orchestration = client
        return self._local_orchestration

    def messaging_websocket(self, queue_name='tripleo'):
        """Returns a websocket for the messaging service"""
        return WebsocketClient(self._instance, queue_name,
                               cacert=self._instance.cacert)

    @property
    def object_store(self):
        """Returns an object_store service client

        The Swift/Object client returned by python-openstack client isn't an
        instance of python-swiftclient, and had far less functionality.
        """

        if self._object_store is not None:
            return self._object_store

        endpoint = self._instance.get_endpoint_for_service_type(
            "object-store",
            region_name=self._instance._region_name,
        )

        token = self._instance.auth.get_token(self._instance.session)

        kwargs = {
            'preauthurl': endpoint,
            'preauthtoken': token
        }

        self._object_store = swift_client.Connection(**kwargs)
        return self._object_store
