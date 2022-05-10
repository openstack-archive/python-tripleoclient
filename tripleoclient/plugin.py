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

import logging

from osc_lib import utils

LOG = logging.getLogger(__name__)

DEFAULT_TRIPLEOCLIENT_API_VERSION = '2'

# Required by the OSC plugin interface
API_NAME = 'tripleoclient'
API_VERSION_OPTION = 'os_tripleoclient_api_version'
API_VERSIONS = {
    '2': 'tripleoclient.plugin'
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


class ClientWrapper(object):

    def __init__(self, instance):
        self._instance = instance
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
