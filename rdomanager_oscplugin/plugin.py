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

from ironicclient import client as ironic_client
from openstackclient.common import utils
from tuskarclient import client as tuskar_client


LOG = logging.getLogger(__name__)

DEFAULT_RDOMANAGER_OSCPLUGIN_API_VERSION = '1'

# Required by the OSC plugin interface
API_NAME = 'rdomanager_oscplugin'
API_VERSION_OPTION = 'os_rdomanager_oscplugin_api_version'
API_VERSIONS = {
    '1': 'rdomanager_oscplugin.plugin'
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
        '--os-rdomanager-oscplugin-api-version',
        metavar='<rdomanager-oscplugin-api-version>',
        default=utils.env(
            'OS_RDOMANAGER_OSCPLUGIN_API_VERSION',
            default=DEFAULT_RDOMANAGER_OSCPLUGIN_API_VERSION),
        help='RDO Manager OSC Plugin API version, default=' +
             DEFAULT_RDOMANAGER_OSCPLUGIN_API_VERSION +
             ' (Env: OS_RDOMANAGER_OSCPLUGIN_API_VERSION)')
    return parser


class ClientWrapper(object):

    def __init__(self, instance):
        self._instance = instance
        self._baremetal = None
        self._orchestration = None
        self._management = None

    def baremetal(self):
        """Returns an baremetal service client"""

        # TODO(d0ugal): When the ironicclient has it's own OSC plugin, the
        # following client handling code should be removed in favor of the
        # upstream version.

        if self._baremetal is not None:
            return self._baremetal

        endpoint = self._instance.get_endpoint_for_service_type(
            "baremetal",
            region_name=self._instance._region_name,
        )

        token = self._instance.auth.get_token(self._instance.session)

        self._baremetal = ironic_client.get_client(
            1, os_auth_token=token, ironic_url=endpoint)

        return self._baremetal

    def orchestration(self):
        """Returns an orchestration service client"""

        # TODO(d0ugal): This code is based on the upstream WIP implementation
        # and should be removed when it lands:
        # https://review.openstack.org/#/c/111786

        if self._orchestration is not None:
            return self._orchestration

        API_VERSIONS = {
            '1': 'heatclient.v1.client.Client',
        }

        heat_client = utils.get_client_class(
            API_NAME,
            self._instance._api_version[API_NAME],
            API_VERSIONS)
        LOG.debug('Instantiating orchestration client: %s', heat_client)

        endpoint = self._instance.get_endpoint_for_service_type(
            'orchestration')
        token = self._instance.auth.get_token(self._instance.session)

        client = heat_client(
            endpoint=endpoint,
            auth_url=self._instance._auth_url,
            token=token,
            username=self._instance._username,
            password=self._instance._password,
            region_name=self._instance._region_name,
            insecure=self._instance._insecure,
        )

        self._orchestration = client
        return self._orchestration

    def management(self):
        """Returns an management service client"""

        endpoint = self._instance.get_endpoint_for_service_type(
            "management",
            region_name=self._instance._region_name,
        )

        token = self._instance.auth.get_token(self._instance.session)

        self._management = tuskar_client.get_client(
            2, os_auth_token=token, tuskar_url=endpoint)

        return self._management
