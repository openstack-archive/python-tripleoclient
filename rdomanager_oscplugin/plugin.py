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


LOG = logging.getLogger(__name__)

DEFAULT_RDOMANAGER_OSCPLUGIN_API_VERSION = '1'

# Required by the OSC plugin interface
API_NAME = 'rdomanager_oscplugin'
API_VERSION_OPTION = 'os_rdomanager_oscplugin_api_version'


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

    def __init__(self, instace):
        self._instace = instace
        self._baremetal = None

    def baremetal(self):

        # TODO(d0ugal): When the ironicclient has it's own OSC plugin, the
        # following client handling code should be removed in favor of the
        # upstream version.

        if self._baremetal is None:

            endpoint = self._instace.get_endpoint_for_service_type(
                "baremetal",
                region_name=self._instace._region_name,
            )

            token = self._instace.auth.get_token(self._instace.session)

            self._baremetal = ironic_client.get_client(
                1, os_auth_token=token, ironic_url=endpoint)

        return self._baremetal
