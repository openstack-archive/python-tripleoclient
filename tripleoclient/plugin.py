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
from swiftclient import client as swift_client

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


class MistralContext(object):
    """MistralContext, a shim for calling Mistral actions directly

    The MistralContext and MistralSecurityContext combined mimic the context
    which Mistral passes to actions during a Workflow execution. It does
    not include all the data or cover all of the functionality but it does
    include everything we use in tripleo-common.

    The MistralContext should be created by the create_mistral_context method
    on the ClientWrapper class below.

    This should be refactored and removed once Mistral server has been removed.
    """
    def __init__(self, security_ctx=None):
        self.security = security_ctx

    def __getattribute__(self, name):
        deprecated = [
            "auth_cacert", "auth_token", "auth_uri", "expires_at", "insecure",
            "is_target", "is_trust_scoped", "project_id", "project_name",
            "redelivered", "region_name", "service_catalog", "trust_id",
            "user_name"
        ]
        if name in deprecated:
            return getattr(self.security, name)
        return super(MistralContext, self).__getattribute__(name)


class MistralSecurityContext(object):
    def __init__(self, auth_uri=None, auth_cacert=None, insecure=None,
                 service_catalog=None, region_name=None, is_trust_scoped=None,
                 redelivered=None, expires_at=None, trust_id=None,
                 is_target=None, project_id=None, project_name=None,
                 user_name=None, user_id=None, auth_token=None):
        self.auth_uri = auth_uri
        self.auth_cacert = auth_cacert
        self.insecure = insecure
        self.service_catalog = service_catalog
        self.region_name = region_name
        self.is_trust_scoped = is_trust_scoped
        self.redelivered = redelivered
        self.expires_at = expires_at
        self.trust_id = trust_id
        self.is_target = is_target
        self.project_id = project_id
        self.project_name = project_name
        self.user_name = user_name
        self.user_id = user_id
        self.auth_token = auth_token


class ClientWrapper(object):

    def __init__(self, instance):
        self._instance = instance
        self._object_store = None
        self._local_orchestration = None

    def create_mistral_context(self):
        """Create a Mistral context

        Create a class that mimics the Mistral context. This allows us to call
        Mistral action classes directly.

        See the docstring on MistralContext for more context.
        """
        session = self._instance.session
        security_ctx = MistralSecurityContext(
            auth_token=self._instance.auth.get_token(session),
            auth_uri=self._instance.auth.auth_url,
            project_id=self._instance.auth.get_project_id(session),
            project_name=self._instance.auth._project_name,
            service_catalog=session.auth.auth_ref._data['token'],
            trust_id=self._instance.auth_ref.trust_id,
            user_name=self._instance.auth._username,
            auth_cacert=self._instance.cacert,
            user_id=self._instance.auth._user_id
        )
        return MistralContext(security_ctx=security_ctx)

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
