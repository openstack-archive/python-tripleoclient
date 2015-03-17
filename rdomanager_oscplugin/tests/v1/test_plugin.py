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

import sys

from rdomanager_oscplugin.tests import base
from rdomanager_oscplugin.tests import fakes
from rdomanager_oscplugin.v1 import plugin

# Load the plugin init module for the plugin list and show commands
import rdomanager_oscplugin.plugin
plugin_name = 'rdomanager_oscplugin'
plugin_client = 'rdomanager_oscplugin.plugin'


class FakePluginV1Client(object):
    def __init__(self, **kwargs):
        #self.servers = mock.Mock()
        #self.servers.resource_class = fakes.FakeResource(None, {})
        self.auth_token = kwargs['token']
        self.management_url = kwargs['endpoint']


class TestPluginV1(base.TestCommand):
    def setUp(self):
        super(TestPluginV1, self).setUp()

        self.app.client_manager.rdomanager_oscplugin = FakePluginV1Client(
            endpoint=fakes.AUTH_URL,
            token=fakes.AUTH_TOKEN,
        )

        # Get a shortcut to the Service Catalog Mock
        #self.catalog_mock = self.app.client_manager.identity.service_catalog
        #self.catalog_mock.reset_mock()
