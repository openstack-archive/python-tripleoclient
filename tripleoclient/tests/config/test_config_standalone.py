#   Copyright 2018 Red Hat, Inc.
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

from tripleoclient.config.standalone import StandaloneConfig
from tripleoclient.tests import base


class TestStandaloneConfig(base.TestCase):
    def setUp(self):
        super(TestStandaloneConfig, self).setUp()
        # Get the class object to test
        self.config = StandaloneConfig()

    def test_get_base_opts(self):
        ret = self.config.get_base_opts()
        expected = ['cleanup',
                    'container_images_file',
                    'custom_env_files',
                    'deployment_user',
                    'docker_insecure_registries',
                    'docker_registry_mirror',
                    'heat_container_image',
                    'heat_native',
                    'hieradata_override',
                    'net_config_override',
                    'output_dir',
                    'roles_file',
                    'templates']
        self.assertEqual(expected, [x.name for x in ret])

    def test_get_service_opts(self):
        ret = self.config.get_enable_service_opts()
        expected = ['enable_cinder',
                    'enable_ironic',
                    'enable_ironic_inspector',
                    'enable_mistral',
                    'enable_novajoin',
                    'enable_telemetry',
                    'enable_tempest',
                    'enable_ui',
                    'enable_validations',
                    'enable_zaqar']
        self.assertEqual(expected, [x.name for x in ret])
        for x in ret:
            self.assertEqual(x.default, False, "%s config not False" % x.name)

    def test_get_service_opts_enabled(self):
        ret = self.config.get_enable_service_opts(cinder=True,
                                                  ironic=True,
                                                  ironic_inspector=True,
                                                  mistral=True,
                                                  novajoin=True,
                                                  telemetry=True,
                                                  tempest=True,
                                                  tripleo_ui=True,
                                                  validations=True,
                                                  zaqar=True)
        expected = ['enable_cinder',
                    'enable_ironic',
                    'enable_ironic_inspector',
                    'enable_mistral',
                    'enable_novajoin',
                    'enable_telemetry',
                    'enable_tempest',
                    'enable_ui',
                    'enable_validations',
                    'enable_zaqar']
        self.assertEqual(expected, [x.name for x in ret])
        for x in ret:
            self.assertEqual(x.default, True, "%s config not True" % x.name)

    def test_get_opts(self):
        ret = self.config.get_opts()
        expected = ['cleanup',
                    'container_images_file',
                    'custom_env_files',
                    'deployment_user',
                    'docker_insecure_registries',
                    'docker_registry_mirror',
                    'enable_cinder',
                    'enable_ironic',
                    'enable_ironic_inspector',
                    'enable_mistral',
                    'enable_novajoin',
                    'enable_telemetry',
                    'enable_tempest',
                    'enable_ui',
                    'enable_validations',
                    'enable_zaqar',
                    'heat_container_image',
                    'heat_native',
                    'hieradata_override',
                    'net_config_override',
                    'output_dir',
                    'roles_file',
                    'templates']
        self.assertEqual(expected, [x.name for x in ret])
