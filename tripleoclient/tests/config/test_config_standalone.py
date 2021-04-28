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
                    'container_cli',
                    'container_healthcheck_disabled',
                    'container_images_file',
                    'container_insecure_registries',
                    'container_registry_mirror',
                    'custom_env_files',
                    'deployment_user',
                    'heat_container_image',
                    'heat_native',
                    'hieradata_override',
                    'net_config_override',
                    'networks_file',
                    'output_dir',
                    'roles_file',
                    'templates']
        self.assertEqual(expected, [x.name for x in ret])

    def test_get_service_opts(self):
        ret = self.config.get_enable_service_opts()
        expected = ['enable_cinder',
                    'enable_frr',
                    'enable_heat',
                    'enable_ironic',
                    'enable_ironic_inspector',
                    'enable_mistral',
                    'enable_neutron',
                    'enable_nova',
                    'enable_novajoin',
                    'enable_swift',
                    'enable_telemetry',
                    'enable_validations',
                    'enable_zaqar']
        self.assertEqual(expected, [x.name for x in ret])
        for x in ret:
            self.assertEqual(x.default, False, "%s config not False" % x.name)

    def test_get_service_opts_enabled(self):
        ret = self.config.get_enable_service_opts(cinder=True,
                                                  frr=True,
                                                  heat=True,
                                                  ironic=True,
                                                  ironic_inspector=True,
                                                  mistral=True,
                                                  neutron=True,
                                                  nova=True,
                                                  novajoin=True,
                                                  swift=True,
                                                  telemetry=True,
                                                  validations=True,
                                                  zaqar=True)
        expected = ['enable_cinder',
                    'enable_frr',
                    'enable_heat',
                    'enable_ironic',
                    'enable_ironic_inspector',
                    'enable_mistral',
                    'enable_neutron',
                    'enable_nova',
                    'enable_novajoin',
                    'enable_swift',
                    'enable_telemetry',
                    'enable_validations',
                    'enable_zaqar']
        self.assertEqual(expected, [x.name for x in ret])
        for x in ret:
            self.assertEqual(x.default, True, "%s config not True" % x.name)

    def test_get_opts(self):
        ret = self.config.get_opts()
        expected = ['cleanup',
                    'container_cli',
                    'container_healthcheck_disabled',
                    'container_images_file',
                    'container_insecure_registries',
                    'container_registry_mirror',
                    'custom_env_files',
                    'deployment_user',
                    'enable_cinder',
                    'enable_frr',
                    'enable_heat',
                    'enable_ironic',
                    'enable_ironic_inspector',
                    'enable_mistral',
                    'enable_neutron',
                    'enable_nova',
                    'enable_novajoin',
                    'enable_swift',
                    'enable_telemetry',
                    'enable_validations',
                    'enable_zaqar',
                    'heat_container_image',
                    'heat_native',
                    'hieradata_override',
                    'net_config_override',
                    'networks_file',
                    'output_dir',
                    'roles_file',
                    'templates']
        self.assertEqual(expected, [x.name for x in ret])
