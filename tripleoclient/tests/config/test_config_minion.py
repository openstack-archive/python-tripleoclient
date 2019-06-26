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

from tripleoclient.config.minion import MinionConfig
from tripleoclient.tests import base


class TestMinionConfig(base.TestCase):
    def setUp(self):
        super(TestMinionConfig, self).setUp()
        # Get the class object to test
        self.config = MinionConfig()

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
                    'minion_debug',
                    'minion_enable_selinux',
                    'minion_enable_validations',
                    'minion_hostname',
                    'minion_local_interface',
                    'minion_local_ip',
                    'minion_local_mtu',
                    'minion_log_file',
                    'minion_nameservers',
                    'minion_ntp_servers',
                    'minion_password_file',
                    'minion_service_certificate',
                    'minion_timezone',
                    'minion_undercloud_output_file',
                    'net_config_override',
                    'networks_file',
                    'output_dir',
                    'roles_file',
                    'templates']
        self.assertEqual(expected, [x.name for x in ret])

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
                    'enable_heat_engine',
                    'enable_ironic_conductor',
                    'heat_container_image',
                    'heat_native',
                    'hieradata_override',
                    'minion_debug',
                    'minion_enable_selinux',
                    'minion_enable_validations',
                    'minion_hostname',
                    'minion_local_interface',
                    'minion_local_ip',
                    'minion_local_mtu',
                    'minion_log_file',
                    'minion_nameservers',
                    'minion_ntp_servers',
                    'minion_password_file',
                    'minion_service_certificate',
                    'minion_timezone',
                    'minion_undercloud_output_file',
                    'net_config_override',
                    'networks_file',
                    'output_dir',
                    'roles_file',
                    'templates']
        self.assertEqual(expected, [x.name for x in ret])

    def test_get_minion_service_opts(self):
        ret = self.config.get_minion_service_opts()
        expected = {'enable_heat_engine': True,
                    'enable_ironic_conductor': False}
        self.assertEqual(sorted(expected.keys()), [x.name for x in ret])
        for x in ret:
            self.assertEqual(expected[x.name], x.default, "%s config not %s" %
                             (x.name, expected[x.name]))
