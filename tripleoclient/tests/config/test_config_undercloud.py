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

from tripleoclient.config.undercloud import UndercloudConfig
from tripleoclient.tests import base


class TestUndercloudConfig(base.TestCase):
    def setUp(self):
        super(TestUndercloudConfig, self).setUp()
        # Get the class object to test
        self.config = UndercloudConfig()

    def test_get_base_opts(self):
        ret = self.config.get_base_opts()
        expected = ['additional_architectures',
                    'certificate_generation_ca',
                    'clean_nodes',
                    'cleanup',
                    'container_images_file',
                    'custom_env_files',
                    'deployment_user',
                    'discovery_default_driver',
                    'docker_insecure_registries',
                    'docker_registry_mirror',
                    'enable_node_discovery',
                    'enable_routed_networks',
                    'enable_swift_encryption',
                    'enabled_hardware_types',
                    'generate_service_certificate',
                    'heat_container_image',
                    'heat_native',
                    'hieradata_override',
                    'inspection_extras',
                    'inspection_interface',
                    'inspection_runbench',
                    'ipa_otp',
                    'ipxe_enabled',
                    'local_interface',
                    'local_ip',
                    'local_mtu',
                    'local_subnet',
                    'net_config_override',
                    'output_dir',
                    'overcloud_domain_name',
                    'roles_file',
                    'scheduler_max_attempts',
                    'service_principal',
                    'subnets',
                    'templates',
                    'undercloud_admin_host',
                    'undercloud_debug',
                    'undercloud_enable_selinux',
                    'undercloud_hostname',
                    'undercloud_log_file',
                    'undercloud_nameservers',
                    'undercloud_ntp_servers',
                    'undercloud_public_host',
                    'undercloud_service_certificate',
                    'undercloud_update_packages',
                    'upgrade_cleanup']
        self.assertEqual(expected, [x.name for x in ret])

    def test_get_opts(self):
        ret = self.config.get_opts()
        expected = ['additional_architectures',
                    'certificate_generation_ca',
                    'clean_nodes',
                    'cleanup',
                    'container_images_file',
                    'custom_env_files',
                    'deployment_user',
                    'discovery_default_driver',
                    'docker_insecure_registries',
                    'docker_registry_mirror',
                    'enable_cinder',
                    'enable_ironic',
                    'enable_ironic_inspector',
                    'enable_mistral',
                    'enable_node_discovery',
                    'enable_novajoin',
                    'enable_routed_networks',
                    'enable_swift_encryption',
                    'enable_telemetry',
                    'enable_tempest',
                    'enable_ui',
                    'enable_validations',
                    'enable_zaqar',
                    'enabled_hardware_types',
                    'generate_service_certificate',
                    'heat_container_image',
                    'heat_native',
                    'hieradata_override',
                    'inspection_extras',
                    'inspection_interface',
                    'inspection_runbench',
                    'ipa_otp',
                    'ipxe_enabled',
                    'local_interface',
                    'local_ip',
                    'local_mtu',
                    'local_subnet',
                    'net_config_override',
                    'output_dir',
                    'overcloud_domain_name',
                    'roles_file',
                    'scheduler_max_attempts',
                    'service_principal',
                    'subnets',
                    'templates',
                    'undercloud_admin_host',
                    'undercloud_debug',
                    'undercloud_enable_selinux',
                    'undercloud_hostname',
                    'undercloud_log_file',
                    'undercloud_nameservers',
                    'undercloud_ntp_servers',
                    'undercloud_public_host',
                    'undercloud_service_certificate',
                    'undercloud_update_packages',
                    'upgrade_cleanup']
        self.assertEqual(expected, [x.name for x in ret])

    def test_get_subnet_opts(self):
        ret = self.config.get_subnet_opts()
        expected = ['cidr',
                    'dhcp_end',
                    'dhcp_start',
                    'gateway',
                    'inspection_iprange',
                    'masquerade']
        self.assertEqual(expected, [x.name for x in ret])

    def test_get_undercloud_service_opts(self):
        ret = self.config.get_undercloud_service_opts()
        expected = {'enable_cinder': False,
                    'enable_ironic': True,
                    'enable_ironic_inspector': True,
                    'enable_mistral': True,
                    'enable_novajoin': False,
                    'enable_telemetry': False,
                    'enable_tempest': True,
                    'enable_ui': True,
                    'enable_validations': True,
                    'enable_zaqar': True}
        self.assertEqual(sorted(expected.keys()), [x.name for x in ret])
        for x in ret:
            self.assertEqual(expected[x.name], x.default, "%s config not %s" %
                             (x.name, expected[x.name]))
