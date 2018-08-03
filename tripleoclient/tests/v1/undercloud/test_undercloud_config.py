#   Copyright 2017 Red Hat, Inc.
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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime
from datetime import timedelta
import mock
import os
import tempfile
import yaml

from tripleo_common.image import kolla_builder

from tripleoclient.tests import base
from tripleoclient.v1 import undercloud_config


class TestProcessDriversAndHardwareTypes(base.TestCase):
    def setUp(self):
        super(TestProcessDriversAndHardwareTypes, self).setUp()
        self.conf = mock.Mock(**{key: getattr(undercloud_config.CONF, key)
                                 for key in ('enabled_hardware_types',
                                             'enable_node_discovery',
                                             'discovery_default_driver')})

    def test_defaults(self):
        env = {}
        undercloud_config._process_drivers_and_hardware_types(self.conf, env)
        self.assertEqual({
            'IronicEnabledHardwareTypes': ['idrac', 'ilo', 'ipmi', 'redfish'],
            'IronicEnabledBootInterfaces': ['ilo-pxe', 'pxe'],
            'IronicEnabledManagementInterfaces': ['fake', 'idrac', 'ilo',
                                                  'ipmitool', 'redfish'],
            'IronicEnabledPowerInterfaces': ['fake', 'idrac', 'ilo',
                                             'ipmitool', 'redfish'],
            'IronicEnabledRaidInterfaces': ['idrac', 'no-raid'],
            'IronicEnabledVendorInterfaces': ['idrac', 'ipmitool', 'no-vendor']
        }, env)

    def test_one_hardware_type_with_discovery(self):
        env = {}
        self.conf.enabled_hardware_types = ['redfish']
        self.conf.enable_node_discovery = True

        undercloud_config._process_drivers_and_hardware_types(self.conf, env)
        self.assertEqual({
            # ipmi added because it's the default discovery driver
            'IronicEnabledHardwareTypes': ['ipmi', 'redfish'],
            'IronicEnabledBootInterfaces': ['pxe'],
            'IronicEnabledManagementInterfaces': ['fake', 'ipmitool',
                                                  'redfish'],
            'IronicEnabledPowerInterfaces': ['fake', 'ipmitool', 'redfish'],
            'IronicEnabledRaidInterfaces': ['no-raid'],
            'IronicEnabledVendorInterfaces': ['ipmitool', 'no-vendor'],
            'IronicInspectorDiscoveryDefaultDriver': 'ipmi',
            'IronicInspectorEnableNodeDiscovery': True
        }, env)

    def test_all_hardware_types(self):
        env = {}
        self.conf.enabled_hardware_types = (
            self.conf.enabled_hardware_types + ['staging-ovirt', 'snmp',
                                                'irmc', 'cisco-ucs-managed',
                                                'cisco-ucs-standalone',
                                                'xclarity']
        )

        undercloud_config._process_drivers_and_hardware_types(self.conf, env)
        self.assertEqual({
            'IronicEnabledHardwareTypes': ['cisco-ucs-managed',
                                           'cisco-ucs-standalone',
                                           'idrac', 'ilo', 'ipmi', 'irmc',
                                           'redfish', 'snmp', 'staging-ovirt',
                                           'xclarity'],
            'IronicEnabledBootInterfaces': ['ilo-pxe', 'irmc-pxe', 'pxe'],
            'IronicEnabledManagementInterfaces': ['cimc', 'fake', 'idrac',
                                                  'ilo', 'ipmitool', 'irmc',
                                                  'redfish', 'staging-ovirt',
                                                  'ucsm', 'xclarity'],
            'IronicEnabledPowerInterfaces': ['cimc', 'fake', 'idrac',
                                             'ilo', 'ipmitool', 'irmc',
                                             'redfish', 'snmp',
                                             'staging-ovirt', 'ucsm',
                                             'xclarity'],
            'IronicEnabledRaidInterfaces': ['idrac', 'no-raid'],
            'IronicEnabledVendorInterfaces': ['idrac', 'ipmitool', 'no-vendor']
        }, env)


class TestTLSSettings(base.TestCase):
    def test_public_host_with_ip_should_give_ip_endpoint_environment(self):
        expected_env_file = os.path.join(
            undercloud_config.THT_HOME,
            "environments/ssl/tls-endpoints-public-ip.yaml")

        resulting_env_file1 = undercloud_config._get_tls_endpoint_environment(
            '127.0.0.1', undercloud_config.THT_HOME)

        self.assertEqual(expected_env_file, resulting_env_file1)

        resulting_env_file2 = undercloud_config._get_tls_endpoint_environment(
            '192.168.1.1', undercloud_config.THT_HOME)

        self.assertEqual(expected_env_file, resulting_env_file2)

    def test_public_host_with_fqdn_should_give_dns_endpoint_environment(self):
        expected_env_file = os.path.join(
            undercloud_config.THT_HOME,
            "environments/ssl/tls-endpoints-public-dns.yaml")

        resulting_env_file1 = undercloud_config._get_tls_endpoint_environment(
            'controller-1', undercloud_config.THT_HOME)

        self.assertEqual(expected_env_file, resulting_env_file1)

        resulting_env_file2 = undercloud_config._get_tls_endpoint_environment(
            'controller-1.tripleodomain.com', undercloud_config.THT_HOME)

        self.assertEqual(expected_env_file, resulting_env_file2)

    def get_certificate_and_private_key(self):
        private_key = rsa.generate_private_key(public_exponent=3,
                                               key_size=1024,
                                               backend=default_backend())
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"FI"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Helsinki"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Some Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Test Certificate"),
        ])
        cert_builder = x509.CertificateBuilder(
            issuer_name=issuer, subject_name=issuer,
            public_key=private_key.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_before=datetime.utcnow(),
            not_valid_after=datetime.utcnow() + timedelta(days=10)
        )
        cert = cert_builder.sign(private_key,
                                 hashes.SHA256(),
                                 default_backend())
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
        return cert_pem, key_pem

    def test_get_dict_with_cert_and_key_from_bundled_pem(self):
        cert_pem, key_pem = self.get_certificate_and_private_key()

        with tempfile.NamedTemporaryFile() as tempbundle:
            tempbundle.write(cert_pem)
            tempbundle.write(key_pem)
            tempbundle.seek(0)

            tls_parameters = undercloud_config._get_public_tls_parameters(
                tempbundle.name)

        self.assertEqual(cert_pem, tls_parameters['SSLCertificate'])
        self.assertEqual(key_pem, tls_parameters['SSLKey'])

    def test_get_tls_parameters_fails_cause_of_missing_cert(self):
        _, key_pem = self.get_certificate_and_private_key()

        with tempfile.NamedTemporaryFile() as tempbundle:
            tempbundle.write(key_pem)
            tempbundle.seek(0)

            self.assertRaises(ValueError,
                              undercloud_config._get_public_tls_parameters,
                              tempbundle.name)

    def test_get_tls_parameters_fails_cause_of_missing_key(self):
        cert_pem, _ = self.get_certificate_and_private_key()

        with tempfile.NamedTemporaryFile() as tempbundle:
            tempbundle.write(cert_pem)
            tempbundle.seek(0)

            self.assertRaises(ValueError,
                              undercloud_config._get_public_tls_parameters,
                              tempbundle.name)

    def test_get_tls_parameters_fails_cause_of_unexistent_file(self):
        self.assertRaises(IOError,
                          undercloud_config._get_public_tls_parameters,
                          '/tmp/unexistent-file-12345.pem')


class TestContainerImageConfig(base.TestCase):
    def setUp(self):
        super(TestContainerImageConfig, self).setUp()
        conf_keys = (
            'container_images_file',
        )
        self.conf = mock.Mock(**{key: getattr(undercloud_config.CONF, key)
                                 for key in conf_keys})

    @mock.patch('shutil.copy')
    def test_defaults(self, mock_copy):
        env = {}
        deploy_args = []
        cip_default = getattr(kolla_builder,
                              'CONTAINER_IMAGE_PREPARE_PARAM', None)
        self.addCleanup(setattr, kolla_builder,
                        'CONTAINER_IMAGE_PREPARE_PARAM', cip_default)

        setattr(kolla_builder, 'CONTAINER_IMAGE_PREPARE_PARAM', [{
            'set': {
                'namespace': 'one',
                'name_prefix': 'two',
                'name_suffix': 'three',
                'tag': 'four',
            },
            'tag_from_label': 'five',
        }])

        undercloud_config._container_images_config(self.conf, deploy_args,
                                                   env, None)
        self.assertEqual([], deploy_args)
        cip = env['ContainerImagePrepare'][0]
        set = cip['set']

        self.assertEqual(
            'one', set['namespace'])
        self.assertEqual(
            'two', set['name_prefix'])
        self.assertEqual(
            'three', set['name_suffix'])
        self.assertEqual(
            'four', set['tag'])
        self.assertEqual(
            'five', cip['tag_from_label'])

    @mock.patch('shutil.copy')
    def test_container_images_file(self, mock_copy):
        env = {}
        deploy_args = []
        self.conf.container_images_file = '/tmp/container_images_file.yaml'
        undercloud_config._container_images_config(self.conf, deploy_args,
                                                   env, None)
        self.assertEqual(['-e', '/tmp/container_images_file.yaml'],
                         deploy_args)
        self.assertEqual({}, env)

    @mock.patch('shutil.copy')
    def test_custom(self, mock_copy):
        env = {}
        deploy_args = []
        with tempfile.NamedTemporaryFile(mode='w') as f:
            yaml.dump({
                'parameter_defaults': {'ContainerImagePrepare': [{
                    'set': {
                        'namespace': 'one',
                        'name_prefix': 'two',
                        'name_suffix': 'three',
                        'tag': 'four',
                    },
                    'tag_from_label': 'five',
                }]}
            }, f)
            self.conf.container_images_file = f.name
            cif_name = f.name

            undercloud_config._container_images_config(
                self.conf, deploy_args, env, None)
        self.assertEqual(['-e', cif_name], deploy_args)
