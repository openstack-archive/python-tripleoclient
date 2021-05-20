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
import fixtures
import mock
import os
import tempfile
import yaml

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture

from tripleo_common.image import kolla_builder

from tripleoclient import exceptions
from tripleoclient.tests import base
from tripleoclient.v1 import undercloud_config


class TestProcessDriversAndHardwareTypes(base.TestCase):
    def setUp(self):
        super(TestProcessDriversAndHardwareTypes, self).setUp()
        self.conf = mock.Mock(**{key: getattr(undercloud_config.CONF, key)
                                 for key in (
                                     'enabled_hardware_types',
                                     'enable_node_discovery',
                                     'discovery_default_driver',
                                     'ironic_enabled_network_interfaces',
                                     'ironic_default_network_interface')})

    def test_defaults(self):
        env = {}
        undercloud_config._process_drivers_and_hardware_types(self.conf, env)
        self.assertEqual({
            'IronicEnabledNetworkInterfaces': ['flat'],
            'IronicDefaultNetworkInterface': 'flat',
            'IronicEnabledHardwareTypes': ['idrac', 'ilo', 'ipmi', 'redfish'],
            'IronicEnabledBootInterfaces': ['ilo-pxe', 'ipxe', 'pxe'],
            'IronicEnabledBiosInterfaces': ['ilo', 'no-bios', 'redfish'],
            'IronicEnabledDeployInterfaces': ['ansible', 'direct', 'iscsi'],
            'IronicEnabledInspectInterfaces': ['idrac', 'ilo', 'inspector',
                                               'no-inspect', 'redfish'],
            'IronicEnabledManagementInterfaces': ['fake', 'idrac', 'ilo',
                                                  'ipmitool', 'noop',
                                                  'redfish'],
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
            'IronicEnabledNetworkInterfaces': ['flat'],
            'IronicDefaultNetworkInterface': 'flat',
            # ipmi added because it's the default discovery driver
            'IronicEnabledHardwareTypes': ['ipmi', 'redfish'],
            'IronicEnabledBootInterfaces': ['ipxe', 'pxe'],
            'IronicEnabledBiosInterfaces': ['no-bios', 'redfish'],
            'IronicEnabledDeployInterfaces': ['ansible', 'direct', 'iscsi'],
            'IronicEnabledInspectInterfaces': ['inspector', 'no-inspect',
                                               'redfish'],
            'IronicEnabledManagementInterfaces': ['fake', 'ipmitool',
                                                  'noop', 'redfish'],
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
                                                'irmc', 'xclarity',
                                                'fake-hardware']
        )

        undercloud_config._process_drivers_and_hardware_types(self.conf, env)
        self.assertEqual({
            'IronicEnabledNetworkInterfaces': ['flat'],
            'IronicDefaultNetworkInterface': 'flat',
            'IronicEnabledHardwareTypes': ['fake-hardware', 'idrac', 'ilo',
                                           'ipmi', 'irmc', 'redfish', 'snmp',
                                           'staging-ovirt', 'xclarity'],
            'IronicEnabledBootInterfaces': ['fake', 'ilo-pxe', 'ipxe',
                                            'irmc-pxe', 'pxe'],
            'IronicEnabledBiosInterfaces': ['ilo', 'irmc',
                                            'no-bios', 'redfish'],
            'IronicEnabledDeployInterfaces': ['ansible', 'direct', 'fake',
                                              'iscsi'],
            'IronicEnabledInspectInterfaces': ['idrac', 'ilo', 'inspector',
                                               'irmc', 'no-inspect',
                                               'redfish'],
            'IronicEnabledManagementInterfaces': ['fake', 'idrac',
                                                  'ilo', 'ipmitool', 'irmc',
                                                  'noop', 'redfish',
                                                  'staging-ovirt', 'xclarity'],
            'IronicEnabledPowerInterfaces': ['fake', 'idrac',
                                             'ilo', 'ipmitool', 'irmc',
                                             'redfish', 'snmp',
                                             'staging-ovirt', 'xclarity'],
            'IronicEnabledRaidInterfaces': ['idrac', 'no-raid'],
            'IronicEnabledVendorInterfaces': ['idrac', 'ipmitool', 'no-vendor']
        }, env)


class TestBaseNetworkSettings(base.TestCase):
    def setUp(self):
        super(TestBaseNetworkSettings, self).setUp()
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        # don't actually load config from ~/undercloud.conf
        self.mock_config_load = self.useFixture(
            fixtures.MockPatch('tripleoclient.utils.load_config'))
        self.conf.config(local_ip='192.168.24.1/24',
                         undercloud_admin_host='192.168.24.3',
                         undercloud_public_host='192.168.24.2',
                         undercloud_nameservers=['10.10.10.10', '10.10.10.11'])
        # ctlplane network - config group options
        self.grp0 = cfg.OptGroup(name='ctlplane-subnet',
                                 title='ctlplane-subnet')
        self.opts = [cfg.StrOpt('cidr'),
                     cfg.ListOpt('dhcp_start'),
                     cfg.ListOpt('dhcp_end'),
                     cfg.ListOpt('dhcp_exclude'),
                     cfg.StrOpt('inspection_iprange'),
                     cfg.StrOpt('gateway'),
                     cfg.BoolOpt('masquerade'),
                     cfg.ListOpt('host_routes',
                                 item_type=cfg.types.Dict(bounds=True),
                                 bounds=True,),
                     cfg.ListOpt('dns_nameservers')]
        self.conf.register_opts(self.opts, group=self.grp0)
        self.grp1 = cfg.OptGroup(name='subnet1', title='subnet1')
        self.grp2 = cfg.OptGroup(name='subnet2', title='subnet2')
        self.conf.config(cidr='192.168.24.0/24',
                         dhcp_start='192.168.24.5',
                         dhcp_end='192.168.24.24',
                         dhcp_exclude=[],
                         inspection_iprange='192.168.24.100,192.168.24.120',
                         gateway='192.168.24.1',
                         masquerade=False,
                         host_routes=[],
                         dns_nameservers=[],
                         group='ctlplane-subnet')


class TestNetworkSettings(TestBaseNetworkSettings):
    def test_default(self):
        env = {}
        undercloud_config._process_network_args(env)
        expected = {
            'DnsServers': '10.10.10.10,10.10.10.11',
            'ControlPlaneStaticRoutes': [],
            'IronicInspectorSubnets': [
                {'gateway': '192.168.24.1',
                 'host_routes': [],
                 'ip_range': '192.168.24.100,192.168.24.120',
                 'netmask': '255.255.255.0',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500}],
            'MasqueradeNetworks': {},
            'PortPhysnetCidrMap': {'192.168.24.0/24': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': '192.168.24.5', 'end': '192.168.24.24'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.24.0/24',
                    'NetworkGateway': '192.168.24.1'}},
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateless',
        }
        self.assertEqual(expected, env)

    def test_ipv6_control_plane_stateless_default(self):
        env = {}
        self.conf.config(local_ip='fd12:3456:789a:1::2/64',
                         undercloud_admin_host='fd12:3456:789a:1::3',
                         undercloud_public_host='fd12:3456:789a:1::4')
        self.conf.config(cidr='fd12:3456:789a:1::/64',
                         dhcp_start='fd12:3456:789a:1::10',
                         dhcp_end='fd12:3456:789a:1::20',
                         dhcp_exclude=[],
                         dns_nameservers=['fd12:3456:789a:1::5',
                                          'fd12:3456:789a:1::6'],
                         inspection_iprange=('fd12:3456:789a:1::30,'
                                             'fd12:3456:789a:1::40'),
                         gateway='fd12:3456:789a:1::1',
                         masquerade=False,
                         host_routes=[],
                         group='ctlplane-subnet')
        undercloud_config._process_network_args(env)
        expected = {
            'NovaIPv6': True,
            'RabbitIPv6': True,
            'MemcachedIPv6': True,
            'RedisIPv6': True,
            'MysqlIPv6': True,
            'IronicIpVersion': '6',
            'ControlPlaneStaticRoutes': [],
            'DnsServers': '10.10.10.10,10.10.10.11',
            'IronicInspectorSubnets': [
                {'gateway': 'fd12:3456:789a:1::1',
                 'host_routes': [],
                 'ip_range': 'fd12:3456:789a:1::,static',
                 'netmask': 'ffff:ffff:ffff:ffff::',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500}],
            'MasqueradeNetworks': {},
            'PortPhysnetCidrMap': {'fd12:3456:789a:1::/64': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': 'fd12:3456:789a:1::10',
                         'end': 'fd12:3456:789a:1::20'}],
                    'DnsNameServers': ['fd12:3456:789a:1::5',
                                       'fd12:3456:789a:1::6'],
                    'HostRoutes': [],
                    'NetworkCidr': 'fd12:3456:789a:1::/64',
                    'NetworkGateway': 'fd12:3456:789a:1::1'}},
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateless',
        }
        self.assertEqual(expected, env)

    def test_ipv6_control_plane_stateful(self):
        env = {}
        self.conf.config(local_ip='fd12:3456:789a:1::2/64',
                         undercloud_admin_host='fd12:3456:789a:1::3',
                         undercloud_public_host='fd12:3456:789a:1::4',
                         ipv6_address_mode='dhcpv6-stateful')
        self.conf.config(cidr='fd12:3456:789a:1::/64',
                         dhcp_start='fd12:3456:789a:1::10',
                         dhcp_end='fd12:3456:789a:1::20',
                         dhcp_exclude=[],
                         dns_nameservers=['fd12:3456:789a:1::5',
                                          'fd12:3456:789a:1::6'],
                         inspection_iprange=('fd12:3456:789a:1::30,'
                                             'fd12:3456:789a:1::40'),
                         gateway='fd12:3456:789a:1::1',
                         masquerade=False,
                         host_routes=[],
                         group='ctlplane-subnet')
        undercloud_config._process_network_args(env)
        expected = {
            'NovaIPv6': True,
            'RabbitIPv6': True,
            'MemcachedIPv6': True,
            'RedisIPv6': True,
            'MysqlIPv6': True,
            'IronicIpVersion': '6',
            'ControlPlaneStaticRoutes': [],
            'DnsServers': '10.10.10.10,10.10.10.11',
            'IronicInspectorSubnets': [
                {'gateway': 'fd12:3456:789a:1::1',
                 'host_routes': [],
                 'ip_range': 'fd12:3456:789a:1::30,fd12:3456:789a:1::40',
                 'netmask': 'ffff:ffff:ffff:ffff::',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500}],
            'MasqueradeNetworks': {},
            'PortPhysnetCidrMap': {'fd12:3456:789a:1::/64': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': 'fd12:3456:789a:1::10',
                         'end': 'fd12:3456:789a:1::20'}],
                    'DnsNameServers': ['fd12:3456:789a:1::5',
                                       'fd12:3456:789a:1::6'],
                    'HostRoutes': [],
                    'NetworkCidr': 'fd12:3456:789a:1::/64',
                    'NetworkGateway': 'fd12:3456:789a:1::1'}},
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateful',
        }
        self.assertEqual(expected, env)

    def test_nameserver_toomany_fail(self):
        env = {}
        self.conf.config(undercloud_nameservers=['1.1.1.1', '1.1.1.2',
                                                 '1.1.1.3', '1.1.1.4',
                                                 '1.1.1.5', '1.1.1.6'])
        self.assertRaises(exceptions.InvalidConfiguration,
                          undercloud_config._process_network_args,
                          env)

    def test_undercloud_ips_duplicated_fail(self):
        env = {}

        # local_ip == undercloud_admin_host
        self.conf.config(local_ip='192.168.24.1/24',
                         undercloud_admin_host='192.168.24.1',
                         undercloud_public_host='192.168.24.2',
                         generate_service_certificate=True)
        self.assertRaises(exceptions.InvalidConfiguration,
                          undercloud_config._process_network_args,
                          env)

        # local_ip == undercloud_public_host
        self.conf.config(local_ip='192.168.24.1/24',
                         undercloud_admin_host='192.168.24.3',
                         undercloud_public_host='192.168.24.1',
                         generate_service_certificate=True)
        undercloud_config._process_network_args(env)

        # undercloud_admin_host == undercloud_public_host
        self.conf.config(local_ip='192.168.24.1/24',
                         undercloud_admin_host='192.168.24.2',
                         undercloud_public_host='192.168.24.2',
                         generate_service_certificate=True)
        undercloud_config._process_network_args(env)

        # We do not care about ip duplication when ssl is disabled
        self.conf.config(local_ip='192.168.24.1/24',
                         undercloud_admin_host='192.168.24.1',
                         undercloud_public_host='192.168.24.2',
                         generate_service_certificate=False,
                         undercloud_service_certificate='')
        undercloud_config._process_network_args(env)

    def test_start_end_all_addresses(self):
        self.conf.config(dhcp_start='192.168.24.0',
                         dhcp_end='192.168.24.255',
                         group='ctlplane-subnet')
        env = {}
        undercloud_config._process_network_args(env)
        expected = {
            'DnsServers': '10.10.10.10,10.10.10.11',
            'ControlPlaneStaticRoutes': [],
            'IronicInspectorSubnets': [
                {'gateway': '192.168.24.1',
                 'host_routes': [],
                 'ip_range': '192.168.24.100,192.168.24.120',
                 'netmask': '255.255.255.0',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500}],
            'MasqueradeNetworks': {},
            'PortPhysnetCidrMap': {'192.168.24.0/24': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': '192.168.24.4', 'end': '192.168.24.99'},
                        {'start': '192.168.24.121', 'end': '192.168.24.254'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.24.0/24',
                    'NetworkGateway': '192.168.24.1'}},
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateless',
        }
        self.assertEqual(expected, env)

    def test_ignore_dhcp_start_end_if_default_but_cidr_not_default(self):
        self.conf.config(cidr='192.168.10.0/24',
                         inspection_iprange='192.168.10.100,192.168.10.120',
                         gateway='192.168.10.1',
                         group='ctlplane-subnet')
        env = {}
        undercloud_config._process_network_args(env)
        expected = {
            'DnsServers': '10.10.10.10,10.10.10.11',
            'ControlPlaneStaticRoutes': [],
            'IronicInspectorSubnets': [
                {'gateway': '192.168.10.1',
                 'host_routes': [],
                 'ip_range': '192.168.10.100,192.168.10.120',
                 'netmask': '255.255.255.0',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500}],
            'MasqueradeNetworks': {},
            'PortPhysnetCidrMap': {'192.168.10.0/24': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': '192.168.10.2', 'end': '192.168.10.99'},
                        {'start': '192.168.10.121', 'end': '192.168.10.254'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.10.0/24',
                    'NetworkGateway': '192.168.10.1'}},
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateless',
        }
        self.assertEqual(expected, env)

    def test_dhcp_exclude(self):
        self.conf.config(cidr='192.168.10.0/24',
                         inspection_iprange='192.168.10.100,192.168.10.120',
                         gateway='192.168.10.1',
                         dhcp_exclude=['192.168.10.50',
                                       '192.168.10.80-192.168.10.89'],
                         group='ctlplane-subnet')
        env = {}
        undercloud_config._process_network_args(env)
        expected = {
            'DnsServers': '10.10.10.10,10.10.10.11',
            'ControlPlaneStaticRoutes': [],
            'IronicInspectorSubnets': [
                {'gateway': '192.168.10.1',
                 'host_routes': [],
                 'ip_range': '192.168.10.100,192.168.10.120',
                 'netmask': '255.255.255.0',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500}],
            'MasqueradeNetworks': {},
            'PortPhysnetCidrMap': {'192.168.10.0/24': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': '192.168.10.2', 'end': '192.168.10.49'},
                        {'start': '192.168.10.51', 'end': '192.168.10.79'},
                        {'start': '192.168.10.90', 'end': '192.168.10.99'},
                        {'start': '192.168.10.121', 'end': '192.168.10.254'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.10.0/24',
                    'NetworkGateway': '192.168.10.1'}},
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateless',
        }
        self.assertEqual(expected, env)

    def test_no_dhcp_start_no_dhcp_end(self):
        self.conf.config(dhcp_start=[],
                         dhcp_end=[],
                         group='ctlplane-subnet')
        env = {}
        undercloud_config._process_network_args(env)
        expected = {
            'DnsServers': '10.10.10.10,10.10.10.11',
            'ControlPlaneStaticRoutes': [],
            'IronicInspectorSubnets': [
                {'gateway': '192.168.24.1',
                 'host_routes': [],
                 'ip_range': '192.168.24.100,192.168.24.120',
                 'netmask': '255.255.255.0',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500}],
            'MasqueradeNetworks': {},
            'PortPhysnetCidrMap': {'192.168.24.0/24': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': '192.168.24.4', 'end': '192.168.24.99'},
                        {'start': '192.168.24.121', 'end': '192.168.24.254'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.24.0/24',
                    'NetworkGateway': '192.168.24.1'}},
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateless',
        }
        self.assertEqual(expected, env)

    def test_dhcp_start_no_dhcp_end(self):
        self.conf.config(dhcp_start='192.168.24.10',
                         dhcp_end=[],
                         group='ctlplane-subnet')
        env = {}
        undercloud_config._process_network_args(env)
        expected = {
            'DnsServers': '10.10.10.10,10.10.10.11',
            'ControlPlaneStaticRoutes': [],
            'IronicInspectorSubnets': [
                {'gateway': '192.168.24.1',
                 'host_routes': [],
                 'ip_range': '192.168.24.100,192.168.24.120',
                 'netmask': '255.255.255.0',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500}],
            'MasqueradeNetworks': {},
            'PortPhysnetCidrMap': {'192.168.24.0/24': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': '192.168.24.10', 'end': '192.168.24.99'},
                        {'start': '192.168.24.121', 'end': '192.168.24.254'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.24.0/24',
                    'NetworkGateway': '192.168.24.1'},
            },
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateless',
        }
        self.assertEqual(expected, env)

    def test_dhcp_end_no_dhcp_start(self):
        self.conf.config(dhcp_start=[],
                         dhcp_end='192.168.24.220',
                         group='ctlplane-subnet')
        env = {}
        undercloud_config._process_network_args(env)
        expected = {
            'DnsServers': '10.10.10.10,10.10.10.11',
            'ControlPlaneStaticRoutes': [],
            'IronicInspectorSubnets': [
                {'gateway': '192.168.24.1',
                 'host_routes': [],
                 'ip_range': '192.168.24.100,192.168.24.120',
                 'netmask': '255.255.255.0',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500}],
            'MasqueradeNetworks': {},
            'PortPhysnetCidrMap': {'192.168.24.0/24': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': '192.168.24.4', 'end': '192.168.24.99'},
                        {'start': '192.168.24.121', 'end': '192.168.24.220'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.24.0/24',
                    'NetworkGateway': '192.168.24.1'},
            },
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateless',
        }
        self.assertEqual(expected, env)

    def test_routed_network(self):
        self.conf.config(subnets=['ctlplane-subnet', 'subnet1', 'subnet2'])
        self.conf.register_opts(self.opts, group=self.grp1)
        self.conf.register_opts(self.opts, group=self.grp2)
        self.conf.config(masquerade=True,
                         dns_nameservers=['10.1.1.100', '10.1.1.101'],
                         group='ctlplane-subnet')
        self.conf.config(cidr='192.168.10.0/24',
                         dhcp_start='192.168.10.10',
                         dhcp_end='192.168.10.99',
                         dhcp_exclude=[],
                         inspection_iprange='192.168.10.100,192.168.10.189',
                         gateway='192.168.10.254',
                         dns_nameservers=['10.2.2.100', '10.2.2.101'],
                         host_routes=[],
                         masquerade=True,
                         group='subnet1')
        self.conf.config(cidr='192.168.20.0/24',
                         dhcp_start='192.168.20.10',
                         dhcp_end='192.168.20.99',
                         dhcp_exclude=[],
                         inspection_iprange='192.168.20.100,192.168.20.189',
                         gateway='192.168.20.254',
                         dns_nameservers=['10.3.3.100', '10.3.3.101'],
                         host_routes=[],
                         masquerade=True,
                         group='subnet2')
        env = {}
        undercloud_config._process_network_args(env)
        expected = {
            'DnsServers': '10.10.10.10,10.10.10.11',
            'ControlPlaneStaticRoutes': [
                {'ip_netmask': '192.168.10.0/24', 'next_hop': '192.168.24.1'},
                {'ip_netmask': '192.168.20.0/24', 'next_hop': '192.168.24.1'}],
            'IronicInspectorSubnets': [
                {'gateway': '192.168.24.1',
                 'host_routes': [],
                 'ip_range': '192.168.24.100,192.168.24.120',
                 'netmask': '255.255.255.0',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500},
                {'gateway': '192.168.10.254',
                 'host_routes': [],
                 'ip_range': '192.168.10.100,192.168.10.189',
                 'netmask': '255.255.255.0',
                 'tag': 'subnet1',
                 'mtu': 1500},
                {'gateway': '192.168.20.254',
                 'host_routes': [],
                 'ip_range': '192.168.20.100,192.168.20.189',
                 'netmask': '255.255.255.0',
                 'tag': 'subnet2',
                 'mtu': 1500}
            ],
            'MasqueradeNetworks': {
                '192.168.10.0/24': ['192.168.24.0/24',
                                    '192.168.10.0/24',
                                    '192.168.20.0/24'],
                '192.168.20.0/24': ['192.168.24.0/24',
                                    '192.168.10.0/24',
                                    '192.168.20.0/24'],
                '192.168.24.0/24': ['192.168.24.0/24',
                                    '192.168.10.0/24',
                                    '192.168.20.0/24']},
            'PortPhysnetCidrMap': {'192.168.10.0/24': 'subnet1',
                                   '192.168.20.0/24': 'subnet2',
                                   '192.168.24.0/24': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                # The ctlplane-subnet subnet have defaults
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': '192.168.24.5', 'end': '192.168.24.24'}],
                    'DnsNameServers': ['10.1.1.100', '10.1.1.101'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.24.0/24',
                    'NetworkGateway': '192.168.24.1'},
                'subnet1': {
                    'AllocationPools': [
                        {'start': '192.168.10.10', 'end': '192.168.10.99'}],
                    'DnsNameServers': ['10.2.2.100', '10.2.2.101'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.10.0/24',
                    'NetworkGateway': '192.168.10.254'},
                'subnet2': {
                    'AllocationPools': [
                        {'start': '192.168.20.10', 'end': '192.168.20.99'}],
                    'DnsNameServers': ['10.3.3.100', '10.3.3.101'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.20.0/24',
                    'NetworkGateway': '192.168.20.254'}
            },
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateless',
        }
        self.assertEqual(expected, env)

    def test_routed_network_no_masquerading(self):
        self.conf.config(subnets=['ctlplane-subnet', 'subnet1', 'subnet2'])
        self.conf.register_opts(self.opts, group=self.grp1)
        self.conf.register_opts(self.opts, group=self.grp2)
        self.conf.config(cidr='192.168.10.0/24',
                         dhcp_start='192.168.10.10',
                         dhcp_end='192.168.10.99',
                         dhcp_exclude=[],
                         inspection_iprange='192.168.10.100,192.168.10.189',
                         gateway='192.168.10.254',
                         dns_nameservers=[],
                         host_routes=[],
                         group='subnet1')
        self.conf.config(cidr='192.168.20.0/24',
                         dhcp_start='192.168.20.10',
                         dhcp_end='192.168.20.99',
                         dhcp_exclude=[],
                         inspection_iprange='192.168.20.100,192.168.20.189',
                         gateway='192.168.20.254',
                         dns_nameservers=[],
                         host_routes=[],
                         group='subnet2')
        env = {}
        undercloud_config._process_network_args(env)
        expected = {
            'DnsServers': '10.10.10.10,10.10.10.11',
            'ControlPlaneStaticRoutes': [
                {'ip_netmask': '192.168.10.0/24', 'next_hop': '192.168.24.1'},
                {'ip_netmask': '192.168.20.0/24', 'next_hop': '192.168.24.1'}],
            'IronicInspectorSubnets': [
                {'gateway': '192.168.24.1',
                 'host_routes': [],
                 'ip_range': '192.168.24.100,192.168.24.120',
                 'netmask': '255.255.255.0',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500},
                {'gateway': '192.168.10.254',
                 'host_routes': [],
                 'ip_range': '192.168.10.100,192.168.10.189',
                 'netmask': '255.255.255.0',
                 'tag': 'subnet1',
                 'mtu': 1500},
                {'gateway': '192.168.20.254',
                 'host_routes': [],
                 'ip_range': '192.168.20.100,192.168.20.189',
                 'netmask': '255.255.255.0',
                 'tag': 'subnet2',
                 'mtu': 1500}
            ],
            'MasqueradeNetworks': {},
            'PortPhysnetCidrMap': {'192.168.10.0/24': 'subnet1',
                                   '192.168.20.0/24': 'subnet2',
                                   '192.168.24.0/24': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                # The ctlplane-subnet subnet have defaults
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': '192.168.24.5', 'end': '192.168.24.24'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.24.0/24',
                    'NetworkGateway': '192.168.24.1'},
                'subnet1': {
                    'AllocationPools': [
                        {'start': '192.168.10.10', 'end': '192.168.10.99'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.10.0/24',
                    'NetworkGateway': '192.168.10.254'},
                'subnet2': {
                    'AllocationPools': [
                        {'start': '192.168.20.10', 'end': '192.168.20.99'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.20.0/24',
                    'NetworkGateway': '192.168.20.254'}
            },
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateless',
        }
        self.assertEqual(expected, env)

    def test_no_allocation_pool_on_remote_network(self):
        self.conf.config(subnets=['ctlplane-subnet', 'subnet1'])
        self.conf.register_opts(self.opts, group=self.grp1)
        self.conf.config(cidr='192.168.10.0/24',
                         dhcp_exclude=[],
                         inspection_iprange='192.168.10.200,192.168.10.254',
                         gateway='192.168.10.254',
                         dns_nameservers=[],
                         host_routes=[],
                         masquerade=False,
                         group='subnet1')
        env = {}
        undercloud_config._process_network_args(env)
        expected = {
            'DnsServers': '10.10.10.10,10.10.10.11',
            'ControlPlaneStaticRoutes': [
                {'ip_netmask': '192.168.10.0/24', 'next_hop': '192.168.24.1'}],
            'IronicInspectorSubnets': [
                {'gateway': '192.168.24.1',
                 'host_routes': [],
                 'ip_range': '192.168.24.100,192.168.24.120',
                 'netmask': '255.255.255.0',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500},
                {'gateway': '192.168.10.254',
                 'host_routes': [],
                 'ip_range': '192.168.10.200,192.168.10.254',
                 'netmask': '255.255.255.0',
                 'tag': 'subnet1',
                 'mtu': 1500},
            ],
            'MasqueradeNetworks': {},
            'PortPhysnetCidrMap': {'192.168.10.0/24': 'subnet1',
                                   '192.168.24.0/24': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                # The ctlplane-subnet subnet have defaults
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': '192.168.24.5', 'end': '192.168.24.24'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.24.0/24',
                    'NetworkGateway': '192.168.24.1'},
                'subnet1': {
                    'AllocationPools': [
                        {'start': '192.168.10.1', 'end': '192.168.10.199'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.10.0/24',
                    'NetworkGateway': '192.168.10.254'}
            },
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateless',
        }
        self.assertEqual(expected, env)

    def test_no_allocation_pool_on_remote_network_three_pools(self):
        self.conf.config(subnets=['ctlplane-subnet', 'subnet1'])
        self.conf.register_opts(self.opts, group=self.grp1)
        self.conf.config(cidr='192.168.10.0/24',
                         dhcp_exclude=[],
                         inspection_iprange='192.168.10.100,192.168.10.199',
                         gateway='192.168.10.222',
                         dns_nameservers=[],
                         host_routes=[],
                         masquerade=False,
                         group='subnet1')
        env = {}
        undercloud_config._process_network_args(env)
        expected = {
            'DnsServers': '10.10.10.10,10.10.10.11',
            'ControlPlaneStaticRoutes': [
                {'ip_netmask': '192.168.10.0/24', 'next_hop': '192.168.24.1'}],
            'IronicInspectorSubnets': [
                {'gateway': '192.168.24.1',
                 'host_routes': [],
                 'ip_range': '192.168.24.100,192.168.24.120',
                 'netmask': '255.255.255.0',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500},
                {'gateway': '192.168.10.222',
                 'host_routes': [],
                 'ip_range': '192.168.10.100,192.168.10.199',
                 'netmask': '255.255.255.0',
                 'tag': 'subnet1',
                 'mtu': 1500},
            ],
            'MasqueradeNetworks': {},
            'PortPhysnetCidrMap': {'192.168.10.0/24': 'subnet1',
                                   '192.168.24.0/24': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                # The ctlplane-subnet subnet have defaults
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': '192.168.24.5', 'end': '192.168.24.24'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.24.0/24',
                    'NetworkGateway': '192.168.24.1'},
                'subnet1': {
                    'AllocationPools': [
                        {'start': '192.168.10.1', 'end': '192.168.10.99'},
                        {'start': '192.168.10.200', 'end': '192.168.10.221'},
                        {'start': '192.168.10.223', 'end': '192.168.10.254'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [],
                    'NetworkCidr': '192.168.10.0/24',
                    'NetworkGateway': '192.168.10.222'}
            },
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateless',
        }
        self.assertEqual(expected, env)

    def test_additional_host_routes(self):
        self.conf.config(subnets=['ctlplane-subnet', 'subnet1', 'subnet2'])
        self.conf.config(host_routes=[{'destination': '10.10.10.254/32',
                                       'nexthop': '192.168.24.1'}],
                         group='ctlplane-subnet')
        self.conf.register_opts(self.opts, group=self.grp1)
        self.conf.register_opts(self.opts, group=self.grp2)
        self.conf.config(cidr='192.168.10.0/24',
                         dhcp_start='192.168.10.10',
                         dhcp_end='192.168.10.99',
                         dhcp_exclude=[],
                         inspection_iprange='192.168.10.100,192.168.10.189',
                         gateway='192.168.10.254',
                         dns_nameservers=[],
                         host_routes=[{'destination': '10.10.10.254/32',
                                       'nexthop': '192.168.10.254'}],
                         group='subnet1')
        self.conf.config(cidr='192.168.20.0/24',
                         dhcp_start='192.168.20.10',
                         dhcp_end='192.168.20.99',
                         dhcp_exclude=[],
                         inspection_iprange='192.168.20.100,192.168.20.189',
                         gateway='192.168.20.254',
                         dns_nameservers=[],
                         host_routes=[{'destination': '10.10.10.254/32',
                                       'nexthop': '192.168.20.254'}],
                         group='subnet2')
        env = {}
        undercloud_config._process_network_args(env)
        expected = {
            'DnsServers': '10.10.10.10,10.10.10.11',
            'ControlPlaneStaticRoutes': [
                {'ip_netmask': '192.168.10.0/24', 'next_hop': '192.168.24.1'},
                {'ip_netmask': '192.168.20.0/24', 'next_hop': '192.168.24.1'},
                {'ip_netmask': '10.10.10.254/32', 'next_hop': '192.168.24.1'}],
            'IronicInspectorSubnets': [
                {'gateway': '192.168.24.1',
                 'host_routes': [{'destination': '10.10.10.254/32',
                                  'nexthop': '192.168.24.1'}],
                 'ip_range': '192.168.24.100,192.168.24.120',
                 'netmask': '255.255.255.0',
                 'tag': 'ctlplane-subnet',
                 'mtu': 1500},
                {'gateway': '192.168.10.254',
                 'host_routes': [{'destination': '10.10.10.254/32',
                                  'nexthop': '192.168.10.254'}],
                 'ip_range': '192.168.10.100,192.168.10.189',
                 'netmask': '255.255.255.0',
                 'tag': 'subnet1',
                 'mtu': 1500},
                {'gateway': '192.168.20.254',
                 'host_routes': [{'destination': '10.10.10.254/32',
                                  'nexthop': '192.168.20.254'}],
                 'ip_range': '192.168.20.100,192.168.20.189',
                 'netmask': '255.255.255.0',
                 'tag': 'subnet2',
                 'mtu': 1500}
            ],
            'MasqueradeNetworks': {},
            'PortPhysnetCidrMap': {'192.168.10.0/24': 'subnet1',
                                   '192.168.20.0/24': 'subnet2',
                                   '192.168.24.0/24': 'ctlplane'},
            'UndercloudCtlplaneSubnets': {
                # The ctlplane-subnet subnet have defaults
                'ctlplane-subnet': {
                    'AllocationPools': [
                        {'start': '192.168.24.5', 'end': '192.168.24.24'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [{'destination': '10.10.10.254/32',
                                    'nexthop': '192.168.24.1'}],
                    'NetworkCidr': '192.168.24.0/24',
                    'NetworkGateway': '192.168.24.1'},
                'subnet1': {
                    'AllocationPools': [
                        {'start': '192.168.10.10', 'end': '192.168.10.99'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [{'destination': '10.10.10.254/32',
                                    'nexthop': '192.168.10.254'}],
                    'NetworkCidr': '192.168.10.0/24',
                    'NetworkGateway': '192.168.10.254'},
                'subnet2': {
                    'AllocationPools': [
                        {'start': '192.168.20.10', 'end': '192.168.20.99'}],
                    'DnsNameServers': ['10.10.10.10', '10.10.10.11'],
                    'HostRoutes': [{'destination': '10.10.10.254/32',
                                    'nexthop': '192.168.20.254'}],
                    'NetworkCidr': '192.168.20.0/24',
                    'NetworkGateway': '192.168.20.254'}
            },
            'UndercloudCtlplaneIPv6AddressMode': 'dhcpv6-stateless'
        }
        self.assertEqual(expected, env)

    def test_generate_inspection_subnets(self):
        result = undercloud_config._generate_inspection_subnets()
        expected = [{'gateway': '192.168.24.1',
                     'host_routes': [],
                     'ip_range': '192.168.24.100,192.168.24.120',
                     'mtu': 1500,
                     'netmask': '255.255.255.0',
                     'tag': 'ctlplane-subnet'}]
        self.assertEqual(expected, result)

    def test_generate_inspection_subnets_invalid(self):
        self.conf.config(subnets=['ctlplane-subnet', 'subnet1'])
        self.conf.config(host_routes=[{'destination': '10.10.10.254/32',
                                       'nexthop': '192.168.24.1'}],
                         group='ctlplane-subnet')
        self.conf.register_opts(self.opts, group=self.grp1)
        self.conf.config(group='subnet1')
        self.assertRaises(exceptions.DeploymentError,
                          undercloud_config._generate_inspection_subnets)


class TestChronySettings(TestBaseNetworkSettings):
    def test_default(self):
        env = {}
        undercloud_config._process_chrony_acls(env)
        expected = {
            'ChronyAclRules': ['allow 192.168.24.0/24'],
        }
        self.assertEqual(expected, env)


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
