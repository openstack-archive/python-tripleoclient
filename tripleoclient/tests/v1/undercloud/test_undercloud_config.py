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

import mock

from tripleoclient.tests import base
from tripleoclient.v1 import undercloud_config


class TestProcessDriversAndHardwareTypes(base.TestCase):
    def setUp(self):
        super(TestProcessDriversAndHardwareTypes, self).setUp()
        self.conf = mock.Mock(**{key: getattr(undercloud_config.CONF, key)
                                 for key in ('enabled_drivers',
                                             'enabled_hardware_types',
                                             'enable_node_discovery',
                                             'discovery_default_driver')})

    def test_defaults(self):
        env = {}
        undercloud_config._process_drivers_and_hardware_types(self.conf, env)
        self.assertEqual({
            'IronicEnabledDrivers': ['pxe_drac', 'pxe_ilo', 'pxe_ipmitool'],
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
            'IronicEnabledDrivers': ['pxe_drac', 'pxe_ilo', 'pxe_ipmitool'],
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
                                                'cisco-ucs-standalone']
        )

        undercloud_config._process_drivers_and_hardware_types(self.conf, env)
        self.assertEqual({
            'IronicEnabledDrivers': ['pxe_drac', 'pxe_ilo', 'pxe_ipmitool'],
            'IronicEnabledHardwareTypes': ['cisco-ucs-managed',
                                           'cisco-ucs-standalone',
                                           'idrac', 'ilo', 'ipmi', 'irmc',
                                           'redfish', 'snmp', 'staging-ovirt'],
            'IronicEnabledBootInterfaces': ['ilo-pxe', 'irmc-pxe', 'pxe'],
            'IronicEnabledManagementInterfaces': ['cimc', 'fake', 'idrac',
                                                  'ilo', 'ipmitool', 'irmc',
                                                  'redfish', 'staging-ovirt',
                                                  'ucsm'],
            'IronicEnabledPowerInterfaces': ['cimc', 'fake', 'idrac',
                                             'ilo', 'ipmitool', 'irmc',
                                             'redfish', 'snmp',
                                             'staging-ovirt', 'ucsm'],
            'IronicEnabledRaidInterfaces': ['idrac', 'no-raid'],
            'IronicEnabledVendorInterfaces': ['idrac', 'ipmitool', 'no-vendor']
        }, env)
