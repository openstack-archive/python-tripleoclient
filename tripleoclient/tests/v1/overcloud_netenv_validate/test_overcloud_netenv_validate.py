#   Copyright 2015 Red Hat, Inc.
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

import os
import tempfile

import yaml

from tripleoclient.tests.v1.overcloud_netenv_validate import fakes
from tripleoclient.v1 import overcloud_netenv_validate


EMPTY_NETENV = """resource_registry:
  OS::TripleO::BlockStorage::Net::SoftwareConfig: /tmp/foo

parameter_defaults:
  NeutronExternalNetworkBridge: "''"
"""


class TestValidateOvercloudNetenv(fakes.TestValidateOvercloudNetenv):

    def setUp(self):
        super(TestValidateOvercloudNetenv, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_netenv_validate.ValidateOvercloudNetenv(
            self.app, None)

    def temporary_nic_config_file(self, bridges):
        nic_config = {
            'resources': {
                'OsNetConfigImpl': {
                    'properties': {
                        'config': {
                            'os_net_config': {
                                'network_config': bridges,
                            }
                        }
                    }
                }
            }
        }
        tmp = tempfile.NamedTemporaryFile(mode='w', delete=False)
        yaml.dump(nic_config, tmp)
        tmp.close()
        return tmp.name

    def test_cidr_no_overlapping_networks(self):
        networks = [
            '172.17.0.0/24',
            '172.16.0.0/24',
            '172.17.1.0/24',
            '172.17.2.0/24',
            '10.1.2.0/24',
        ]
        self.cmd.error_count = 0
        self.cmd.check_cidr_overlap(networks)
        self.assertEqual(0, self.cmd.error_count)

    def test_cidr_overlapping_networks(self):
        networks = [
            '172.17.1.0/24',
            '172.17.1.0/24',
            '10.1.2.0/24',
        ]
        self.cmd.error_count = 0
        self.cmd.check_cidr_overlap(networks)
        self.assertEqual(1, self.cmd.error_count)

    def test_cidr_nonnumerical_address(self):
        networks = [
            'nonsense',
        ]
        self.cmd.error_count = 0
        self.cmd.check_cidr_overlap(networks)
        self.assertEqual(1, self.cmd.error_count)

    def test_cidr_address_outside_of_range(self):
        networks = [
            '172.17.0.278/24',
        ]
        self.cmd.error_count = 0
        self.cmd.check_cidr_overlap(networks)
        self.assertEqual(1, self.cmd.error_count)

    def test_vlan_ids_unique(self):
        vlans = {
            'InternalApiNetworkVlanID': 201,
            'StorageNetworkVlanID': 202,
            'StorageMgmtNetworkVlanID': 203,
            'TenantNetworkVlanID': 204,
            'ExternalNetworkVlanID': 100,
        }
        self.cmd.error_count = 0
        self.cmd.check_vlan_ids(vlans)
        self.assertEqual(0, self.cmd.error_count)

    def test_vlan_ids_duplicate(self):
        vlans = {
            'InternalApiNetworkVlanID': 201,
            'StorageNetworkVlanID': 202,
            'StorageMgmtNetworkVlanID': 203,
            'TenantNetworkVlanID': 202,  # conflicts with StorageNetworkVlanID
            'ExternalNetworkVlanID': 100,
        }
        self.cmd.error_count = 0
        self.cmd.check_vlan_ids(vlans)
        self.assertEqual(1, self.cmd.error_count)

    def test_allocation_pools_pairing_no_overlap(self):
        filedata = {
            'InternalApiNetCidr': '172.17.0.0/24',
            'StorageNetCidr': '172.18.0.0/24',
            'InternalApiAllocationPools': [
                {'start': '172.17.0.10', 'end': '172.17.0.200'}],
            'StorageAllocationPools': [
                {'start': '172.18.0.10', 'end': '172.18.0.200'}],
        }
        pools = {
            'InternalApiAllocationPools': [
                {'start': '172.17.0.10', 'end': '172.17.0.200'}],
            'StorageAllocationPools': [
                {'start': '172.18.0.10', 'end': '172.18.0.200'}],
        }
        self.cmd.error_count = 0
        self.cmd.check_allocation_pools_pairing(filedata, pools)
        self.assertEqual(0, self.cmd.error_count)

    def test_allocation_pools_pairing_inverse_range(self):
        filedata = {
            'InternalApiNetCidr': '172.17.0.0/24',
            'StorageNetCidr': '172.18.0.0/24',
            'InternalApiAllocationPools': [
                {'start': '172.17.0.200', 'end': '172.17.0.10'}],
            'StorageAllocationPools': [
                {'start': '172.18.0.10', 'end': '172.18.0.200'}],
        }
        pools = {
            'InternalApiAllocationPools': [
                {'start': '172.17.0.200', 'end': '172.17.0.10'}],
            'StorageAllocationPools': [
                {'start': '172.18.0.10', 'end': '172.18.0.200'}],
        }
        self.cmd.error_count = 0
        self.cmd.check_allocation_pools_pairing(filedata, pools)
        self.assertEqual(1, self.cmd.error_count)

    def test_allocation_pools_pairing_pool_outside_subnet(self):
        filedata = {
            'InternalApiNetCidr': '172.17.0.0/24',
            'InternalApiAllocationPools': [
                {'start': '172.16.0.10', 'end': '172.16.0.200'}],
        }
        pools = {
            'InternalApiAllocationPools': [
                {'start': '172.16.0.10', 'end': '172.16.0.200'}],
        }
        self.cmd.error_count = 0
        self.cmd.check_allocation_pools_pairing(filedata, pools)
        self.assertEqual(1, self.cmd.error_count)

    def test_allocation_pools_pairing_invalid_cidr(self):
        filedata = {
            'InternalApiNetCidr': '172.17.0.298/24',
            'InternalApiAllocationPools': [
                {'start': '172.17.0.10', 'end': '172.17.0.200'}],
        }
        pools = {
            'InternalApiAllocationPools': [
                {'start': '172.17.0.10', 'end': '172.17.0.200'}],
        }
        self.cmd.error_count = 0
        self.cmd.check_allocation_pools_pairing(filedata, pools)
        self.assertEqual(1, self.cmd.error_count)

    def test_allocation_pools_pairing_invalid_range(self):
        filedata = {
            'InternalApiNetCidr': '172.17.0.0/24',
            'InternalApiAllocationPools': [
                {'start': '172.17.0.10', 'end': '172.17.0.287'}],
        }
        pools = {
            'InternalApiAllocationPools': [
                {'start': '172.17.0.10', 'end': '172.17.0.287'}],
        }
        self.cmd.error_count = 0
        self.cmd.check_allocation_pools_pairing(filedata, pools)
        self.assertEqual(1, self.cmd.error_count)

    def test_nic_nonexistent_path(self):
        self.cmd.error_count = 0
        self.cmd.NIC_validate('OS::TripleO::Controller::Net::SoftwareConfig',
                              'this file that not exist')
        self.assertEqual(1, self.cmd.error_count)

    def test_nic_valid_file(self):
        bridges = [{
            'type': 'ovs_bridge',
            'name': 'br-storage',
            'members': [
                {'type': 'interface', 'name': 'eth0'},
                {'type': 'interface', 'name': 'eth1'},
                {'type': 'ovs_bond', 'name': 'bond1'}
            ],
        }]
        tmp = self.temporary_nic_config_file(bridges)
        self.cmd.error_count = 0
        self.cmd.NIC_validate(
            'OS::TripleO::Controller::Net::SoftwareConfig', tmp)
        os.unlink(tmp)
        self.assertEqual(0, self.cmd.error_count)

    def test_nic_no_bond_too_many_interfaces(self):
        bridges = [{
            'type': 'ovs_bridge',
            'name': 'br-storage',
            'members': [
                {'type': 'interface', 'name': 'eth0'},
                {'type': 'interface', 'name': 'eth1'},
            ],
        }]
        tmp = self.temporary_nic_config_file(bridges)
        self.cmd.error_count = 0
        self.cmd.NIC_validate(
            'OS::TripleO::Controller::Net::SoftwareConfig', tmp)
        os.unlink(tmp)
        self.assertEqual(1, self.cmd.error_count)

    def test_nic_two_bonds(self):
        bridges = [{
            'type': 'ovs_bridge',
            'name': 'br-storage',
            'members': [
                {'type': 'interface', 'name': 'eth0'},
                {'type': 'interface', 'name': 'eth1'},
                {'type': 'ovs_bond', 'name': 'bond1'},
                {'type': 'ovs_bond', 'name': 'bond2'},
            ],
        }]
        tmp = self.temporary_nic_config_file(bridges)
        self.cmd.error_count = 0
        self.cmd.NIC_validate(
            'OS::TripleO::Controller::Net::SoftwareConfig', tmp)
        os.unlink(tmp)
        self.assertEqual(1, self.cmd.error_count)

    def test_command(self):
        """Testing the command with a minimal file that will fail"""
        with tempfile.NamedTemporaryFile('wt') as net_file:
                net_file.write(EMPTY_NETENV)
                net_file.flush()

                arglist = ['--file', net_file.name]
                verifylist = [
                    ('netenv', net_file.name),
                ]

                parsed_args = self.check_parser(self.cmd, arglist, verifylist)
                # Validating a minimal file shouldn't raise errors.
                self.cmd.take_action(parsed_args)
