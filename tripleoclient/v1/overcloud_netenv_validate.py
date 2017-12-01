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
from __future__ import print_function

import itertools
import logging
import os

import ipaddress
from osc_lib.i18n import _
import six
import yaml

from tripleoclient import command


class ValidateOvercloudNetenv(command.Command):
    """Validate the network environment file."""

    auth_required = False
    log = logging.getLogger(__name__ + ".ValidateOvercloudNetworkEnvironment")

    def get_parser(self, prog_name):
        parser = super(ValidateOvercloudNetenv, self).get_parser(prog_name)
        parser.add_argument(
            '-f', '--file', dest='netenv',
            help=_("Path to the network environment file"),
            default='network-environment.yaml')
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        with open(parsed_args.netenv, 'r') as net_file:
            network_data = yaml.safe_load(net_file)

        cidrinfo = {}
        poolsinfo = {}
        vlaninfo = {}

        self.error_count = 0

        for item in network_data['resource_registry']:
            if item.endswith("Net::SoftwareConfig"):
                data = network_data['resource_registry'][item]
                self.log.info('Validating %s', data)
                data_path = os.path.join(os.path.dirname(parsed_args.netenv),
                                         data)
                self.NIC_validate(item, data_path)

        for item in network_data['parameter_defaults']:
            data = network_data['parameter_defaults'][item]

            if item.endswith('NetCidr'):
                cidrinfo[item] = data
            elif item.endswith('AllocationPools'):
                poolsinfo[item] = data
            elif item.endswith('NetworkVlanID'):
                vlaninfo[item] = data
            elif item == 'ExternalInterfaceDefaultRoute':
                pass
            elif item == 'BondInterfaceOvsOptions':
                pass

        self.check_cidr_overlap(cidrinfo.values())
        self.check_allocation_pools_pairing(network_data['parameter_defaults'],
                                            poolsinfo)
        self.check_vlan_ids(vlaninfo)

        if self.error_count > 0:
            print('\nFAILED Validation with %i error(s)' % self.error_count)
        else:
            print('SUCCESSFUL Validation with %i error(s)' % self.error_count)

    def check_cidr_overlap(self, networks):
        objs = []
        for x in networks:
            try:
                objs += [ipaddress.ip_network(six.u(x))]
            except ValueError:
                self.log.error('Invalid address: %s', x)
                self.error_count += 1

        for net1, net2 in itertools.combinations(objs, 2):
            if (net1.overlaps(net2)):
                self.log.error(
                    'Overlapping networks detected {} {}'.format(net1, net2))
                self.error_count += 1

    def check_allocation_pools_pairing(self, filedata, pools):
        for poolitem in pools:
            pooldata = filedata[poolitem]

            self.log.info('Checking allocation pool {}'.format(poolitem))

            pool_objs = []
            for pool in pooldata:
                try:
                    ip_start = ipaddress.ip_address(
                        six.u(pool['start']))
                except ValueError:
                    self.log.error('Invalid address: %s' % ip_start)
                    self.error_count += 1
                    ip_start = None
                try:
                    ip_end = ipaddress.ip_address(six.u(pool['end']))
                except ValueError:
                    self.log.error('Invalid address: %s' % ip_start)
                    self.error_count += 1
                    ip_end = None
                if (ip_start is None) or (ip_end is None):
                    continue
                try:
                    pool_objs.append(list(
                        ipaddress.summarize_address_range(ip_start, ip_end)))
                except Exception:
                    self.log.error('Invalid address pool: %s, %s' %
                                   (ip_start, ip_end))
                    self.error_count += 1

            subnet_item = poolitem.split('AllocationPools')[0] + 'NetCidr'
            try:
                subnet_obj = ipaddress.ip_network(
                    six.u(filedata[subnet_item]))
            except ValueError:
                self.log.error('Invalid address: %s', subnet_item)
                self.error_count += 1
                continue

            for ranges in pool_objs:
                for range in ranges:
                    if not subnet_obj.overlaps(range):
                        self.log.error(
                            'Allocation pool {} {} outside of subnet {}: {}'
                            .format(poolitem, pooldata, subnet_item,
                                    subnet_obj))
                        self.error_count += 1
                        break

    def check_vlan_ids(self, vlans):
        invertdict = {}
        for k, v in six.iteritems(vlans):
            self.log.info('Checking Vlan ID {}'.format(k))
            if v not in invertdict:
                invertdict[v] = k
            else:
                self.log.error('Vlan ID {} ({}) already exists in {}'.format(
                    v, k, invertdict[v]))
                self.error_count += 1

    def NIC_validate(self, resource, path):
        try:
            with open(path, 'r') as nic_file:
                nic_data = yaml.safe_load(nic_file)
        except IOError:
            self.log.error(
                'The resource "%s" reference file does not exist: "%s"',
                resource, path)
            self.error_count += 1
            return

        # Look though every resources bridges and make sure there is only a
        # single bond per bridge and only 1 interface per bridge if there are
        # no bonds.
        for item in nic_data['resources']:
            bridges = nic_data['resources'][item]['properties']['config'][
                'os_net_config']['network_config']
            for bridge in bridges:
                if bridge['type'] == 'ovs_bridge':
                    bond_count = 0
                    interface_count = 0
                    for bond in bridge['members']:
                        if bond['type'] == 'ovs_bond':
                            bond_count += 1
                        if bond['type'] == 'interface':
                            interface_count += 1
                    if bond_count == 0:
                        # Logging could be better if we knew the bridge name.
                        # Since it's passed as a paramter we would need to
                        # catch it
                        self.log.debug(
                            'There are 0 bonds for bridge %s of '
                            'resource %s in %s',
                            bridge['name'], item, path)
                    if bond_count == 1:
                        self.log.debug(
                            'There is 1 bond for bridge %s of '
                            'resource %s in %s',
                            bridge['name'], item, path)
                    if bond_count == 2:
                        self.log.error(
                            'Invalid bonding: There are 2 bonds for bridge %s '
                            'of resource %s in %s',
                            bridge['name'], item, path)
                        self.error_count += 1
                    if bond_count == 0 and interface_count > 1:
                        self.log.error(
                            'Invalid interface: When not using a bond, there '
                            'can only be 1 interface for bridge %s of resource'
                            '%s in %s',
                            bridge['name'], item, path)
                        self.error_count += 1
