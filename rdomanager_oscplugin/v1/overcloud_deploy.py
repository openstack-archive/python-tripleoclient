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

import logging
import os

from cliff import command


TRIPLEO_HEAT_TEMPLATES = "/usr/share/openstack-tripleo-heat-templates/"
OVERCLOUD_YAML_PATH = os.path.join(TRIPLEO_HEAT_TEMPLATES,
                                   "overcloud-without-mergepy.yaml")
RESOURCE_REGISTRY_PATH = os.path.join(
    TRIPLEO_HEAT_TEMPLATES, "overcloud-resource-registry-puppet.yaml")

PARAMETERS = {
    'AdminPassword': None,
    'AdminToken': None,
    'CeilometerPassword': None,
    'CeilometerMeteringSecret': None,
    'CinderPassword': None,
    'CinderISCSIHelper': 'lioadm',
    'CloudName': 'overcloud',
    'ExtraConfig': '{}',
    'GlancePassword': None,
    'HeatPassword': None,
    'NeutronControlPlaneID': None,
    'NeutronDnsmasqOptions': 'dhcp-option-force=26,1400',
    'NeutronPassword': None,
    'NeutronPublicInterface': 'nic1',
    'NeutronFlatNetworks': 'datacentre',
    'HypervisorNeutronPhysicalBridge': 'br-ex',
    'NeutronBridgeMappings': 'datacentre:br-ex',
    'HypervisorNeutronPublicInterface': 'nic1',
    'NovaComputeLibvirtType': 'qemu',
    'NovaPassword': None,
    'SwiftHashSuffix': None,
    'SwiftPassword': None,
    'NeutronNetworkType': 'gre',
    'NeutronTunnelTypes': 'gre',
    'SnmpdReadonlyUserPassword': None,
    'OvercloudControlFlavor': 'baremetal',
    'OvercloudComputeFlavor': 'baremetal',
    'OvercloudBlockStorageFlavor': 'baremetal',
    'OvercloudSwiftStorageFlavor': 'baremetal',
    'OvercloudCephStorageFlavor': 'baremetal',
    'NtpServer': '',
    'controllerImage': 'overcloud-full',
    'NovaImage': 'overcloud-full',
    'BlockStorageImage': 'overcloud-full',
    'SwiftStorageImage': 'overcloud-full',
    'CephStorageImage': 'overcloud-full',
    'Debug': 'True',
}


class DeployOvercloud(command.Command):
    """Deploy Overcloud"""

    log = logging.getLogger(__name__ + ".DeployOvercloud")

    def get_parser(self, prog_name):
        parser = super(DeployOvercloud, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
