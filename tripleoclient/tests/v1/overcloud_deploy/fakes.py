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

import mock

from tripleoclient.tests import fakes


FAKE_STACK = {
    'parameters': {
        'ControllerCount': 1,
        'ComputeCount': 1,
        'ObjectStorageCount': 0,
        'BlockStorageCount': 0,
        'CephStorageCount': 0,
        'DeployIdentifier': '',
    },
    'stack_name': 'overcloud',
    'stack_status': "CREATE_COMPLETE",
    'outputs': [{
        'output_key': 'KeystoneURL',
        'output_value': 'http://0.0.0.0:8000',
    }, {
        'output_key': 'EndpointMap',
        'output_value': {
            'KeystoneAdmin': {
                'host': '0.0.0.0',
                'uri': 'http://0.0.0.0:35357',
                'port': 35357,
            },
            'KeystoneInternal': {
                'host': '0.0.0.0',
                'uri': 'http://0.0.0.0:5000',
                'port': 5000,
            },
            'KeystonePublic': {
                'host': '0.0.0.0',
                'uri': 'http://0.0.0.0:5000',
                'port': 5000,
            },
            'NovaAdmin': {
                'host': '0.0.0.0',
                'uri': 'http://0.0.0.0:5000',
                'port': 8774,
            },
            'NovaInternal': {
                'host': '0.0.0.0',
                'uri': 'http://0.0.0.0:5000',
                'port': 8774,
            },
            'NovaPublic': {
                'host': '0.0.0.0',
                'uri': 'https://0.0.0.0:8774',
                'port': 8774,
            },
        }
    }]
}


def create_to_dict_mock(**kwargs):
    mock_with_to_dict = mock.Mock()
    mock_with_to_dict.configure_mock(**kwargs)
    mock_with_to_dict.to_dict.return_value = kwargs
    return mock_with_to_dict


def create_tht_stack(**kwargs):
    stack = FAKE_STACK.copy()
    stack.update(kwargs)
    return create_to_dict_mock(**stack)


def create_env_with_ntp(**kwargs):
    env = {
        'parameter_defaults': {
            'CinderEnableRbdBackend': True,
            'NtpServer': 'ntp.local',
        },
    }
    env.update(kwargs)
    return env


def create_env(**kwargs):
    env = {
        'parameter_defaults': {
            'CinderEnableRbdBackend': True,
        },
    }
    env.update(kwargs)
    return env


class TestDeployOvercloud(fakes.FakePlaybookExecution):

    def setUp(self):
        super(TestDeployOvercloud, self).setUp(ansible_mock=False)


class FakeNeutronNetwork(dict):
    def __init__(self, **attrs):
        NETWORK_ATTRS = ['id',
                         'name',
                         'status',
                         'tenant_id',
                         'is_admin_state_up',
                         'mtu',
                         'segments',
                         'is_shared',
                         'subnet_ids',
                         'provider:network_type',
                         'provider:physical_network',
                         'provider:segmentation_id',
                         'router:external',
                         'availability_zones',
                         'availability_zone_hints',
                         'is_default',
                         'tags']

        raw = dict.fromkeys(NETWORK_ATTRS)
        raw.update(attrs)
        raw.update({
            'provider_physical_network': attrs.get(
                'provider:physical_network', None),
            'provider_network_type': attrs.get(
                'provider:network_type', None),
            'provider_segmentation_id': attrs.get(
                'provider:segmentation_id', None)
        })
        super(FakeNeutronNetwork, self).__init__(raw)

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)

    def __setattr__(self, key, value):
        if key in self:
            self[key] = value
        else:
            raise AttributeError(key)


class FakeNeutronSubnet(dict):
    def __init__(self, **attrs):
        SUBNET_ATTRS = ['id',
                        'name',
                        'network_id',
                        'cidr',
                        'tenant_id',
                        'is_dhcp_enabled',
                        'dns_nameservers',
                        'allocation_pools',
                        'host_routes',
                        'ip_version',
                        'gateway_ip',
                        'ipv6_address_mode',
                        'ipv6_ra_mode',
                        'subnetpool_id',
                        'segment_id',
                        'tags']

        raw = dict.fromkeys(SUBNET_ATTRS)
        raw.update(attrs)
        super(FakeNeutronSubnet, self).__init__(raw)

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)

    def __setattr__(self, key, value):
        if key in self:
            self[key] = value
        else:
            raise AttributeError(key)
