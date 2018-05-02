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


from oslo_config import cfg
from tripleoclient.config.standalone import StandaloneConfig

# Control plane network name
SUBNETS_DEFAULT = ['ctlplane-subnet']

# Deprecated options
_deprecated_opt_network_gateway = [cfg.DeprecatedOpt(
    'network_gateway', group='DEFAULT')]
_deprecated_opt_network_cidr = [cfg.DeprecatedOpt(
    'network_cidr', group='DEFAULT')]
_deprecated_opt_dhcp_start = [cfg.DeprecatedOpt(
    'dhcp_start', group='DEFAULT')]
_deprecated_opt_dhcp_end = [cfg.DeprecatedOpt('dhcp_end', group='DEFAULT')]
_deprecated_opt_inspection_iprange = [cfg.DeprecatedOpt(
    'inspection_iprange', group='DEFAULT')]


class UndercloudConfig(StandaloneConfig):
    def get_undercloud_service_opts(self):
        return super(UndercloudConfig, self).get_enable_service_opts(
            cinder=False,
            ironic=True,
            ironic_inspector=True,
            mistral=True,
            novajoin=False,
            tempest=True,
            telemetry=False,
            tripleo_ui=True,
            validations=True,
            zaqar=True)

    def get_base_opts(self):
        _base_opts = super(UndercloudConfig, self).get_base_opts()
        _opts = [
            cfg.StrOpt('undercloud_hostname',
                       help=(
                           'Fully qualified hostname (including domain) to '
                           'set on the Undercloud. If left unset, the current '
                           'hostname will be used, but the user is '
                           'responsible for configuring all system hostname '
                           'settings appropriately.  If set, the undercloud '
                           'install will configure all system hostname '
                           'settings.'),
                       ),
            cfg.StrOpt('local_ip',
                       default='192.168.24.1/24',
                       help=(
                           'IP information for the interface on the '
                           'Undercloud that will be handling the PXE boots '
                           'and DHCP for Overcloud instances.  The IP portion '
                           'of the value will be assigned to the network '
                           'interface defined by local_interface, with the '
                           'netmask defined by the prefix portion of the '
                           'value.')
                       ),
            cfg.StrOpt('undercloud_public_host',
                       deprecated_name='undercloud_public_vip',
                       default='192.168.24.2',
                       help=('Virtual IP or DNS address to use for the public '
                             'endpoints of Undercloud services. Only used '
                             'with SSL.')
                       ),
            cfg.StrOpt('undercloud_admin_host',
                       deprecated_name='undercloud_admin_vip',
                       default='192.168.24.3',
                       help=('Virtual IP or DNS address to use for the admin '
                             'endpoints of Undercloud services. Only used '
                             'with SSL.')
                       ),
            cfg.ListOpt('undercloud_nameservers',
                        default=[],
                        help=(
                            'DNS nameserver(s) to use for the undercloud '
                            'node.'),
                        ),
            cfg.ListOpt('undercloud_ntp_servers',
                        default=[],
                        help=('List of ntp servers to use.')),
            cfg.StrOpt('overcloud_domain_name',
                       default='localdomain',
                       help=(
                           'DNS domain name to use when deploying the '
                           'overcloud. The overcloud parameter "CloudDomain" '
                           'must be set to a matching value.')
                       ),
            cfg.ListOpt('subnets',
                        default=SUBNETS_DEFAULT,
                        help=('List of routed network subnets for '
                              'provisioning and introspection. Comma '
                              'separated list of names/tags. For each network '
                              'a section/group needs to be added to the '
                              'configuration file with these parameters set: '
                              'cidr, dhcp_start, dhcp_end, '
                              'inspection_iprange, gateway and '
                              'masquerade_network.'
                              '\n\n'
                              'Example:\n\n'
                              'subnets = subnet1,subnet2\n'
                              '\n'
                              'An example section/group in config file:\n'
                              '\n'
                              '[subnet1]\n'
                              'cidr = 192.168.10.0/24\n'
                              'dhcp_start = 192.168.10.100\n'
                              'dhcp_end = 192.168.10.200\n'
                              'inspection_iprange = 192.168.10.20,'
                              '192.168.10.90\n'
                              'gateway = 192.168.10.254\n'
                              'masquerade = True'
                              '\n'
                              '[subnet2]\n'
                              '. . .\n')),
            cfg.StrOpt('local_subnet',
                       default=SUBNETS_DEFAULT[0],
                       help=(
                           'Name of the local subnet, where the PXE boot and '
                           'DHCP interfaces for overcloud instances is '
                           'located. The IP address of the '
                           'local_ip/local_interface should reside '
                           'in this subnet.')),
            cfg.StrOpt('undercloud_service_certificate',
                       default='',
                       help=(
                           'Certificate file to use for OpenStack service SSL '
                           'connections.  Setting this enables SSL for the '
                           'OpenStack API endpoints, leaving it unset '
                           'disables SSL.')
                       ),
            cfg.BoolOpt('generate_service_certificate',
                        default=True,
                        help=(
                            'When set to True, an SSL certificate will be '
                            'generated as part of the undercloud install and '
                            'this certificate will be used in place of the '
                            'value for undercloud_service_certificate.  The '
                            'resulting certificate will be written to '
                            '/etc/pki/tls/certs/'
                            'undercloud-[undercloud_public_host].pem.  This '
                            'certificate is signed by CA selected by the '
                            '"certificate_generation_ca" option.')
                        ),
            cfg.StrOpt('certificate_generation_ca',
                       default='local',
                       help=('The certmonger nickname of the CA from which '
                             'the certificate will be requested. This is used '
                             'only if the generate_service_certificate option '
                             'is set. Note that if the "local" CA is selected '
                             'the certmonger\'s local CA certificate will be '
                             'extracted to /etc/pki/ca-trust/source/anchors/'
                             'cm-local-ca.pem and subsequently added to the '
                             'trust chain.')

                       ),
            cfg.StrOpt('service_principal',
                       default='',
                       help=(
                           'The kerberos principal for the service that will '
                           'use the certificate. This is only needed if your '
                           'CA requires a kerberos principal. e.g. with '
                           'FreeIPA.')
                       ),
            cfg.StrOpt('local_interface',
                       default='eth1',
                       help=('Network interface on the Undercloud that will '
                             'be handling the PXE boots and DHCP for '
                             'Overcloud instances.')
                       ),
            cfg.IntOpt('local_mtu',
                       default=1500,
                       help=('MTU to use for the local_interface.')
                       ),

            cfg.StrOpt('inspection_interface',
                       default='br-ctlplane',
                       deprecated_name='discovery_interface',
                       help=(
                           'Network interface on which inspection dnsmasq '
                           'will listen.  If in doubt, use the default value.')
                       ),
            cfg.BoolOpt('inspection_extras',
                        default=True,
                        help=(
                            'Whether to enable extra hardware collection '
                            'during the inspection process. Requires '
                            'python-hardware or python-hardware-detect '
                            'package on the introspection image.')),
            cfg.BoolOpt('inspection_runbench',
                        default=False,
                        deprecated_name='discovery_runbench',
                        help=(
                            'Whether to run benchmarks when inspecting '
                            'nodes. Requires inspection_extras set to True.')
                        ),
            cfg.BoolOpt('enable_node_discovery',
                        default=False,
                        help=(
                            'Makes ironic-inspector enroll any unknown node '
                            'that PXE-boots introspection ramdisk in Ironic. '
                            'By default, the "fake" driver is used for new '
                            'nodes (it is automatically enabled when this '
                            'option is set to True). Set '
                            'discovery_default_driver to override. '
                            'Introspection rules can also be used to specify '
                            'driver information for newly enrolled nodes.')
                        ),
            cfg.StrOpt('discovery_default_driver',
                       default='ipmi',
                       help=(
                           'The default driver or hardware type to use for '
                           'newly discovered nodes (requires '
                           'enable_node_discovery set to True). It is '
                           'automatically added to enabled_hardware_types.')
                       ),
            cfg.BoolOpt('undercloud_debug',
                        default=True,
                        help=(
                            'Whether to enable the debug log level for '
                            'Undercloud OpenStack services.')
                        ),
            cfg.BoolOpt('undercloud_update_packages',
                        default=False,
                        help=(
                            'Whether to update packages during the Undercloud '
                            'install. This is a no-op for containerized '
                            'undercloud.')
                        ),
            cfg.BoolOpt('enable_container_images_build',
                        default=True,
                        help=(
                            'Whether to enable docker container images to be '
                            'build on the undercloud.')
                        ),
            cfg.StrOpt('ipa_otp',
                       default='',
                       help=(
                           'One Time Password to register Undercloud node '
                           'with an IPA server.  Required when '
                           'enable_novajoin = True.')
                       ),
            cfg.BoolOpt('ipxe_enabled',
                        default=True,
                        help=('Whether to use iPXE for deploy and '
                              'inspection.'),
                        deprecated_name='ipxe_deploy',
                        ),
            cfg.IntOpt('scheduler_max_attempts',
                       default=30, min=1,
                       help=(
                           'Maximum number of attempts the scheduler will '
                           'make when deploying the instance. You should keep '
                           'it greater or equal to the number of bare metal '
                           'nodes you expect to deploy at once to work around '
                           'potential race condition when scheduling.')),
            cfg.BoolOpt('clean_nodes',
                        default=False,
                        help=(
                            'Whether to clean overcloud nodes (wipe the hard '
                            'drive) between deployments and after the '
                            'introspection.')),
            cfg.ListOpt('enabled_hardware_types',
                        default=['ipmi', 'redfish', 'ilo', 'idrac'],
                        help=('List of enabled bare metal hardware types '
                              '(next generation drivers).')),
            cfg.BoolOpt('enable_routed_networks',
                        default=False,
                        help=('Enable support for routed ctlplane networks.')),
            cfg.BoolOpt('enable_swift_encryption',
                        default=False,
                        help=(
                            'Whether to enable Swift encryption at-rest or '
                            'not.'
                        )),
        ]
        return self.sort_opts(_base_opts + _opts)

    def get_opts(self):
        _base_opts = self.get_base_opts()
        _service_opts = self.get_undercloud_service_opts()
        return self.sort_opts(_base_opts + _service_opts)

    def get_subnet_opts(self):
        _subnets_opts = [
            cfg.StrOpt('cidr',
                       default='192.168.24.0/24',
                       deprecated_opts=_deprecated_opt_network_cidr,
                       help=('Network CIDR for the Neutron-managed subnet for '
                             'Overcloud instances.')),
            cfg.StrOpt('dhcp_start',
                       default='192.168.24.5',
                       deprecated_opts=_deprecated_opt_dhcp_start,
                       help=(
                           'Start of DHCP allocation range for PXE and DHCP '
                           'of Overcloud instances on this network.')),
            cfg.StrOpt('dhcp_end',
                       default='192.168.24.24',
                       deprecated_opts=_deprecated_opt_dhcp_end,
                       help=('End of DHCP allocation range for PXE and DHCP '
                             'of Overcloud instances on this network.')),
            cfg.StrOpt('inspection_iprange',
                       default='192.168.24.100,192.168.24.120',
                       deprecated_opts=_deprecated_opt_inspection_iprange,
                       help=(
                           'Temporary IP range that will be given to nodes on '
                           'this network during the inspection process. '
                           'Should not overlap with the range defined by '
                           'dhcp_start and dhcp_end, but should be in the '
                           'same ip subnet.'
                       )),
            cfg.StrOpt('gateway',
                       default='192.168.24.1',
                       deprecated_opts=_deprecated_opt_network_gateway,
                       help=(
                           'Network gateway for the Neutron-managed network '
                           'for Overcloud instances on this network.')),
            cfg.BoolOpt('masquerade',
                        default=False,
                        help=(
                            'The network will be masqueraded for external '
                            'access.')),
        ]
        return self.sort_opts(_subnets_opts)
