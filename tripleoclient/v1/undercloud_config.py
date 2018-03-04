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

"""Plugin action implementation"""

import copy
import logging
import netaddr
import os
import yaml

from cryptography import x509

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from oslo_config import cfg
from tripleo_common.image import kolla_builder
from tripleoclient import constants
from tripleoclient import utils

from tripleoclient.v1 import undercloud_preflight


PARAMETER_MAPPING = {
    'inspection_interface': 'IronicInspectorInterface',
    'enabled_drivers': 'IronicEnabledDrivers',
    'undercloud_debug': 'Debug',
    'ipxe_enabled': 'IronicInspectorIPXEEnabled',
    'certificate_generation_ca': 'CertmongerCA',
    'undercloud_public_host': 'CloudName',
    'scheduler_max_attempts': 'NovaSchedulerMaxAttempts',
    'local_mtu': 'UndercloudLocalMtu',
    'clean_nodes': 'IronicAutomatedClean',
    'local_subnet': 'UndercloudCtlplaneLocalSubnet',
    'enable_routed_networks': 'UndercloudEnableRoutedNetworks'
}

SUBNET_PARAMETER_MAPPING = {
    'cidr': 'NetworkCidr',
    'gateway': 'NetworkGateway',
    'dhcp_start': 'DhcpRangeStart',
    'dhcp_end': 'DhcpRangeEnd',
}

THT_HOME = os.environ.get('THT_HOME',
                          "/usr/share/openstack-tripleo-heat-templates/")

TELEMETRY_DOCKER_ENV_YAML = [
    'environments/services/undercloud-gnocchi.yaml',
    'environments/services/undercloud-aodh.yaml',
    'environments/services/undercloud-panko.yaml',
    'environments/services/undercloud-ceilometer.yaml']

# Control plane network name
SUBNETS_DEFAULT = ['ctlplane-subnet']


class Paths(object):
    @property
    def CONF_PATH(self):
        return os.path.expanduser('~/undercloud.conf')


CONF = cfg.CONF
PATHS = Paths()

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

# When adding new options to the lists below, make sure to regenerate the
# sample config by running "tox -e genconfig" in the project root.
ci_defaults = kolla_builder.container_images_prepare_defaults()
_opts = [
    cfg.StrOpt('output_dir',
               default=constants.UNDERCLOUD_OUTPUT_DIR,
               help=('Directory to output state, processed heat templates, '
                     'ansible deployment files.'),
               ),
    cfg.BoolOpt('cleanup',
                default=False,
                help=('Cleanup temporary files'),
                ),
    cfg.StrOpt('deployment_user',
               help=('User used to run openstack undercloud install command '
                     'which will be used to add the user to the docker group, '
                     'required to upload containers'),
               ),
    cfg.StrOpt('undercloud_hostname',
               help=('Fully qualified hostname (including domain) to set on '
                     'the Undercloud. If left unset, the '
                     'current hostname will be used, but the user is '
                     'responsible for configuring all system hostname '
                     'settings appropriately.  If set, the undercloud install '
                     'will configure all system hostname settings.'),
               ),
    cfg.StrOpt('local_ip',
               default='192.168.24.1/24',
               help=('IP information for the interface on the Undercloud '
                     'that will be handling the PXE boots and DHCP for '
                     'Overcloud instances.  The IP portion of the value will '
                     'be assigned to the network interface defined by '
                     'local_interface, with the netmask defined by the '
                     'prefix portion of the value.')
               ),
    cfg.StrOpt('undercloud_public_host',
               deprecated_name='undercloud_public_vip',
               default='192.168.24.2',
               help=('Virtual IP or DNS address to use for the public '
                     'endpoints of Undercloud services. Only used with SSL.')
               ),
    cfg.StrOpt('undercloud_admin_host',
               deprecated_name='undercloud_admin_vip',
               default='192.168.24.3',
               help=('Virtual IP or DNS address to use for the admin '
                     'endpoints of Undercloud services. Only used with SSL.')
               ),
    cfg.ListOpt('undercloud_nameservers',
                default=[],
                help=('DNS nameserver(s) to use for the undercloud node.'),
                ),
    cfg.ListOpt('undercloud_ntp_servers',
                default=[],
                help=('List of ntp servers to use.')),
    cfg.StrOpt('overcloud_domain_name',
               default='localdomain',
               help=('DNS domain name to use when deploying the overcloud. '
                     'The overcloud parameter "CloudDomain" must be set to a '
                     'matching value.')
               ),
    cfg.ListOpt('subnets',
                default=SUBNETS_DEFAULT,
                help=('List of routed network subnets for provisioning '
                      'and introspection. Comma separated list of names/tags. '
                      'For each network a section/group needs to be added to '
                      'the configuration file with these parameters set: '
                      'cidr, dhcp_start, dhcp_end, inspection_iprange, '
                      'gateway and masquerade_network.'
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
                      'inspection_iprange = 192.168.10.20,192.168.10.90\n'
                      'gateway = 192.168.10.254\n'
                      'masquerade = True'
                      '\n'
                      '[subnet2]\n'
                      '. . .\n')),
    cfg.StrOpt('local_subnet',
               default=SUBNETS_DEFAULT[0],
               help=('Name of the local subnet, where the PXE boot and DHCP '
                     'interfaces for overcloud instances is located. The IP '
                     'address of the local_ip/local_interface should reside '
                     'in this subnet.')),
    cfg.StrOpt('undercloud_service_certificate',
               default='',
               help=('Certificate file to use for OpenStack service SSL '
                     'connections.  Setting this enables SSL for the '
                     'OpenStack API endpoints, leaving it unset disables SSL.')
               ),
    cfg.BoolOpt('generate_service_certificate',
                default=True,
                help=('When set to True, an SSL certificate will be generated '
                      'as part of the undercloud install and this certificate '
                      'will be used in place of the value for '
                      'undercloud_service_certificate.  The resulting '
                      'certificate will be written to '
                      '/etc/pki/tls/certs/undercloud-[undercloud_public_host].'
                      'pem.  This certificate is signed by CA selected by the '
                      '"certificate_generation_ca" option.')
                ),
    cfg.StrOpt('certificate_generation_ca',
               default='local',
               help=('The certmonger nickname of the CA from which the '
                     'certificate will be requested. This is used only if '
                     'the generate_service_certificate option is set. '
                     'Note that if the "local" CA is selected the '
                     'certmonger\'s local CA certificate will be extracted to '
                     '/etc/pki/ca-trust/source/anchors/cm-local-ca.pem and '
                     'subsequently added to the trust chain.')

               ),
    cfg.StrOpt('service_principal',
               default='',
               help=('The kerberos principal for the service that will use '
                     'the certificate. This is only needed if your CA '
                     'requires a kerberos principal. e.g. with FreeIPA.')
               ),
    cfg.StrOpt('local_interface',
               default='eth1',
               help=('Network interface on the Undercloud that will be '
                     'handling the PXE boots and DHCP for Overcloud '
                     'instances.')
               ),
    cfg.IntOpt('local_mtu',
               default=1500,
               help=('MTU to use for the local_interface.')
               ),
    cfg.StrOpt('hieradata_override',
               default='',
               help=('Path to hieradata override file. If set, the file will '
                     'be copied under /etc/puppet/hieradata and set as the '
                     'first file in the hiera hierarchy. This can be used '
                     'to custom configure services beyond what '
                     'undercloud.conf provides')
               ),
    cfg.StrOpt('net_config_override',
               default='',
               help=('Path to network config override template. If set, this '
                     'template will be used to configure the networking via '
                     'os-net-config. Must be in json format. '
                     'Templated tags can be used within the '
                     'template, see '
                     'instack-undercloud/elements/undercloud-stack-config/'
                     'net-config.json.template for example tags')
               ),
    cfg.StrOpt('inspection_interface',
               default='br-ctlplane',
               deprecated_name='discovery_interface',
               help=('Network interface on which inspection dnsmasq will '
                     'listen.  If in doubt, use the default value.')
               ),
    cfg.BoolOpt('inspection_extras',
                default=True,
                help=('Whether to enable extra hardware collection during '
                      'the inspection process. Requires python-hardware or '
                      'python-hardware-detect package on the introspection '
                      'image.')),
    cfg.BoolOpt('inspection_runbench',
                default=False,
                deprecated_name='discovery_runbench',
                help=('Whether to run benchmarks when inspecting nodes. '
                      'Requires inspection_extras set to True.')
                ),
    cfg.BoolOpt('enable_node_discovery',
                default=False,
                help=('Makes ironic-inspector enroll any unknown node that '
                      'PXE-boots introspection ramdisk in Ironic. By default, '
                      'the "fake" driver is used for new nodes (it is '
                      'automatically enabled when this option is set to True).'
                      ' Set discovery_default_driver to override. '
                      'Introspection rules can also be used to specify driver '
                      'information for newly enrolled nodes.')
                ),
    cfg.StrOpt('discovery_default_driver',
               default='ipmi',
               help=('The default driver or hardware type to use for newly '
                     'discovered nodes (requires enable_node_discovery set to '
                     'True). It is automatically added to enabled_drivers '
                     'or enabled_hardware_types accordingly.')
               ),
    cfg.BoolOpt('undercloud_debug',
                default=True,
                help=('Whether to enable the debug log level for Undercloud '
                      'OpenStack services.')
                ),
    cfg.BoolOpt('undercloud_update_packages',
                default=False,
                help=('Whether to update packages during the Undercloud '
                      'install. This is a no-op for containerized undercloud.')
                ),
    cfg.BoolOpt('enable_tempest',
                default=True,
                help=('Whether to install Tempest in the Undercloud.'
                      'This is a no-op for containerized undercloud.')
                ),
    cfg.BoolOpt('enable_telemetry',
                default=False,
                help=('Whether to install Telemetry services '
                      '(ceilometer, gnocchi, aodh, panko ) in the Undercloud.')
                ),
    cfg.BoolOpt('enable_ui',
                default=True,
                help=('Whether to install the TripleO UI.')
                ),
    cfg.BoolOpt('enable_validations',
                default=True,
                help=('Whether to install requirements to run the TripleO '
                      'validations.')
                ),
    cfg.BoolOpt('enable_cinder',
                default=False,
                help=('Whether to install the Volume service. It is not '
                      'currently used in the undercloud.')),
    cfg.BoolOpt('enable_novajoin',
                default=False,
                help=('Whether to install novajoin metadata service in '
                      'the Undercloud.')
                ),
    cfg.BoolOpt('enable_container_images_build',
                default=True,
                help=('Whether to enable docker container images to be build '
                      'on the undercloud.')
                ),
    cfg.StrOpt('ipa_otp',
               default='',
               help=('One Time Password to register Undercloud node with '
                     'an IPA server.  '
                     'Required when enable_novajoin = True.')
               ),
    cfg.BoolOpt('ipxe_enabled',
                default=True,
                help=('Whether to use iPXE for deploy and inspection.'),
                deprecated_name='ipxe_deploy',
                ),
    cfg.IntOpt('scheduler_max_attempts',
               default=30, min=1,
               help=('Maximum number of attempts the scheduler will make '
                     'when deploying the instance. You should keep it '
                     'greater or equal to the number of bare metal nodes '
                     'you expect to deploy at once to work around '
                     'potential race condition when scheduling.')),
    cfg.BoolOpt('clean_nodes',
                default=False,
                help=('Whether to clean overcloud nodes (wipe the hard drive) '
                      'between deployments and after the introspection.')),
    cfg.ListOpt('enabled_drivers',
                default=['pxe_ipmitool', 'pxe_drac', 'pxe_ilo'],
                help=('List of enabled bare metal drivers.'),
                deprecated_for_removal=True,
                deprecated_reason=('Please switch to hardware types and '
                                   'the enabled_hardware_types option.')),
    cfg.ListOpt('enabled_hardware_types',
                default=['ipmi', 'redfish', 'ilo', 'idrac'],
                help=('List of enabled bare metal hardware types (next '
                      'generation drivers).')),
    cfg.StrOpt('docker_registry_mirror',
               default='',
               help=('An optional docker \'registry-mirror\' that will be'
                     'configured in /etc/docker/daemon.json.')
               ),
    cfg.ListOpt('docker_insecure_registries',
                default=[],
                help=('Used to add custom insecure registries in '
                      '/etc/sysconfig/docker.')
                ),
    cfg.StrOpt('templates',
               default='',
               help=('heat templates file to override.')
               ),
    cfg.BoolOpt('heat_native',
                default=True,
                help=('Use native heat templates.')),
    cfg.StrOpt('heat_container_image',
               default='',
               help=('URL for the heat container image to use.')
               ),
    cfg.StrOpt('container_images_file',
               default='',
               help=('Heat environment file with parameters for all required '
                     'container images. Or alternatively, parameter '
                     '"ContainerImagePrepare" to drive the required image '
                     'preparation.')),
    cfg.BoolOpt('enable_ironic',
                default=True,
                help=('Whether to enable the ironic service.')),
    cfg.BoolOpt('enable_ironic_inspector',
                default=True,
                help=('Whether to enable the ironic inspector service.')),
    cfg.BoolOpt('enable_mistral',
                default=True,
                help=('Whether to enable the mistral service.')),
    cfg.BoolOpt('enable_zaqar',
                default=True,
                help=('Whether to enable the zaqar service.')),
    cfg.ListOpt('custom_env_files',
                default=[],
                help=('List of any custom environment yaml files to use')),
    cfg.BoolOpt('enable_routed_networks',
                default=False,
                help=('Enable support for routed ctlplane networks.')),
]

# Routed subnets
_subnets_opts = [
    cfg.StrOpt('cidr',
               default='192.168.24.0/24',
               deprecated_opts=_deprecated_opt_network_cidr,
               help=('Network CIDR for the Neutron-managed subnet for '
                     'Overcloud instances.')),
    cfg.StrOpt('dhcp_start',
               default='192.168.24.5',
               deprecated_opts=_deprecated_opt_dhcp_start,
               help=('Start of DHCP allocation range for PXE and DHCP of '
                     'Overcloud instances on this network.')),
    cfg.StrOpt('dhcp_end',
               default='192.168.24.24',
               deprecated_opts=_deprecated_opt_dhcp_end,
               help=('End of DHCP allocation range for PXE and DHCP of '
                     'Overcloud instances on this network.')),
    cfg.StrOpt('inspection_iprange',
               default='192.168.24.100,192.168.24.120',
               deprecated_opts=_deprecated_opt_inspection_iprange,
               help=('Temporary IP range that will be given to nodes on this '
                     'network during the inspection process. Should not '
                     'overlap with the range defined by dhcp_start and '
                     'dhcp_end, but should be in the same ip subnet.')),
    cfg.StrOpt('gateway',
               default='192.168.24.1',
               deprecated_opts=_deprecated_opt_network_gateway,
               help=('Network gateway for the Neutron-managed network for '
                     'Overcloud instances on this network.')),
    cfg.BoolOpt('masquerade',
                default=False,
                help=('The network will be masqueraded for external access.')),
]

CONF.register_opts(_opts)


def _load_subnets_config_groups():
    for group in CONF.subnets:
        g = cfg.OptGroup(name=group, title=group)
        CONF.register_opts(_subnets_opts, group=g)


LOG = logging.getLogger(__name__ + ".undercloud_config")


def list_opts():
    return [(None, copy.deepcopy(_opts)),
            (SUBNETS_DEFAULT[0], copy.deepcopy(_subnets_opts))]


def _load_config():
    conf_params = []
    if os.path.isfile(PATHS.CONF_PATH):
        conf_params += ['--config-file', PATHS.CONF_PATH]
    else:
        LOG.warning('%s does not exist. Using defaults.' % PATHS.CONF_PATH)
    CONF(conf_params)


def _is_classic_driver(name):
    """Poor man's way to detect if something is a driver or a hardware type.

    To be removed when we remove support for classic drivers.
    """
    return (name == 'fake' or
            name.startswith('fake_') or
            name.startswith('pxe_') or
            name.startswith('agent_') or
            name.startswith('iscsi_'))


def _process_drivers_and_hardware_types(conf, env):
    """Populate the environment with ironic driver information."""
    # Ensure correct rendering of the list and uniqueness of the items
    enabled_drivers = set(conf.enabled_drivers)
    enabled_hardware_types = set(conf.enabled_hardware_types)
    if conf.enable_node_discovery:
        if _is_classic_driver(conf.discovery_default_driver):
            if conf.discovery_default_driver not in enabled_drivers:
                enabled_drivers.add(conf.discovery_default_driver)
        else:
            if conf.discovery_default_driver not in enabled_hardware_types:
                enabled_hardware_types.add(conf.discovery_default_driver)
        env['IronicInspectorEnableNodeDiscovery'] = True
        env['IronicInspectorDiscoveryDefaultDriver'] = (
            conf.discovery_default_driver)

    # In most cases power and management interfaces are called the same, so we
    # use one variable for them.
    mgmt_interfaces = {'fake', 'ipmitool'}
    # TODO(dtantsur): can we somehow avoid hardcoding hardware types here?
    for hw_type in ('redfish', 'idrac', 'ilo', 'irmc', 'staging-ovirt'):
        if hw_type in enabled_hardware_types:
            mgmt_interfaces.add(hw_type)
    for (hw_type, iface) in [('cisco-ucs-managed', 'ucsm'),
                             ('cisco-ucs-standalone', 'cimc')]:
        if hw_type in enabled_hardware_types:
            mgmt_interfaces.add(iface)

    # Two hardware types use non-default boot interfaces.
    boot_interfaces = {'pxe'}
    for hw_type in ('ilo', 'irmc'):
        if hw_type in enabled_hardware_types:
            boot_interfaces.add('%s-pxe' % hw_type)

    raid_interfaces = {'no-raid'}
    if 'idrac' in enabled_hardware_types:
        raid_interfaces.add('idrac')

    vendor_interfaces = {'no-vendor'}
    for (hw_type, iface) in [('ipmi', 'ipmitool'),
                             ('idrac', 'idrac')]:
        if hw_type in enabled_hardware_types:
            vendor_interfaces.add(iface)

    env['IronicEnabledDrivers'] = sorted(enabled_drivers)
    env['IronicEnabledHardwareTypes'] = sorted(enabled_hardware_types)

    env['IronicEnabledBootInterfaces'] = sorted(boot_interfaces)
    env['IronicEnabledManagementInterfaces'] = sorted(mgmt_interfaces)
    env['IronicEnabledRaidInterfaces'] = sorted(raid_interfaces)
    env['IronicEnabledVendorInterfaces'] = sorted(vendor_interfaces)

    # The snmp hardware type uses fake management and snmp power
    if 'snmp' in enabled_hardware_types:
        mgmt_interfaces.add('snmp')
    env['IronicEnabledPowerInterfaces'] = sorted(mgmt_interfaces)


def _process_ipa_args(conf, env):
    """Populate the environment with IPA kernal args ."""
    inspection_kernel_args = []
    if conf.undercloud_debug:
        inspection_kernel_args.append('ipa-debug=1')
    if conf.inspection_runbench:
        inspection_kernel_args.append('ipa-inspection-benchmarks=cpu,mem,disk')
    if conf.inspection_extras:
        inspection_kernel_args.append('ipa-inspection-dhcp-all-interfaces=1')
        inspection_kernel_args.append('ipa-collect-lldp=1')
        env['IronicInspectorCollectors'] = ('default,extra-hardware,'
                                            'numa-topology,logs')
    else:
        env['IronicInspectorCollectors'] = 'default,logs'
    env['IronicInspectorKernelArgs'] = ' '.join(inspection_kernel_args)


def _generate_inspection_subnets():
    env_list = []
    for subnet in CONF.subnets:
        env_dict = {}
        s = CONF.get(subnet)
        env_dict['tag'] = subnet
        env_dict['ip_range'] = s.inspection_iprange
        env_dict['netmask'] = str(netaddr.IPNetwork(s.cidr).netmask)
        env_dict['gateway'] = s.gateway
        env_list.append(env_dict)
    return env_list


def _generate_subnets_static_routes():
    env_list = []
    local_router = CONF.get(CONF.local_subnet).gateway
    for subnet in CONF.subnets:
        if subnet == str(CONF.local_subnet):
            continue
        s = CONF.get(subnet)
        env_list.append({'ip_netmask': s.cidr, 'next_hop': local_router})
    return env_list


def _generate_masquerade_networks():
    """Create input for OS::TripleO::Services::MasqueradeNetworks

    The service use parameter MasqueradeNetworks with the following
    formating:
        {'source_cidr_A': ['destination_cidr_A', 'destination_cidr_B'],
         'source_cidr_B': ['destination_cidr_A', 'destination_cidr_B']}
    """
    network_cidrs = []
    for subnet in CONF.subnets:
        s = CONF.get(subnet)
        network_cidrs.append(s.cidr)

    masqurade_networks = {}
    for subnet in CONF.subnets:
        s = CONF.get(subnet)
        if s.masquerade:
            masqurade_networks.update({s.cidr: network_cidrs})

    return masqurade_networks

# def _generate_subnets_cidr_nat_rules():
#     env_list = []
#     for subnet in CONF.subnets:
#         env_dict = {}
#         s = CONF.get(subnet)
#         env_dict['140 ' + subnet + ' cidr nat'] = {
#             'chain': 'FORWARD',
#             'destination': s.cidr
#         }
#         # NOTE(hjensas): sort_keys=True because unit test reference is static
#         env_list.append(json.dumps(env_dict, sort_keys=True)[1:-1])
#     # Whitespace after newline required for indentation in templated yaml
#     return '\n  '.join(env_list)


def prepare_undercloud_deploy(upgrade=False, no_validations=False,
                              verbose_level=1):
    """Prepare Undercloud deploy command based on undercloud.conf"""

    env_data = {}
    registry_overwrites = {}
    deploy_args = []
    _load_config()
    _load_subnets_config_groups()

    # Set the undercloud home dir parameter so that stackrc is produced in
    # the users home directory.
    env_data['UndercloudHomeDir'] = os.environ.get('HOME', '')

    for param_key, param_value in PARAMETER_MAPPING.items():
        if param_key in CONF.keys():
            env_data[param_value] = CONF[param_key]

    # Set up parameters for undercloud networking
    env_data['IronicInspectorSubnets'] = _generate_inspection_subnets()
    env_data['ControlPlaneStaticRoutes'] = _generate_subnets_static_routes()
    env_data['UndercloudCtlplaneSubnets'] = {}
    for subnet in CONF.subnets:
        s = CONF.get(subnet)
        env_data['UndercloudCtlplaneSubnets'][subnet] = {}
        for param_key, param_value in SUBNET_PARAMETER_MAPPING.items():
            env_data['UndercloudCtlplaneSubnets'][subnet].update(
                {param_value: s[param_key]})
    env_data['MasqueradeNetworks'] = _generate_masquerade_networks()
    env_data['DnsServers'] = ','.join(CONF['undercloud_nameservers'])

    # Parse the undercloud.conf options to include necessary args and
    # yaml files for undercloud deploy command

    if CONF.get('undercloud_ntp_servers', None):
        env_data['NtpServer'] = CONF['undercloud_ntp_servers'][0]

    if CONF.get('enable_validations', False) and not no_validations:
        env_data['EnableValidations'] = CONF['enable_validations']

    if CONF.get('overcloud_domain_name', None):
        env_data['NeutronDnsDomain'] = CONF['overcloud_domain_name']
        deploy_args.append('--local-domain=%s' % CONF['overcloud_domain_name'])

    # FIXME need to add admin VIP as well
    env_data['DockerInsecureRegistryAddress'] = [
        '%s:8787' % CONF['local_ip'].split('/')[0]]
    env_data['DockerInsecureRegistryAddress'].extend(
        CONF['docker_insecure_registries'])

    if CONF.get('docker_registry_mirror', None):
        env_data['DockerRegistryMirror'] = CONF['docker_registry_mirror']

    if CONF.get('local_ip', None):
        deploy_args.append('--local-ip=%s' % CONF['local_ip'])

    if CONF.get('templates', None):
        tht_templates = CONF['templates']
        deploy_args.append('--templates=%s' % tht_templates)
    else:
        tht_templates = THT_HOME
        deploy_args.append('--templates=%s' % THT_HOME)

    if upgrade:
        deploy_args += ['-e', os.path.join(
            tht_templates,
            "environments/lifecycle/undercloud-upgrade-prepare.yaml")]

    if CONF.get('heat_native', None):
        deploy_args.append('--heat-native')

    if CONF.get('heat_container_image'):
        deploy_args.append('--heat-container-image=%s'
                           % CONF['heat_container_image'])

    _container_images_config(CONF, deploy_args, env_data)

    if env_data['MasqueradeNetworks']:
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/masquerade-networks.yaml")]

    if CONF.get('enable_ironic'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/ironic.yaml")]

        # ironic-inspector can only work if ironic is enabled
        if CONF.get('enable_ironic_inspector'):
            deploy_args += ['-e', os.path.join(
                tht_templates,
                "environments/services/ironic-inspector.yaml")]

        _process_drivers_and_hardware_types(CONF, env_data)
        _process_ipa_args(CONF, env_data)

    if CONF.get('enable_mistral'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/mistral.yaml")]

    if CONF.get('enable_novajoin'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/novajoin.yaml")]
        env_data['NovajoinIpaOtp'] = CONF['ipa_otp']

    if CONF.get('enable_zaqar'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/zaqar.yaml")]

    if CONF.get('enable_telemetry'):
        for env_file in TELEMETRY_DOCKER_ENV_YAML:
            deploy_args += ['-e', os.path.join(tht_templates, env_file)]

    if CONF.get('enable_ui'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/tripleo-ui.yaml")]

    if CONF.get('enable_cinder'):
        deploy_args += ['-e', os.path.join(
            tht_templates,
            "environments/services/undercloud-cinder.yaml")]

    if CONF.get('generate_service_certificate'):
        deploy_args += ['-e', os.path.join(
            tht_templates,
            "environments/public-tls-undercloud.yaml")]
    elif CONF.get('undercloud_service_certificate'):
        enable_tls_yaml_path = os.path.join(tht_templates,
                                            "environments/ssl/enable-tls.yaml")
        env_data.update(
            _get_public_tls_parameters(
                CONF.get('undercloud_service_certificate')))
        registry_overwrites.update(
            _get_public_tls_resource_registry_overwrites(enable_tls_yaml_path))
        deploy_args += [
            '-e', os.path.join(tht_templates, 'environments/services/'
                               'undercloud-haproxy.yaml'),
            '-e', os.path.join(tht_templates, 'environments/services/'
                               'undercloud-keepalived.yaml')]
    else:
        deploy_args += ['-e', os.path.join(
            tht_templates,
            "environments/no-tls-endpoints-public-ip.yaml")]

    if (CONF.get('generate_service_certificate') or
            CONF.get('undercloud_service_certificate')):
        endpoint_environment = _get_tls_endpoint_environment(
            CONF.get('undercloud_public_host'), tht_templates)
        try:
            public_host = CONF.get('undercloud_public_host')
            netaddr.IPAddress(public_host)
            deploy_args += ['--public-virtual-ip', public_host]

            admin_host = CONF.get('undercloud_admin_host')
            netaddr.IPAddress(admin_host)
            deploy_args += ['--control-virtual-ip', admin_host]
        except netaddr.core.AddrFormatError:
            # TODO(jaosorior): We could do a reverse lookup for the hostnames
            # if the *_host variables are DNS names and not IPs.
            pass

        deploy_args += [
            '-e', endpoint_environment,
            '-e', os.path.join(
                tht_templates,
                'environments/use-dns-for-vips.yaml'),
            '-e', os.path.join(
                tht_templates,
                'environments/services/undercloud-haproxy.yaml'),
            '-e', os.path.join(
                tht_templates,
                'environments/services/undercloud-keepalived.yaml')]

    u = CONF.get('deployment_user') or utils.get_deployment_user()
    env_data['DeploymentUser'] = u

    deploy_args += [
        "-e", os.path.join(tht_templates, "environments/docker.yaml"),
        "-e",
        os.path.join(tht_templates,
                     "environments/config-download-environment.yaml"),
        "-e", os.path.join(tht_templates, "environments/undercloud.yaml")]

    env_file = _write_env_file(
        env_data, registry_overwrites=registry_overwrites)
    deploy_args += ['-e', env_file]

    if CONF.get('output_dir'):
        deploy_args += ['--output-dir=%s' % CONF['output_dir']]
        if not os.path.isdir(CONF['output_dir']):
            os.mkdir(CONF['output_dir'])

    if CONF.get('cleanup'):
        deploy_args.append('--cleanup')

    if CONF.get('custom_env_files'):
        for custom_file in CONF['custom_env_files']:
            deploy_args += ['-e', custom_file]

    if CONF.get('enable_validations') and not no_validations:
        undercloud_preflight.check()

    if verbose_level > 1:
        deploy_args.append('--debug')

    cmd = ["sudo", "openstack", "undercloud", "deploy"]
    cmd += deploy_args[:]

    return cmd


def _get_tls_endpoint_environment(public_host, tht_templates):
    try:
        netaddr.IPAddress(public_host)
        return os.path.join(tht_templates,
                            "environments/tls-endpoints-public-ip.yaml")
    except netaddr.core.AddrFormatError:
        return os.path.join(tht_templates,
                            "environments/tls-endpoints-public-dns.yaml")


def _get_public_tls_parameters(service_certificate_path):
    with open(service_certificate_path, "rb") as pem_file:
        pem_data = pem_file.read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=None,
            backend=default_backend())

        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        return {
            'SSLCertificate': cert_pem,
            'SSLKey': key_pem
        }


def _get_public_tls_resource_registry_overwrites(enable_tls_yaml_path):
    with open(enable_tls_yaml_path, 'rb') as enable_tls_file:
        enable_tls_dict = yaml.load(enable_tls_file.read())
        try:
            return enable_tls_dict['resource_registry']
        except KeyError:
            raise RuntimeError('%s is malformed and is missing the resource '
                               'registry.' % enable_tls_yaml_path)


def _write_env_file(env_data,
                    env_file="/tmp/undercloud_parameters.yaml",
                    registry_overwrites={}):
    """Write the undercloud parameters to yaml"""

    data = {'parameter_defaults': env_data}
    if registry_overwrites:
        data['resource_registry'] = registry_overwrites
    env_file = os.path.abspath(env_file)
    with open(env_file, "w") as f:
        try:
            dumper = yaml.dumper.SafeDumper
            dumper.ignore_aliases = lambda self, data: True
            yaml.dump(data, f, default_flow_style=False, Dumper=dumper)
        except yaml.YAMLError as exc:
            raise exc
    return env_file


def _container_images_config(conf, deploy_args, env_data):
    if conf.container_images_file:
        deploy_args += ['-e', conf.container_images_file]
    else:
        # no images file was provided. Set a default ContainerImagePrepare
        # parameter to trigger the preparation of the required container list
        cip = kolla_builder.CONTAINER_IMAGE_PREPARE_PARAM
        env_data['ContainerImagePrepare'] = cip
