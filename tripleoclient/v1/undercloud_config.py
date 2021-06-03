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

import json
import logging
import netaddr
import os
import shutil
import sys

from cryptography import x509

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from jinja2 import Environment
from jinja2 import FileSystemLoader
from jinja2 import meta

from osc_lib.i18n import _
from oslo_config import cfg
from tripleo_common.image import kolla_builder

from tripleoclient.config.undercloud import load_global_config
from tripleoclient.config.undercloud import UndercloudConfig
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils
from tripleoclient.v1 import undercloud_preflight


# Provides mappings for some of the instack_env tags to undercloud heat
# params or undercloud.conf opts known here (as a fallback), needed to maintain
# feature parity with instack net config override templates.
# TODO(bogdando): all of the needed mappings should be wired-in, eventually
INSTACK_NETCONF_MAPPING = {
    'LOCAL_INTERFACE': 'local_interface',
    'LOCAL_IP': 'local_ip',
    'LOCAL_MTU': 'UndercloudLocalMtu',
    'PUBLIC_INTERFACE_IP': 'undercloud_public_host',  # can't be 'CloudName'
    'UNDERCLOUD_NAMESERVERS': 'undercloud_nameservers',
    'SUBNETS_STATIC_ROUTES': 'ControlPlaneStaticRoutes',
}

MULTI_PARAMETER_MAPPING = {
    'ipxe_enabled': ['IronicIPXEEnabled', 'IronicInspectorIPXEEnabled']
}

PARAMETER_MAPPING = {
    'inspection_interface': 'IronicInspectorInterface',
    'undercloud_debug': 'Debug',
    'certificate_generation_ca': 'CertmongerCA',
    'undercloud_public_host': 'CloudName',
    'scheduler_max_attempts': 'NovaSchedulerMaxAttempts',
    'local_mtu': 'UndercloudLocalMtu',
    'clean_nodes': 'IronicAutomatedClean',
    'upgrade_cleanup': 'UpgradeRemoveUnusedPackages',
    'container_healthcheck_disabled': 'ContainerHealthcheckDisabled',
    'local_subnet': 'UndercloudCtlplaneLocalSubnet',
    'enable_routed_networks': 'UndercloudEnableRoutedNetworks',
    'local_interface': 'NeutronPublicInterface',
    'auth_token_lifetime': 'TokenExpiration',
}

SUBNET_PARAMETER_MAPPING = {
    'cidr': 'NetworkCidr',
    'gateway': 'NetworkGateway',
    'host_routes': 'HostRoutes',
}

THT_HOME = os.environ.get('THT_HOME',
                          "/usr/share/openstack-tripleo-heat-templates/")

USER_HOME = os.environ.get('HOME', '')

TELEMETRY_DOCKER_ENV_YAML = [
    'environments/services/undercloud-gnocchi.yaml',
    'environments/services/undercloud-aodh.yaml',
    'environments/services/undercloud-ceilometer.yaml']

CONF = cfg.CONF

# When adding new options to the lists below, make sure to regenerate the
# sample config by running "tox -e genconfig" in the project root.
ci_defaults = kolla_builder.container_images_prepare_defaults()

config = UndercloudConfig()

# Routed subnets
_opts = config.get_opts()
load_global_config()


def _load_subnets_config_groups():
    for group in CONF.subnets:
        g = cfg.OptGroup(name=group, title=group)
        if group == CONF.local_subnet:
            CONF.register_opts(config.get_local_subnet_opts(), group=g)
        else:
            CONF.register_opts(config.get_remote_subnet_opts(), group=g)


LOG = logging.getLogger(__name__ + ".undercloud_config")


def _get_jinja_env_source(f):
    path, filename = os.path.split(f)
    env = Environment(loader=FileSystemLoader(path))
    src = env.loader.get_source(env, filename)[0]
    return (env, src)


def _get_unknown_instack_tags(env, src):
    found_tags = set(meta.find_undeclared_variables(env.parse(src)))
    known_tags = set(INSTACK_NETCONF_MAPPING.keys())
    if found_tags <= known_tags:
        return (', ').join(found_tags - known_tags)
    else:
        return None


def _process_drivers_and_hardware_types(conf, env):
    """Populate the environment with ironic driver information."""
    # Ensure correct rendering of the list and uniqueness of the items
    enabled_hardware_types = set(conf.enabled_hardware_types)
    if conf.enable_node_discovery:
        if conf.discovery_default_driver not in enabled_hardware_types:
            enabled_hardware_types.add(conf.discovery_default_driver)
        env['IronicInspectorEnableNodeDiscovery'] = True
        env['IronicInspectorDiscoveryDefaultDriver'] = (
            conf.discovery_default_driver)

    env['IronicEnabledNetworkInterfaces'] = \
        conf.ironic_enabled_network_interfaces
    env['IronicDefaultNetworkInterface'] = \
        conf.ironic_default_network_interface

    # In most cases power and management interfaces are called the same, so we
    # use one variable for them.
    mgmt_interfaces = {'fake', 'ipmitool'}
    # TODO(dtantsur): can we somehow avoid hardcoding hardware types here?
    for hw_type in ('redfish', 'idrac', 'ilo', 'irmc', 'staging-ovirt',
                    'xclarity'):
        if hw_type in enabled_hardware_types:
            mgmt_interfaces.add(hw_type)

    bios_interfaces = {'no-bios'}
    for hw_type in ['ilo', 'irmc', 'redfish']:
        if hw_type in enabled_hardware_types:
            bios_interfaces.add(hw_type)

    # Two hardware types use non-default boot interfaces.
    boot_interfaces = {'ipxe', 'pxe'}
    for hw_type in ('ilo', 'irmc'):
        if hw_type in enabled_hardware_types:
            boot_interfaces.add('%s-pxe' % hw_type)

    inspect_interfaces = {'inspector', 'no-inspect'}
    for hw_type in ('redfish', 'idrac', 'ilo', 'irmc'):
        if hw_type in enabled_hardware_types:
            inspect_interfaces.add(hw_type)

    raid_interfaces = {'no-raid'}
    if 'idrac' in enabled_hardware_types:
        raid_interfaces.add('idrac')

    vendor_interfaces = {'no-vendor'}
    for (hw_type, iface) in [('ipmi', 'ipmitool'),
                             ('idrac', 'idrac')]:
        if hw_type in enabled_hardware_types:
            vendor_interfaces.add(iface)

    power_interfaces = mgmt_interfaces.copy()
    # The snmp hardware type uses noop management and snmp power; noop
    # management is also used by ipmi and staging hardware types.
    mgmt_interfaces.add('noop')
    if 'snmp' in enabled_hardware_types:
        power_interfaces.add('snmp')

    deploy_interfaces = {'iscsi', 'direct', 'ansible'}
    if 'fake-hardware' in enabled_hardware_types:
        deploy_interfaces.add('fake')
        boot_interfaces.add('fake')

    env['IronicEnabledHardwareTypes'] = sorted(enabled_hardware_types)

    env['IronicEnabledBiosInterfaces'] = sorted(bios_interfaces)
    env['IronicEnabledBootInterfaces'] = sorted(boot_interfaces)
    env['IronicEnabledInspectInterfaces'] = sorted(inspect_interfaces)
    env['IronicEnabledManagementInterfaces'] = sorted(mgmt_interfaces)
    env['IronicEnabledPowerInterfaces'] = sorted(power_interfaces)
    env['IronicEnabledRaidInterfaces'] = sorted(raid_interfaces)
    env['IronicEnabledVendorInterfaces'] = sorted(vendor_interfaces)
    env['IronicEnabledDeployInterfaces'] = sorted(deploy_interfaces)


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
        try:
            if netaddr.IPNetwork(s.cidr).version == 4:
                env_dict['ip_range'] = s.inspection_iprange
            if netaddr.IPNetwork(s.cidr).version == 6:
                if CONF['ipv6_address_mode'] == 'dhcpv6-stateful':
                    env_dict['ip_range'] = s.inspection_iprange
                if CONF['ipv6_address_mode'] == 'dhcpv6-stateless':
                    # dnsmasq(8): A static-only subnet with address all zeros
                    # may be used as a "catch-all" address to enable replies to
                    # all Information-request packets on a subnet which is
                    # provided with stateless DHCPv6, ie --dhcp-range=::,static
                    env_dict['ip_range'] = ','.join(
                        [str(netaddr.IPNetwork(s.cidr).ip), 'static'])
            env_dict['netmask'] = str(netaddr.IPNetwork(s.cidr).netmask)
            env_dict['gateway'] = s.gateway
            env_dict['host_routes'] = s.host_routes
            env_dict['mtu'] = CONF.local_mtu
            env_list.append(env_dict)
        except Exception as e:
            msg = _('Invalid configuration data in subnet "{}". Double check '
                    'the settings for this subnet. Error: {}').format(subnet,
                                                                      e)
            LOG.error(msg)
            raise exceptions.DeploymentError(msg)
    return env_list


def _generate_subnets_static_routes():
    env_list = []
    local_router = CONF.get(CONF.local_subnet).gateway
    for subnet in CONF.subnets:
        if subnet == str(CONF.local_subnet):
            continue
        s = CONF.get(subnet)
        env_list.append({'ip_netmask': s.cidr, 'next_hop': local_router})
    for route in CONF.get(CONF.local_subnet).host_routes:
        env_list.append({'ip_netmask': route['destination'],
                         'next_hop': route['nexthop']})

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


def _calculate_allocation_pools(subnet):
    """Calculate subnet allocation pools

    Remove the gateway address, the inspection IP range and the undercloud IP's
    from the subnets full IP range and return all remaining address ranges as
    allocation pools. If dhcp_start and/or dhcp_end is defined, also remove
    addresses before dhcp_start and addresses after dhcp_end.
    """
    ip_network = netaddr.IPNetwork(subnet.cidr)
    # NOTE(hjensas): Ignore the default dhcp_start and dhcp_end if cidr is not
    # the default as well. I.e allow not specifying dhcp_start and dhcp_end.
    if (subnet.cidr != constants.CTLPLANE_CIDR_DEFAULT
            and subnet.dhcp_start == constants.CTLPLANE_DHCP_START_DEFAULT
            and subnet.dhcp_end == constants.CTLPLANE_DHCP_END_DEFAULT):
        subnet.dhcp_start, subnet.dhcp_end = None, None
    if subnet.dhcp_start and subnet.dhcp_end:
        ip_set = netaddr.IPSet()
        for a, b in zip(subnet.dhcp_start, subnet.dhcp_end):
            ip_set.add(netaddr.IPRange(netaddr.IPAddress(a),
                                       netaddr.IPAddress(b)))
    else:
        ip_set = netaddr.IPSet(ip_network)
        # Remove addresses before dhcp_start if defined
        if subnet.dhcp_start:
            a = netaddr.IPAddress(ip_network.first)
            b = netaddr.IPAddress(subnet.dhcp_start[0]) - 1
            ip_set.remove(netaddr.IPRange(a, b))
        # Remove addresses after dhcp_end if defined
        if subnet.dhcp_end:
            a = netaddr.IPAddress(subnet.dhcp_end[0]) + 1
            b = netaddr.IPAddress(ip_network.last)
            ip_set.remove(netaddr.IPRange(a, b))
    # Remove network address and broadcast address
    ip_set.remove(ip_network.first)
    ip_set.remove(ip_network.last)
    # Remove gateway, local_ip, admin_host and public_host addresses
    ip_set.remove(netaddr.IPAddress(subnet.get('gateway')))
    ip_set.remove(netaddr.IPNetwork(CONF.local_ip).ip)
    ip_set.remove(netaddr.IPNetwork(utils.get_single_ip(
        CONF.undercloud_admin_host, ip_version=ip_network.version)))
    ip_set.remove(netaddr.IPNetwork(utils.get_single_ip(
        CONF.undercloud_public_host, ip_version=ip_network.version)))
    # Remove dns nameservers
    for addr in subnet.get('dns_nameservers', []):
        ip_set.remove(netaddr.IPAddress(addr))
    # Remove addresses in the inspection_iprange
    inspect_start, inspect_end = subnet.get('inspection_iprange').split(',')
    ip_set.remove(netaddr.IPRange(inspect_start, inspect_end))
    # Remove dhcp_exclude addresses and ip ranges
    for exclude in subnet.dhcp_exclude:
        if '-' in exclude:
            exclude_start, exclude_end = exclude.split('-')
            ip_set.remove(netaddr.IPRange(exclude_start, exclude_end))
        else:
            ip_set.remove(netaddr.IPAddress(exclude))

    return [{'start': netaddr.IPAddress(ip_range.first).format(),
             'end': netaddr.IPAddress(ip_range.last).format()}
            for ip_range in list(ip_set.iter_ipranges())]


def _generate_inspection_physnet_cidr_map():
    cidr_map = {}
    for subnet in CONF.subnets:
        s = CONF.get(subnet)
        if subnet == str(CONF.local_subnet):
            cidr_map[s.cidr] = 'ctlplane'
        else:
            cidr_map[s.cidr] = subnet

    return cidr_map


def _process_network_args(env):
    """Populate the environment with network configuration."""

    env['IronicInspectorSubnets'] = _generate_inspection_subnets()
    env['PortPhysnetCidrMap'] = _generate_inspection_physnet_cidr_map()
    env['ControlPlaneStaticRoutes'] = _generate_subnets_static_routes()
    env['UndercloudCtlplaneSubnets'] = {}
    env['UndercloudCtlplaneIPv6AddressMode'] = CONF['ipv6_address_mode']
    for subnet in CONF.subnets:
        s = CONF.get(subnet)
        env['UndercloudCtlplaneSubnets'][subnet] = {
            'AllocationPools': _calculate_allocation_pools(s)
        }
        if s.get('dns_nameservers'):
            env['UndercloudCtlplaneSubnets'][subnet].update(
                {'DnsNameServers': s['dns_nameservers']})
        else:
            env['UndercloudCtlplaneSubnets'][subnet].update(
                {'DnsNameServers': CONF['undercloud_nameservers']})
        for param_key, param_value in SUBNET_PARAMETER_MAPPING.items():
            if param_value:
                env['UndercloudCtlplaneSubnets'][subnet].update(
                    {param_value: s[param_key]})
    env['MasqueradeNetworks'] = _generate_masquerade_networks()
    if len(CONF['undercloud_nameservers']) > 5:
        raise exceptions.InvalidConfiguration('Too many nameservers provided. '
                                              'Please provide less than 6 '
                                              'servers in undercloud_'
                                              'nameservers.')
    env['DnsServers'] = ','.join(CONF['undercloud_nameservers'])
    if netaddr.IPNetwork(CONF['local_ip']).version == 6:
        env['NovaIPv6'] = True
        env['RabbitIPv6'] = True
        env['MemcachedIPv6'] = True
        env['RedisIPv6'] = True
        env['MysqlIPv6'] = True
        env['IronicIpVersion'] = '6'

    # We do not use undercloud ips for env, but just validate the configured
    # value here.
    if (CONF.get('generate_service_certificate') or
            CONF.get('undercloud_service_certificate')):
        if CONF.local_ip.split('/')[0] == CONF.undercloud_admin_host:
            msg = ("Different IPs should be assigned to local_ip and "
                   "undercloud_admin_host")
            raise exceptions.InvalidConfiguration(msg)


def _process_chrony_acls(env):
    """Populate ACL rules for chrony to allow ctlplane subnets"""
    acl_rules = []
    for subnet in CONF.subnets:
        s = CONF.get(subnet)
        acl_rules.append('allow ' + s.get('cidr'))
    env['ChronyAclRules'] = acl_rules


def prepare_undercloud_deploy(upgrade=False, no_validations=True,
                              verbose_level=1, yes=False,
                              force_stack_update=False, dry_run=False,
                              inflight=False,
                              disable_container_prepare=False):
    """Prepare Undercloud deploy command based on undercloud.conf"""

    if CONF.get('undercloud_hostname'):
        utils.set_hostname(CONF.get('undercloud_hostname'))

    env_data = {}
    registry_overwrites = {}
    deploy_args = []
    # Fetch configuration and use its log file param to add logging to a file
    utils.load_config(CONF, constants.UNDERCLOUD_CONF_PATH)
    utils.configure_logging(LOG, verbose_level, CONF['undercloud_log_file'])
    _load_subnets_config_groups()

    # NOTE(bogdando): the generated env files are stored another path then
    # picked up later.
    # NOTE(aschultz): We copy this into the tht root that we save because
    # we move any user provided environment files into this root later.
    tempdir = os.path.join(os.path.abspath(CONF['output_dir']),
                           'tripleo-config-generated-env-files')
    utils.makedirs(tempdir)

    # Set the undercloud home dir parameter so that stackrc is produced in
    # the users home directory.
    env_data['UndercloudHomeDir'] = USER_HOME

    env_data['PythonInterpreter'] = sys.executable

    env_data['ContainerImagePrepareDebug'] = CONF['undercloud_debug']

    for param_key, param_value in PARAMETER_MAPPING.items():
        if param_key in CONF.keys():
            env_data[param_value] = CONF[param_key]

    # Some undercloud config options need to tweak multiple template parameters
    for undercloud_key in MULTI_PARAMETER_MAPPING:
        for env_value in MULTI_PARAMETER_MAPPING[undercloud_key]:
            if undercloud_key in CONF.keys():
                env_data[env_value] = CONF[undercloud_key]

    # Set up parameters for undercloud networking
    _process_network_args(env_data)

    # Setup parameter for Chrony ACL rules
    _process_chrony_acls(env_data)

    # Parse the undercloud.conf options to include necessary args and
    # yaml files for undercloud deploy command

    if CONF.get('undercloud_enable_selinux'):
        env_data['SELinuxMode'] = 'enforcing'
    else:
        env_data['SELinuxMode'] = 'permissive'

    if CONF.get('undercloud_enable_paunch'):
        env_data['EnablePaunch'] = True
    else:
        env_data['EnablePaunch'] = False

    if CONF.get('undercloud_ntp_servers', None):
        env_data['NtpServer'] = CONF['undercloud_ntp_servers']

    if CONF.get('undercloud_timezone', None):
        env_data['TimeZone'] = CONF['undercloud_timezone']
    else:
        env_data['TimeZone'] = utils.get_local_timezone()

    if CONF.get('enable_validations', False):
        env_data['UndercloudConfigFilePath'] = constants.UNDERCLOUD_CONF_PATH
        if not no_validations:
            env_data['EnableValidations'] = CONF['enable_validations']

    if CONF.get('overcloud_domain_name', None):
        env_data['NeutronDnsDomain'] = CONF['overcloud_domain_name']
        deploy_args.append('--local-domain=%s' % CONF['overcloud_domain_name'])

    local_registry_name = '.'.join([utils.get_short_hostname(),
                                    'ctlplane',
                                    CONF['overcloud_domain_name']])
    if CONF.get('container_cli', 'podman') == 'podman':
        env_data['DockerInsecureRegistryAddress'] = [local_registry_name]
        env_data['DockerInsecureRegistryAddress'].append(
            CONF['local_ip'].split('/')[0])
        env_data['DockerInsecureRegistryAddress'].append(
            CONF['undercloud_admin_host'])
    else:
        env_data['DockerInsecureRegistryAddress'] = [
            '%s:8787' % local_registry_name]
        env_data['DockerInsecureRegistryAddress'].append(
            '%s:8787' % CONF['local_ip'].split('/')[0])
        env_data['DockerInsecureRegistryAddress'].append(
            '%s:8787' % CONF['undercloud_admin_host'])
    env_data['DockerInsecureRegistryAddress'].extend(
        CONF['container_insecure_registries'])

    env_data['ContainerCli'] = CONF['container_cli']

    # NOTE(aschultz): deprecated in Stein
    if CONF.get('docker_bip', None):
        env_data['DockerNetworkOptions'] = CONF['docker_bip']

    if CONF.get('container_registry_mirror', None):
        env_data['DockerRegistryMirror'] = CONF['container_registry_mirror']

    # This parameter the IP address used to bind the local container registry
    env_data['LocalContainerRegistry'] = local_registry_name

    if CONF['additional_architectures']:
        # In queens (instack-undercloud) we used this to setup additional
        # architectures.  For rocky+ we want to pass a list and be smarter in
        # THT.  We can remove this in 'T' when we get there.
        for arch in CONF['additional_architectures']:
            env_data['EnableArchitecture%s' % arch.upper()] = True
        env_data['AdditionalArchitectures'] = \
            ','.join(CONF['additional_architectures'])

    if CONF.get('local_ip', None):
        deploy_args.append('--local-ip=%s' % CONF['local_ip'])

    if CONF.get('templates', None):
        tht_templates = CONF['templates']
        deploy_args.append('--templates=%s' % tht_templates)
    else:
        tht_templates = THT_HOME
        deploy_args.append('--templates=%s' % THT_HOME)

    if CONF.get('roles_file', constants.UNDERCLOUD_ROLES_FILE):
        deploy_args.append('--roles-file=%s' % CONF['roles_file'])

    if CONF.get('networks_file'):
        deploy_args.append('--networks-file=%s' % CONF['networks_file'])
    else:
        deploy_args.append('--networks-file=%s' %
                           constants.UNDERCLOUD_NETWORKS_FILE)

    if yes:
        deploy_args += ['-y']

    if upgrade:
        deploy_args += [
            '--upgrade',
            '-e', os.path.join(
                tht_templates,
                "environments/lifecycle/undercloud-upgrade-prepare.yaml")]

    if not CONF.get('heat_native', False):
        deploy_args.append('--heat-native=False')
    else:
        deploy_args.append('--heat-native')

    if CONF.get('heat_container_image'):
        deploy_args.append('--heat-container-image=%s'
                           % CONF['heat_container_image'])

    # These should be loaded first so we can override all the bits later
    deploy_args += [
        "-e", os.path.join(tht_templates, "environments/undercloud.yaml"),
        '-e', os.path.join(tht_templates, 'environments/use-dns-for-vips.yaml')
        ]

    # we want to load this environment after undercloud.yaml for precedence.
    if CONF.get('container_cli', 'podman') == 'podman':
        deploy_args += [
            '-e', os.path.join(tht_templates, 'environments/podman.yaml')
            ]

    # If a container images file is used, copy it into the tempdir to make it
    # later into other deployment artifacts and user-provided files.
    _container_images_config(CONF, deploy_args, env_data, tempdir)

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

    if not CONF.get('enable_nova', True):
        deploy_args += [
            '-e', os.path.join(
                tht_templates, 'environments/undercloud-disable-nova.yaml')
            ]

    if CONF.get('enable_mistral'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/mistral.yaml")]

    if CONF.get('enable_novajoin'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/novajoin.yaml")]
        env_data['NovajoinIpaOtp'] = CONF['ipa_otp']
    elif CONF.get('ipa_otp'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/undercloud-tls.yaml")]
        env_data['UndercloudIpaOtp'] = CONF['ipa_otp']

    if CONF.get('enable_zaqar'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/zaqar-swift-backend.yaml")]

    if CONF.get('enable_telemetry'):
        for env_file in TELEMETRY_DOCKER_ENV_YAML:
            deploy_args += ['-e', os.path.join(tht_templates, env_file)]
    else:
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/disable-telemetry.yaml")]

    if CONF.get('enable_cinder'):
        deploy_args += ['-e', os.path.join(
            tht_templates,
            "environments/services/undercloud-cinder.yaml")]

    if CONF.get('enable_tempest'):
        deploy_args += ['-e', os.path.join(
            tht_templates,
            "environments/services/tempest.yaml")]

    if CONF.get('enable_swift_encryption'):
        deploy_args += [
            '-e', os.path.join(tht_templates,
                               "environments/services/barbican.yaml"),
            '-e', os.path.join(
                tht_templates,
                "environments/barbican-backend-simple-crypto.yaml")
            ]
        env_data['BarbicanSimpleCryptoGlobalDefault'] = True
        env_data['SwiftEncryptionEnabled'] = True

    if CONF.get('undercloud_service_certificate'):
        # We assume that the certificate is trusted
        env_data['InternalTLSCAFile'] = ''
        env_data.update(
            _get_public_tls_parameters(
                CONF.get('undercloud_service_certificate')))
    elif CONF.get('generate_service_certificate'):
        deploy_args += ['-e', os.path.join(
            tht_templates,
            "environments/public-tls-undercloud.yaml")]
    else:
        deploy_args += ['-e', os.path.join(
            tht_templates,
            "environments/ssl/no-tls-endpoints-public-ip.yaml")]

    if (CONF.get('generate_service_certificate') or
            CONF.get('undercloud_service_certificate')):
        local_net = netaddr.IPNetwork(CONF.get('local_ip'))

        endpoint_environment = _get_tls_endpoint_environment(
            CONF.get('undercloud_public_host'), tht_templates)

        public_host = utils.get_single_ip(CONF.get('undercloud_public_host'),
                                          ip_version=local_net.version)
        public_ip = netaddr.IPAddress(public_host)
        deploy_args += ['--public-virtual-ip', public_host]

        # To make sure the resolved host is set to the right IP in /etc/hosts
        if not utils.is_valid_ip(CONF.get('undercloud_public_host')):
            extra_host = public_host + ' ' + CONF.get('undercloud_public_host')
            env_data['ExtraHostFileEntries'] = extra_host

        admin_host = utils.get_single_ip(CONF.get('undercloud_admin_host'),
                                         ip_version=local_net.version)
        admin_ip = netaddr.IPAddress(admin_host)
        deploy_args += ['--control-virtual-ip', admin_host]

        if CONF.get('net_config_override', None):
            if (admin_ip not in local_net.cidr):
                LOG.warning('You may need to specify a custom '
                            'ControlVirtualInterface in a custom env file to '
                            'correctly assign the ip address to an interface '
                            'for undercloud_admin_host. By default it will be '
                            'set to br-ctlplane.')
            if (public_ip not in local_net.cidr):
                LOG.warning('You may need to specify a custom '
                            'PublicVirtualInterface in a custom env file to '
                            'correctly assign the ip address to an interface '
                            'for undercloud_public_host. By default it will be'
                            ' set to br-ctlplane.')
        else:
            if (admin_ip not in local_net.cidr or
                    public_ip not in local_net.cidr):
                LOG.warning('undercloud_admin_host or undercloud_public_host '
                            'is not in the same cidr as local_ip.')

        # Define the *VirtualInterfaces for keepalived. These are used when
        # configuring the undercloud_*_host addresses. If these adddesses are
        # not in the default cidr for the ctlplane, it will not be defined
        # and leads to general sadness during the deployment. Our default
        # net_config uses br-ctlplane. See rhbz#1737150
        env_data['ControlVirtualInterface'] = 'br-ctlplane'
        env_data['PublicVirtualInterface'] = 'br-ctlplane'

        deploy_args += [
            '-e', endpoint_environment,
            '-e', os.path.join(
                tht_templates,
                'environments/services/undercloud-haproxy.yaml'),
            '-e', os.path.join(
                tht_templates,
                'environments/services/undercloud-keepalived.yaml')]

    u = CONF.get('deployment_user') or utils.get_deployment_user()
    env_data['DeploymentUser'] = u
    # TODO(cjeanner) drop that once using oslo.privsep
    deploy_args += ['--deployment-user', u]

    deploy_args += ['--output-dir=%s' % CONF['output_dir']]
    utils.makedirs(CONF['output_dir'])

    if CONF.get('cleanup'):
        deploy_args.append('--cleanup')

    if CONF.get('net_config_override', None):
        data_file = CONF['net_config_override']
        if os.path.abspath(data_file) != data_file:
            data_file = os.path.join(USER_HOME, data_file)

        if not os.path.exists(data_file):
            msg = _("Could not find net_config_override file '%s'") % data_file
            LOG.error(msg)
            raise RuntimeError(msg)

        # NOTE(bogdando): Process templated net config override data:
        # * get a list of used instack_env j2 tags (j2 vars, like {{foo}}),
        # * fetch values for the tags from the known mappins,
        # * raise, if there is unmatched tags left
        # * render the template into a JSON dict
        net_config_env, template_source = _get_jinja_env_source(data_file)
        unknown_tags = _get_unknown_instack_tags(net_config_env,
                                                 template_source)
        if unknown_tags:
            msg = (_('Can not render net_config_override file {0} contains '
                     'unknown instack_env j2 tags: {1}').format(
                         data_file, unknown_tags))
            LOG.error(msg)
            raise exceptions.DeploymentError(msg)

        # Create rendering context from the known to be present mappings for
        # identified instack_env tags to generated in env_data undercloud heat
        # params. Fall back to config opts, when env_data misses a param.
        context = {}
        for tag in INSTACK_NETCONF_MAPPING.keys():
            mapped_value = INSTACK_NETCONF_MAPPING[tag]
            if mapped_value in env_data.keys() or mapped_value in CONF.keys():
                try:
                    context[tag] = CONF[mapped_value]
                except cfg.NoSuchOptError:
                    context[tag] = env_data.get(mapped_value, None)

        # this returns a unicode string, convert it in into json
        net_config_str = net_config_env.get_template(
            os.path.split(data_file)[-1]).render(context).replace(
                "'", '"').replace('&quot;', '"')
        try:
            net_config_json = json.loads(net_config_str)
        except ValueError:
            net_config_json = json.loads("{%s}" % net_config_str)

        if 'network_config' not in net_config_json:
            msg = ('Unsupported data format in net_config_override '
                   'file %s: %s' % (data_file, net_config_str))
            LOG.error(msg)
            raise exceptions.DeploymentError(msg)

        env_data['UndercloudNetConfigOverride'] = net_config_json

    params_file = os.path.join(tempdir, 'undercloud_parameters.yaml')
    utils.write_env_file(env_data, params_file, registry_overwrites)
    deploy_args += ['-e', params_file]

    if CONF.get('hieradata_override', None):
        data_file = CONF['hieradata_override']
        if os.path.abspath(data_file) != data_file:
            data_file = os.path.join(USER_HOME, data_file)

        if not os.path.exists(data_file):
            msg = _("Could not find hieradata_override file '%s'") % data_file
            LOG.error(msg)
            raise RuntimeError(msg)

        deploy_args += ['--hieradata-override=%s' % data_file]

    if CONF.get('enable_validations') and not no_validations:
        undercloud_preflight.check(verbose_level, upgrade)
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/tripleo-validations.yaml")]

    if inflight:
        deploy_args.append('--inflight-validations')

    if disable_container_prepare:
        deploy_args.append('--disable-container-prepare')

    if CONF.get('custom_env_files'):
        for custom_file in CONF['custom_env_files']:
            deploy_args += ['-e', custom_file]

    if verbose_level > 1:
        deploy_args.append('--debug')

    deploy_args.append('--log-file=%s' % CONF['undercloud_log_file'])

    # Always add a drop-in for the ephemeral undercloud heat stack
    # virtual state tracking (the actual file will be created later)
    stack_vstate_dropin = os.path.join(
        tht_templates, 'undercloud-stack-vstate-dropin.yaml')
    deploy_args += ["-e", stack_vstate_dropin]
    if force_stack_update:
        deploy_args += ["--force-stack-update"]

    cmd = ["sudo", "--preserve-env", "openstack", "tripleo", "deploy",
           "--standalone", "--standalone-role", "Undercloud", "--stack",
           "undercloud"]
    cmd += deploy_args[:]

    # In dry-run, also report the expected heat stack virtual state/action
    if dry_run:
        stack_update_mark = os.path.join(
            constants.STANDALONE_EPHEMERAL_STACK_VSTATE,
            'update_mark_undercloud')
        if os.path.isfile(stack_update_mark) or force_stack_update:
            LOG.warning(_('The heat stack undercloud virtual state/action '
                          ' would be UPDATE'))

    return cmd


def _get_tls_endpoint_environment(public_host, tht_templates):
    try:
        netaddr.IPAddress(public_host)
        return os.path.join(tht_templates,
                            "environments/ssl/tls-endpoints-public-ip.yaml")
    except netaddr.core.AddrFormatError:
        return os.path.join(tht_templates,
                            "environments/ssl/tls-endpoints-public-dns.yaml")


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


def _container_images_config(conf, deploy_args, env_data, tempdir):
    if conf.container_images_file:
        deploy_args += ['-e', conf.container_images_file]
        try:
            shutil.copy(os.path.abspath(conf.container_images_file), tempdir)
        except Exception:
            msg = _('Cannot copy a container images'
                    'file %s into a tempdir!') % conf.container_images_file
            LOG.error(msg)
            raise exceptions.DeploymentError(msg)
    else:
        # no images file was provided. Set a default ContainerImagePrepare
        # parameter to trigger the preparation of the required container list
        cip = kolla_builder.CONTAINER_IMAGE_PREPARE_PARAM
        env_data['ContainerImagePrepare'] = cip
