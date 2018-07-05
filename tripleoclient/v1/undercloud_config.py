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
from oslo_config import cfg
from tripleoclient.v1 import undercloud_preflight
import yaml


PARAMETER_MAPPING = {
    'network_gateway': 'UndercloudNetworkGateway',
    'enabled_drivers': 'IronicEnabledDrivers',
    'inspection_iprange': 'IronicInspectorIpRange',
    'inspection_interface': 'IronicInspectorInterface',
    'dhcp_start': 'UndercloudDhcpRangeStart',
    'dhcp_end': 'UndercloudDhcpRangeEnd',
    'network_cidr': 'UndercloudNetworkCidr',
    'undercloud_debug': 'Debug',
    'ipxe_enabled': 'IronicInspectorIPXEEnabled',
    'certificate_generation_ca': 'CertmongerCA',
    'undercloud_public_host': 'CloudName',
    'scheduler_max_attempts': 'NovaSchedulerMaxAttempts',
}

THT_HOME = os.environ.get('THT_HOME',
                          "/usr/share/openstack-tripleo-heat-templates/")

TELEMETRY_DOCKER_ENV_YAML = [
    'environments/services/undercloud-gnocchi.yaml',
    'environments/services/undercloud-aodh.yaml',
    'environments/services/undercloud-panko.yaml',
    'environments/services/undercloud-ceilometer.yaml']


class Paths(object):
    @property
    def CONF_PATH(self):
        return os.path.expanduser('~/undercloud.conf')


CONF = cfg.CONF
PATHS = Paths()


# When adding new options to the lists below, make sure to regenerate the
# sample config by running "tox -e genconfig" in the project root.
_opts = [
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
    cfg.StrOpt('network_gateway',
               default='192.168.24.1',
               help=('Network gateway for the Neutron-managed network for '
                     'Overcloud instances. This should match the local_ip '
                     'above when using masquerading.')
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
    cfg.StrOpt('undercloud_service_certificate',
               default='',
               help=('Certificate file to use for OpenStack service SSL '
                     'connections.  Setting this enables SSL for the '
                     'OpenStack API endpoints, leaving it unset disables SSL.')
               ),
    cfg.BoolOpt('generate_service_certificate',
                default=False,
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
    cfg.StrOpt('network_cidr',
               default='192.168.24.0/24',
               help=('Network CIDR for the Neutron-managed network for '
                     'Overcloud instances. This should be the subnet used '
                     'for PXE booting.')
               ),
    cfg.StrOpt('masquerade_network',
               default='192.168.24.0/24',
               help=('Network that will be masqueraded for external access, '
                     'if required. This should be the subnet used for PXE '
                     'booting.')
               ),
    cfg.StrOpt('dhcp_start',
               default='192.168.24.5',
               help=('Start of DHCP allocation range for PXE and DHCP of '
                     'Overcloud instances.')
               ),
    cfg.StrOpt('dhcp_end',
               default='192.168.24.24',
               help=('End of DHCP allocation range for PXE and DHCP of '
                     'Overcloud instances.')
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
    cfg.StrOpt('inspection_iprange',
               default='192.168.24.100,192.168.24.120',
               deprecated_name='discovery_iprange',
               help=('Temporary IP range that will be given to nodes during '
                     'the inspection process.  Should not overlap with the '
                     'range defined by dhcp_start and dhcp_end, but should '
                     'be in the same network.')
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
    cfg.BoolOpt('inspection_enable_uefi',
                default=True,
                help=('Whether to support introspection of nodes that have '
                      'UEFI-only firmware.')
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
               help=('Container yaml file with all available images in the'
                     'registry')
               ),
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
]

CONF.register_opts(_opts)

LOG = logging.getLogger(__name__ + ".undercloud_config")


def list_opts():
    return [(None, copy.deepcopy(_opts))]


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


def prepare_undercloud_deploy(upgrade=False, no_validations=False):
    """Prepare Undercloud deploy command based on undercloud.conf"""

    env_data = {}
    deploy_args = []
    _load_config()

    # Set the undercloud home dir parameter so that stackrc is produced in
    # the users home directory.
    env_data['UndercloudHomeDir'] = os.environ.get('HOME', '')

    for param_key, param_value in PARAMETER_MAPPING.items():
        if param_key in CONF.keys():
            env_data[param_value] = CONF[param_key]

    # Parse the undercloud.conf options to include necessary args and
    # yaml files for undercloud deploy command

    # we use this to set --dns-nameserver for the ctlplane network
    # so just pick the first entry
    if CONF.get('undercloud_nameservers', None):
        env_data['UndercloudNameserver'] = CONF['undercloud_nameservers'][0]

    if CONF.get('undercloud_ntp_servers', None):
        env_data['NtpServer'] = CONF['undercloud_ntp_servers'][0]

    # FIXME need to add admin VIP as well
    env_data['DockerInsecureRegistryAddress'] = [
        '%s:8787' % CONF['local_ip'].split('/')[0]]
    env_data['DockerInsecureRegistryAddress'].extend(
        CONF['docker_insecure_registries'])

    if CONF.get('docker_registry_mirror', None):
        env_data['DockerRegistryMirror'] = CONF['docker_registry_mirror']

    if CONF.get('local_ip', None):
        # local_ip is defined as a CIDR
        just_local_ip = CONF['local_ip'].split('/')[0]
        deploy_args.append('--local-ip=%s' % just_local_ip)

    if CONF.get('templates', None):
        tht_templates = CONF['templates']
        deploy_args.append('--templates=%s' % tht_templates)
    else:
        tht_templates = THT_HOME
        deploy_args.append('--templates=%s' % THT_HOME)

    if upgrade:
        # Containerized undercloud upgrade is still WIP
        # We're in upgrade scenario, include the major upgrade steps
        deploy_args += ['-e', os.path.join(
            tht_templates,
            "environments/major-upgrade-composable-steps-docker.yaml")]

    if CONF.get('heat_native', None):
        deploy_args.append('--heat-native')

    if CONF.get('heat_container_image'):
        deploy_args.append('--heat-container-image=%s'
                           % CONF['heat_container_image'])

    if CONF.get('container_images_file'):
        deploy_args += ['-e', CONF['container_images_file']]

    if CONF.get('enable_ironic'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/ironic.yaml")]

        # ironic-inspector can only work if ironic is enabled
        if CONF.get('enable_ironic_inspector'):
            deploy_args += ['-e', os.path.join(
                tht_templates,
                "environments/services/ironic-inspector.yaml")]

        _process_drivers_and_hardware_types(CONF, env_data)

    if CONF.get('enable_mistral'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/mistral.yaml")]

    if CONF.get('enable_zaqar'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/zaqar.yaml")]

    if CONF.get('enable_telemetry'):
        for env_file in TELEMETRY_DOCKER_ENV_YAML:
            deploy_args += ['-e', os.path.join(tht_templates, env_file)]

    if CONF.get('enable_cinder'):
        deploy_args += ['-e', os.path.join(
            tht_templates,
            "environments/services/undercloud-cinder.yaml")]

    if CONF.get('generate_service_certificate'):
        try:
            public_host = CONF.get('undercloud_public_host')
            netaddr.IPAddress(public_host)
            endpoint_environment = os.path.join(
                tht_templates,
                "environments/tls-endpoints-public-ip.yaml")
        except netaddr.core.AddrFormatError:
            endpoint_environment = os.path.join(
                tht_templates,
                "environments/tls-endpoints-public-dns.yaml")

        deploy_args += ['-e', os.path.join(
            tht_templates,
            "environments/public-tls-undercloud.yaml"),
            '-e', endpoint_environment]

    deploy_args += [
        "-e", os.path.join(tht_templates, "environments/docker.yaml"),
        "-e",
        os.path.join(tht_templates,
                     "environments/config-download-environment.yaml"),
        "-e", os.path.join(tht_templates, "environments/undercloud.yaml")]

    env_file = _write_env_file(env_data)
    deploy_args += ['-e', env_file]

    deploy_args += ['--output-dir=%s' % os.environ.get('HOME', '')]

    if CONF.get('custom_env_files'):
        for custom_file in CONF['custom_env_files']:
            deploy_args += ['-e', custom_file]

    if CONF.get('enable_validations') and not no_validations:
        undercloud_preflight.check()

    cmd = ["sudo", "openstack", "undercloud", "deploy"]
    cmd += deploy_args[:]

    return cmd


def _write_env_file(env_data,
                    env_file="/tmp/undercloud_parameters.yaml"):
    """Write the undercloud parameters to yaml"""

    data = {'parameter_defaults': env_data}
    env_file = os.path.abspath(env_file)
    with open(env_file, "w") as f:
        try:
            yaml.dump(data, f, default_flow_style=False)
        except yaml.YAMLError as exc:
            raise exc
    return env_file
