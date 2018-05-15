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
import jinja2
import json
import logging
import netaddr
import os
import yaml

from cryptography import x509

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from oslo_config import cfg
from tripleo_common.image import kolla_builder

from tripleoclient.config.undercloud import SUBNETS_DEFAULT
from tripleoclient.config.undercloud import UndercloudConfig
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

PARAMETER_MAPPING = {
    'inspection_interface': 'IronicInspectorInterface',
    'undercloud_debug': 'Debug',
    'ipxe_enabled': 'IronicInspectorIPXEEnabled',
    'certificate_generation_ca': 'CertmongerCA',
    'undercloud_public_host': 'CloudName',
    'scheduler_max_attempts': 'NovaSchedulerMaxAttempts',
    'local_mtu': 'UndercloudLocalMtu',
    'clean_nodes': 'IronicAutomatedClean',
    'local_subnet': 'UndercloudCtlplaneLocalSubnet',
    'enable_routed_networks': 'UndercloudEnableRoutedNetworks',
    'local_interface': 'NeutronPublicInterface'
}

SUBNET_PARAMETER_MAPPING = {
    'cidr': 'NetworkCidr',
    'gateway': 'NetworkGateway',
    'dhcp_start': 'DhcpRangeStart',
    'dhcp_end': 'DhcpRangeEnd',
}

THT_HOME = os.environ.get('THT_HOME',
                          "/usr/share/openstack-tripleo-heat-templates/")

USER_HOME = os.environ.get('HOME', '')

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
ci_defaults = kolla_builder.container_images_prepare_defaults()

config = UndercloudConfig()

# Routed subnets
_opts = config.get_opts()
CONF.register_opts(_opts)


def _load_subnets_config_groups():
    for group in CONF.subnets:
        g = cfg.OptGroup(name=group, title=group)
        CONF.register_opts(config.get_subnet_opts(), group=g)


LOG = logging.getLogger(__name__ + ".undercloud_config")


# this is needed for the oslo config generator
def list_opts():
    return [(None, copy.deepcopy(_opts)),
            (SUBNETS_DEFAULT[0], copy.deepcopy(config.get_subnet_opts()))]


def _load_config():
    conf_params = []
    if os.path.isfile(PATHS.CONF_PATH):
        conf_params += ['--config-file', PATHS.CONF_PATH]
    else:
        LOG.warning('%s does not exist. Using defaults.' % PATHS.CONF_PATH)
    CONF(conf_params)


def _get_jinja_env_source(f):
    path, filename = os.path.split(f)
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(path))
    src = env.loader.get_source(env, filename)[0]
    return (env, src)


def _get_unknown_instack_tags(env, src):
    found_tags = set(jinja2.meta.find_undeclared_variables(env.parse(src)))
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
    env_data['UndercloudHomeDir'] = USER_HOME

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

    # This parameter the IP address used to bind the local container registry
    env_data['LocalContainerRegistry'] = CONF['local_ip'].split('/')[0]

    if CONF.get('local_ip', None):
        deploy_args.append('--local-ip=%s' % CONF['local_ip'])

    if CONF.get('templates', None):
        tht_templates = CONF['templates']
        deploy_args.append('--templates=%s' % tht_templates)
    else:
        tht_templates = THT_HOME
        deploy_args.append('--templates=%s' % THT_HOME)

    if CONF.get('roles_file', None):
        deploy_args.append('--roles-file=%s' % CONF['roles_file'])

    if upgrade:
        deploy_args += ['--upgrade']

    if CONF.get('heat_native', None):
        deploy_args.append('--heat-native')

    if CONF.get('heat_container_image'):
        deploy_args.append('--heat-container-image=%s'
                           % CONF['heat_container_image'])

    # These should be loaded first so we can override all the bits later
    deploy_args += [
        "-e", os.path.join(tht_templates, "environments/docker.yaml"),
        "-e", os.path.join(tht_templates, "environments/undercloud.yaml")]

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

    params_file = os.path.abspath(os.path.join(CONF['output_dir'],
                                               'undercloud_parameters.yaml'))
    deploy_args += ['--output-dir=%s' % CONF['output_dir']]
    if not os.path.isdir(CONF['output_dir']):
        os.mkdir(CONF['output_dir'])

    if CONF.get('cleanup'):
        deploy_args.append('--cleanup')

    if CONF.get('custom_env_files'):
        for custom_file in CONF['custom_env_files']:
            deploy_args += ['-e', custom_file]

    if CONF.get('net_config_override', None):
        data_file = CONF['net_config_override']
        if os.path.abspath(data_file) != data_file:
            data_file = os.path.join(tht_templates, data_file)

        if not os.path.exists(data_file):
            msg = "Could not find net_config_override file '%s'" % data_file
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
            msg = ('Can not render net_config_override file %s contains '
                   'unknown instack_env j2 tags: %s' % (
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
                context[tag] = env_data.get(
                    mapped_value, None) or CONF[mapped_value]

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
            LOG(msg)
            raise exceptions.DeploymentError(msg)

        env_data['UndercloudNetConfigOverride'] = net_config_json

    deploy_args += ['-e', params_file]
    utils.write_env_file(env_data, params_file, registry_overwrites)

    if CONF.get('hieradata_override', None):
        data_file = CONF['hieradata_override']
        if os.path.abspath(data_file) != data_file:
            data_file = os.path.join(USER_HOME, data_file)

        if not os.path.exists(data_file):
            msg = "Could not find hieradata_override file '%s'" % data_file
            LOG.error(msg)
            raise RuntimeError(msg)

        deploy_args += ['--hieradata-override=%s' % data_file]

    if CONF.get('enable_validations') and not no_validations:
        undercloud_preflight.check()

    if verbose_level > 1:
        deploy_args.append('--debug')

    LOG_FILE = os.path.join(os.getcwd() + '/install-undercloud.log')
    deploy_args.append('--log-file=' + LOG_FILE)

    cmd = ["sudo", "openstack", "tripleo", "deploy", "--standalone"]
    cmd += deploy_args[:]

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


def _get_public_tls_resource_registry_overwrites(enable_tls_yaml_path):
    with open(enable_tls_yaml_path, 'rb') as enable_tls_file:
        enable_tls_dict = yaml.load(enable_tls_file.read())
        try:
            return enable_tls_dict['resource_registry']
        except KeyError:
            raise RuntimeError('%s is malformed and is missing the resource '
                               'registry.' % enable_tls_yaml_path)


def _container_images_config(conf, deploy_args, env_data):
    if conf.container_images_file:
        deploy_args += ['-e', conf.container_images_file]
    else:
        # no images file was provided. Set a default ContainerImagePrepare
        # parameter to trigger the preparation of the required container list
        cip = kolla_builder.CONTAINER_IMAGE_PREPARE_PARAM
        env_data['ContainerImagePrepare'] = cip
