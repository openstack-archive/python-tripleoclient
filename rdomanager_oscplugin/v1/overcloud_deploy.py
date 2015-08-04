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

import json
import logging
import os
import re
import six
import sys
import tempfile
import uuid

from cliff import command
from heatclient.common import template_utils
from heatclient.exc import HTTPNotFound
from openstackclient.i18n import _
from os_cloud_config import keystone
from os_cloud_config import keystone_pki
from os_cloud_config.utils import clients
from tuskarclient.common import utils as tuskarutils

from rdomanager_oscplugin import utils

TRIPLEO_HEAT_TEMPLATES = "/usr/share/openstack-tripleo-heat-templates/"
OVERCLOUD_YAML_NAME = "overcloud-without-mergepy.yaml"
RESOURCE_REGISTRY_NAME = "overcloud-resource-registry-puppet.yaml"
RHEL_REGISTRATION_EXTRACONFIG_NAME = (
    "extraconfig/post_deploy/rhel-registration/")

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
    'HeatStackDomainAdminPassword': None,
    'NeutronControlPlaneID': None,
    'NeutronDnsmasqOptions': 'dhcp-option-force=26,1400',
    'NeutronPassword': None,
    'NeutronPublicInterface': 'nic1',
    'NeutronFlatNetworks': 'datacentre',
    'HypervisorNeutronPhysicalBridge': 'br-ex',
    'NeutronBridgeMappings': 'datacentre:br-ex',
    'HypervisorNeutronPublicInterface': 'nic1',
    'NovaPassword': None,
    'SwiftHashSuffix': None,
    'SwiftPassword': None,
    'SnmpdReadonlyUserPassword': None,
    'NtpServer': '',
    'controllerImage': 'overcloud-full',
    'NovaImage': 'overcloud-full',
    'BlockStorageImage': 'overcloud-full',
    'SwiftStorageImage': 'overcloud-full',
    'CephStorageImage': 'overcloud-full',
    'Debug': 'True',
    'OvercloudControlFlavor': 'baremetal',
    'OvercloudComputeFlavor': 'baremetal',
    'OvercloudBlockStorageFlavor': 'baremetal',
    'OvercloudSwiftStorageFlavor': 'baremetal',
    'OvercloudCephStorageFlavor': 'baremetal',
    'NeutronNetworkVLANRanges': 'datacentre:1:1000',
}

NEW_STACK_PARAMETERS = {
    'NovaComputeLibvirtType': 'qemu',
    'NeutronEnableTunnelling': 'True',
    'NeutronNetworkType': 'gre',
    'NeutronTunnelTypes': 'gre',
}


class DeployOvercloud(command.Command):
    """Deploy Overcloud"""

    log = logging.getLogger(__name__ + ".DeployOvercloud")

    def set_overcloud_passwords(self, parameters, parsed_args):
        """Add passwords to the parameters dictionary

        :param parameters: A dictionary for the passwords to be added to
        :type parameters: dict
        """

        undercloud_ceilometer_snmpd_password = utils.get_config_value(
            "auth", "undercloud_ceilometer_snmpd_password")

        self.passwords = passwords = utils.generate_overcloud_passwords()
        ceilometer_pass = passwords['OVERCLOUD_CEILOMETER_PASSWORD']
        ceilometer_secret = passwords['OVERCLOUD_CEILOMETER_SECRET']
        if parsed_args.templates:
            parameters['AdminPassword'] = passwords['OVERCLOUD_ADMIN_PASSWORD']
            parameters['AdminToken'] = passwords['OVERCLOUD_ADMIN_TOKEN']
            parameters['CeilometerPassword'] = ceilometer_pass
            parameters['CeilometerMeteringSecret'] = ceilometer_secret
            parameters['CinderPassword'] = passwords[
                'OVERCLOUD_CINDER_PASSWORD']
            parameters['GlancePassword'] = passwords[
                'OVERCLOUD_GLANCE_PASSWORD']
            parameters['HeatPassword'] = passwords['OVERCLOUD_HEAT_PASSWORD']
            parameters['HeatStackDomainAdminPassword'] = passwords[
                'OVERCLOUD_HEAT_STACK_DOMAIN_PASSWORD']
            parameters['NeutronPassword'] = passwords[
                'OVERCLOUD_NEUTRON_PASSWORD']
            parameters['NovaPassword'] = passwords['OVERCLOUD_NOVA_PASSWORD']
            parameters['SwiftHashSuffix'] = passwords['OVERCLOUD_SWIFT_HASH']
            parameters['SwiftPassword'] = passwords['OVERCLOUD_SWIFT_PASSWORD']
            parameters['SnmpdReadonlyUserPassword'] = (
                undercloud_ceilometer_snmpd_password)
        else:
            parameters['Controller-1::AdminPassword'] = passwords[
                'OVERCLOUD_ADMIN_PASSWORD']
            parameters['Controller-1::AdminToken'] = passwords[
                'OVERCLOUD_ADMIN_TOKEN']
            parameters['Compute-1::AdminPassword'] = passwords[
                'OVERCLOUD_ADMIN_PASSWORD']
            parameters['Controller-1::SnmpdReadonlyUserPassword'] = (
                undercloud_ceilometer_snmpd_password)
            parameters['Cinder-Storage-1::SnmpdReadonlyUserPassword'] = (
                undercloud_ceilometer_snmpd_password)
            parameters['Swift-Storage-1::SnmpdReadonlyUserPassword'] = (
                undercloud_ceilometer_snmpd_password)
            parameters['Compute-1::SnmpdReadonlyUserPassword'] = (
                undercloud_ceilometer_snmpd_password)
            parameters['Controller-1::CeilometerPassword'] = ceilometer_pass
            parameters[
                'Controller-1::CeilometerMeteringSecret'] = ceilometer_secret
            parameters['Compute-1::CeilometerPassword'] = ceilometer_pass
            parameters[
                'Compute-1::CeilometerMeteringSecret'] = ceilometer_secret
            parameters['Controller-1::CinderPassword'] = (
                passwords['OVERCLOUD_CINDER_PASSWORD'])
            parameters['Controller-1::GlancePassword'] = (
                passwords['OVERCLOUD_GLANCE_PASSWORD'])
            parameters['Controller-1::HeatPassword'] = (
                passwords['OVERCLOUD_HEAT_PASSWORD'])
            parameters['Controller-1::HeatStackDomainAdminPassword'] = (
                passwords['OVERCLOUD_HEAT_STACK_DOMAIN_PASSWORD'])
            parameters['Controller-1::NeutronPassword'] = (
                passwords['OVERCLOUD_NEUTRON_PASSWORD'])
            parameters['Compute-1::NeutronPassword'] = (
                passwords['OVERCLOUD_NEUTRON_PASSWORD'])
            parameters['Controller-1::NovaPassword'] = (
                passwords['OVERCLOUD_NOVA_PASSWORD'])
            parameters['Compute-1::NovaPassword'] = (
                passwords['OVERCLOUD_NOVA_PASSWORD'])
            parameters['Controller-1::SwiftHashSuffix'] = (
                passwords['OVERCLOUD_SWIFT_HASH'])
            parameters['Controller-1::SwiftPassword'] = (
                passwords['OVERCLOUD_SWIFT_PASSWORD'])

    def _get_stack(self, orchestration_client):
        """Get the ID for the current deployed overcloud stack if it exists."""

        try:
            stack = orchestration_client.stacks.get('overcloud')
            self.log.info("Stack found, will be doing a stack update")
            return stack
        except HTTPNotFound:
            self.log.info("No stack found, will be doing a stack create")

    def _update_paramaters(self, args, network_client, stack):
        if args.templates:
            parameters = PARAMETERS.copy()
            if stack is None:
                parameters.update(NEW_STACK_PARAMETERS)
        else:
            parameters = {}

        self.log.debug("Generating overcloud passwords")
        self.set_overcloud_passwords(parameters, args)

        self.log.debug("Getting ctlplane from Neutron")
        net = network_client.api.find_attr('networks', 'ctlplane')
        parameters['NeutronControlPlaneID'] = net['id']

        if args.templates:
            param_args = (
                ('NeutronPublicInterface', 'neutron_public_interface'),
                ('NeutronBridgeMappings', 'neutron_bridge_mappings'),
                ('NeutronFlatNetworks', 'neutron_flat_networks'),
                ('HypervisorNeutronPhysicalBridge', 'neutron_physical_bridge'),
                ('NtpServer', 'ntp_server'),
                ('ControllerCount', 'control_scale'),
                ('ComputeCount', 'compute_scale'),
                ('ObjectStorageCount', 'swift_storage_scale'),
                ('BlockStorageCount', 'block_storage_scale'),
                ('CephStorageCount', 'ceph_storage_scale'),
                ('OvercloudControlFlavor', 'control_flavor'),
                ('OvercloudComputeFlavor', 'compute_flavor'),
                ('OvercloudBlockStorageFlavor', 'block_storage_flavor'),
                ('OvercloudSwiftStorageFlavor', 'swift_storage_flavor'),
                ('OvercloudCephStorageFlavor', 'ceph_storage_flavor'),
                ('NeutronNetworkVLANRanges', 'neutron_network_vlan_ranges'),
                ('NeutronMechanismDrivers', 'neutron_mechanism_drivers')
            )

            if stack is None:
                new_stack_args = (
                    ('NeutronNetworkType', 'neutron_network_type'),
                    ('NeutronTunnelTypes', 'neutron_tunnel_types'),
                    ('NovaComputeLibvirtType', 'libvirt_type'),
                )
                param_args = param_args + new_stack_args

                if args.neutron_disable_tunneling is not None:
                    neutron_enable_tunneling = (
                        not args.neutron_disable_tunneling)
                    parameters.update({
                        'NeutronEnableTunnelling': neutron_enable_tunneling,
                    })

        else:
            param_args = (
                ('Controller-1::NeutronPublicInterface',
                    'neutron_public_interface'),
                ('Compute-1::NeutronPublicInterface',
                    'neutron_public_interface'),
                ('Controller-1::NeutronBridgeMappings',
                    'neutron_bridge_mappings'),
                ('Compute-1::NeutronBridgeMappings',
                    'neutron_bridge_mappings'),
                ('Controller-1::NeutronFlatNetworks', 'neutron_flat_networks'),
                ('Compute-1::NeutronFlatNetworks', 'neutron_flat_networks'),
                ('Compute-1::NeutronPhysicalBridge',
                    'neutron_physical_bridge'),
                ('Controller-1::NtpServer', 'ntp_server'),
                ('Compute-1::NtpServer', 'ntp_server'),
                ('Controller-1::NeutronNetworkVLANRanges',
                    'neutron_network_vlan_ranges'),
                ('Compute-1::NeutronNetworkVLANRanges',
                    'neutron_network_vlan_ranges'),
                ('Controller-1::NeutronMechanismDrivers',
                    'neutron_mechanism_drivers'),
                ('Compute-1::NeutronMechanismDrivers',
                    'neutron_mechanism_drivers'),
                ('Controller-1::count', 'control_scale'),
                ('Compute-1::count', 'compute_scale'),
                ('Swift-Storage-1::count', 'swift_storage_scale'),
                ('Cinder-Storage-1::count', 'block_storage_scale'),
                ('Ceph-Storage-1::count', 'ceph_storage_scale'),
                ('Cinder-Storage-1::Flavor', 'block_storage_flavor'),
                ('Compute-1::Flavor', 'compute_flavor'),
                ('Controller-1::Flavor', 'control_flavor'),
                ('Swift-Storage-1::Flavor', 'swift_storage_flavor'),
                ('Ceph-Storage-1::Flavor', 'ceph_storage_flavor'),
            )

            if stack is None:
                new_stack_args = (
                    ('Controller-1::NeutronNetworkType',
                        'neutron_network_type'),
                    ('Compute-1::NeutronNetworkType', 'neutron_network_type'),
                    ('Controller-1::NeutronTunnelTypes',
                        'neutron_tunnel_types'),
                    ('Compute-1::NeutronTunnelTypes', 'neutron_tunnel_types'),
                    ('Compute-1::NovaComputeLibvirtType', 'libvirt_type'),
                )
                param_args = param_args + new_stack_args

                if args.neutron_disable_tunneling is not None:
                    neutron_enable_tunneling = (
                        not args.neutron_disable_tunneling)
                    parameters.update({
                        'Controller-1::NeutronEnableTunnelling':
                            neutron_enable_tunneling,
                        'Compute-1::NeutronEnableTunnelling':
                            neutron_enable_tunneling,
                    })

        # Update parameters from commandline
        for param, arg in param_args:
            if getattr(args, arg, None) is not None:
                parameters[param] = getattr(args, arg)

        # Scaling needs extra parameters
        number_controllers = max((
            int(parameters.get('ControllerCount', 0)),
            int(parameters.get('Controller-1::count', 0))
        ))

        if number_controllers > 1:
            if args.templates:
                parameters.update({
                    'NeutronL3HA': True,
                    'NeutronAllowL3AgentFailover': False,
                })
            else:
                parameters.update({
                    'Controller-1::NeutronL3HA': True,
                    'Controller-1::NeutronAllowL3AgentFailover': False,
                    'Compute-1::NeutronL3HA': True,
                    'Compute-1::NeutronAllowL3AgentFailover': False,
                })
        else:
            if args.templates:
                parameters.update({
                    'NeutronL3HA': False,
                    'NeutronAllowL3AgentFailover': False,
                })
            else:
                parameters.update({
                    'Controller-1::NeutronL3HA': False,
                    'Controller-1::NeutronAllowL3AgentFailover': False,
                    'Compute-1::NeutronL3HA': False,
                    'Compute-1::NeutronAllowL3AgentFailover': False,
                })

        # set at least 3 dhcp_agents_per_network
        dhcp_agents_per_network = (number_controllers if number_controllers and
                                   number_controllers > 3 else 3)

        if args.templates:
            parameters.update({
                'NeutronDhcpAgentsPerNetwork': dhcp_agents_per_network,
            })
        else:
            parameters.update({
                'Controller-1::NeutronDhcpAgentsPerNetwork':
                    dhcp_agents_per_network,
            })

        if max((int(parameters.get('CephStorageCount', 0)),
                int(parameters.get('Ceph-Storage-1::count', 0)))) > 0:

            if stack is None:
                parameters.update({
                    'CephClusterFSID': six.text_type(uuid.uuid1()),
                    'CephMonKey': utils.create_cephx_key(),
                    'CephAdminKey': utils.create_cephx_key()
                })

        return parameters

    def _create_registration_env(self, args):

        if args.templates:
            tht_root = args.templates
        else:
            tht_root = TRIPLEO_HEAT_TEMPLATES

        environment = os.path.join(tht_root,
                                   RHEL_REGISTRATION_EXTRACONFIG_NAME,
                                   'environment-rhel-registration.yaml')
        registry = os.path.join(tht_root, RHEL_REGISTRATION_EXTRACONFIG_NAME,
                                'rhel-registration-resource-registry.yaml')
        user_env = ("parameter_defaults:\n"
                    "  rhel_reg_method: \"%(method)s\"\n"
                    "  rhel_reg_org: \"%(org)s\"\n"
                    "  rhel_reg_force: \"%(force)s\"\n"
                    "  rhel_reg_sat_url: \"%(sat_url)s\"\n"
                    "  rhel_reg_activation_key: \"%(activation_key)s\"\n"
                    % {'method': args.reg_method,
                       'org': args.reg_org,
                       'force': args.reg_force,
                       'sat_url': args.reg_sat_url,
                       'activation_key': args.reg_activation_key})
        handle, user_env_file = tempfile.mkstemp()
        with open(user_env_file, 'w') as temp_file:
            temp_file.write(user_env)
        return [registry, environment, user_env_file]

    def _heat_deploy(self, stack, template_path, parameters, environments,
                     timeout):
        """Verify the Baremetal nodes are available and do a stack update"""

        self.log.debug("Processing environment files")
        env_files, env = (
            template_utils.process_multiple_environments_and_files(
                environments))

        self.log.debug("Getting template contents")
        template_files, template = template_utils.get_template_contents(
            template_path)

        files = dict(list(template_files.items()) + list(env_files.items()))

        clients = self.app.client_manager
        orchestration_client = clients.rdomanager_oscplugin.orchestration()

        stack_name = "overcloud"

        self.log.debug("Deploying stack: %s", stack_name)
        self.log.debug("Deploying template: %s", template)
        self.log.debug("Deploying parameters: %s", parameters)
        self.log.debug("Deploying environment: %s", env)
        self.log.debug("Deploying files: %s", files)

        stack_args = {
            'stack_name': stack_name,
            'template': template,
            'parameters': parameters,
            'environment': env,
            'files': files
        }

        if timeout:
            stack_args['timeout_mins'] = timeout

        if stack is None:
            self.log.info("Performing Heat stack create")
            orchestration_client.stacks.create(**stack_args)
        else:
            self.log.info("Performing Heat stack update")
            # Make sure existing parameters for stack are reused
            stack_args['existing'] = 'true'
            orchestration_client.stacks.update(stack.id, **stack_args)

        create_result = utils.wait_for_stack_ready(
            orchestration_client, "overcloud")
        if not create_result:
            if stack is None:
                raise Exception("Heat Stack create failed.")
            else:
                raise Exception("Heat Stack update failed.")

    def _get_overcloud_endpoint(self, stack):
        for output in stack.to_dict().get('outputs', {}):
            if output['output_key'] == 'KeystoneURL':
                return output['output_value']

    def _get_service_ips(self, stack):
        service_ips = {}
        for output in stack.to_dict().get('outputs', {}):
            service_ips[output['output_key']] = output['output_value']
        return service_ips

    def _pre_heat_deploy(self):
        """Setup before the Heat stack create or update has been done."""
        clients = self.app.client_manager
        compute_client = clients.compute

        self.log.debug("Checking hypervisor stats")
        if utils.check_hypervisor_stats(compute_client) is None:
            print("Expected hypervisor stats not met", file=sys.stderr)
            return

    def _deploy_tripleo_heat_templates(self, stack, parsed_args):
        """Deploy the fixed templates in TripleO Heat Templates"""
        clients = self.app.client_manager
        network_client = clients.network

        parameters = self._update_paramaters(
            parsed_args, network_client, stack)

        tht_root = parsed_args.templates

        print("Deploying templates in the directory {0}".format(
            os.path.abspath(tht_root)))

        self.log.debug("Creating Environment file")
        env_path = utils.create_environment_file()

        if stack is None:
            self.log.debug("Creating Keystone certificates")
            keystone_pki.generate_certs_into_json(env_path, False)

        resource_registry_path = os.path.join(tht_root, RESOURCE_REGISTRY_NAME)

        environments = [resource_registry_path, env_path]
        if parsed_args.rhel_reg:
            reg_env = self._create_registration_env(parsed_args)
            environments.extend(reg_env)
        if parsed_args.environment_files:
            environments.extend(parsed_args.environment_files)

        overcloud_yaml = os.path.join(tht_root, OVERCLOUD_YAML_NAME)

        self._heat_deploy(stack, overcloud_yaml, parameters, environments,
                          parsed_args.timeout)

    def _deploy_tuskar(self, stack, parsed_args):

        clients = self.app.client_manager
        management = clients.rdomanager_oscplugin.management()
        network_client = clients.network

        # TODO(dmatthews): The Tuskar client has very similar code to this for
        # downloading templates. It should be refactored upstream so we can use
        # it.

        if parsed_args.output_dir:
            output_dir = parsed_args.output_dir
        else:
            output_dir = tempfile.mkdtemp()

        if not os.path.isdir(output_dir):
            os.mkdir(output_dir)

        management_plan = tuskarutils.find_resource(
            management.plans, parsed_args.plan)

        # retrieve templates
        templates = management.plans.templates(management_plan.uuid)

        parameters = self._update_paramaters(
            parsed_args, network_client, stack)

        if stack is None:
            ca_key_pem, ca_cert_pem = keystone_pki.create_ca_pair()
            signing_key_pem, signing_cert_pem = (
                keystone_pki.create_signing_pair(ca_key_pem, ca_cert_pem))
            parameters['Controller-1::KeystoneCACertificate'] = ca_cert_pem
            parameters['Controller-1::KeystoneSigningCertificate'] = (
                signing_cert_pem)
            parameters['Controller-1::KeystoneSigningKey'] = signing_key_pem

        # Save the parameters to Tuskar so they can be used when redeploying.
        # Tuskar expects to get all values as strings. So we convert them all
        # below.
        management.plans.patch(
            management_plan.uuid,
            [{'name': x[0], 'value': six.text_type(x[1])}
             for x in parameters.items()]
        )

        # write file for each key-value in templates
        print("The following templates will be written:")
        for template_name, template_content in templates.items():

            # It's possible to organize the role templates and their dependent
            # files into directories, in which case the template_name will
            # carry the directory information. If that's the case, first
            # create the directory structure (if it hasn't already been
            # created by another file in the templates list).
            template_dir = os.path.dirname(template_name)
            output_template_dir = os.path.join(output_dir, template_dir)
            if template_dir and not os.path.exists(output_template_dir):
                os.makedirs(output_template_dir)

            filename = os.path.join(output_dir, template_name)
            with open(filename, 'w+') as template_file:
                template_file.write(template_content)
            print(filename)

        overcloud_yaml = os.path.join(output_dir, 'plan.yaml')
        environment_yaml = os.path.join(output_dir, 'environment.yaml')
        environments = [environment_yaml, ]
        if parsed_args.rhel_reg:
            reg_env = self._create_registration_env(parsed_args)
            environments.extend(reg_env)
        if parsed_args.environment_files:
            environments.extend(parsed_args.environment_files)

        self._heat_deploy(stack, overcloud_yaml, parameters, environments,
                          parsed_args.timeout)

    def _create_overcloudrc(self, stack, parsed_args):
        overcloud_endpoint = self._get_overcloud_endpoint(stack)
        overcloud_ip = six.moves.urllib.parse.urlparse(
            overcloud_endpoint).hostname

        rc_params = {
            'NOVA_VERSION': '1.1',
            'COMPUTE_API_VERSION': '1.1',
            'OS_USERNAME': 'admin',
            'OS_TENANT_NAME': 'admin',
            'OS_NO_CACHE': 'True',
            'OS_CLOUDNAME': 'overcloud',
            'no_proxy': "%(no_proxy)s,%(overcloud_ip)s" % {
                'no_proxy': parsed_args.no_proxy,
                'overcloud_ip': overcloud_ip,
            }
        }
        rc_params.update({
            'OS_PASSWORD': self.passwords['OVERCLOUD_ADMIN_PASSWORD'],
            'OS_AUTH_URL': self._get_overcloud_endpoint(stack),
        })
        with open('overcloudrc', 'w') as f:
            for key, value in rc_params.items():
                f.write("export %(key)s=%(value)s\n" %
                        {'key': key, 'value': value})

    def _update_nodesjson(self, stack):

        with open("instackenv.json") as f:
            instack_env = json.load(f)

            instack_env.setdefault('overcloud', {})
            instack_env['overcloud']['password'] = (
                self.passwords['OVERCLOUD_ADMIN_PASSWORD'])
            instack_env['overcloud']['endpoint'] = (
                self._get_overcloud_endpoint(stack))

        with open("instackenv.json", "w") as f:
            json.dump(instack_env, f)

    def _deploy_postconfig(self, stack, parsed_args):
        self.log.debug("_deploy_postconfig(%s)" % parsed_args)

        passwords = self.passwords

        overcloud_endpoint = self._get_overcloud_endpoint(stack)
        overcloud_ip = six.moves.urllib.parse.urlparse(
            overcloud_endpoint).hostname

        no_proxy = [os.environ.get('no_proxy'), overcloud_ip]
        os.environ['no_proxy'] = ','.join(
            [x for x in no_proxy if x is not None])

        service_ips = self._get_service_ips(stack)

        utils.remove_known_hosts(overcloud_ip)

        keystone_ip = service_ips.get('KeystoneInternalVip')
        if not keystone_ip:
            keystone_ip = overcloud_ip

        keystone.initialize(
            keystone_ip,
            passwords['OVERCLOUD_ADMIN_TOKEN'],
            'admin@example.com',
            passwords['OVERCLOUD_ADMIN_PASSWORD'],
            public=overcloud_ip,
            user='heat-admin')

        # NOTE(bcrochet): Bad hack. Remove the ssl_port info from the
        # os_cloud_config.SERVICES dictionary
        for service_name, data in keystone.SERVICES.iteritems():
            data.pop('ssl_port', None)

        services = {}
        for service, data in six.iteritems(utils.SERVICE_LIST):
            service_data = data.copy()
            service_data.pop('password_field', None)
            password_field = data.get('password_field')
            if password_field:
                service_data['password'] = passwords[password_field]

            service_name = re.sub('v[0-9]+', '',
                                  service.capitalize() + 'InternalVip')
            internal_vip = service_ips.get(service_name)
            if internal_vip:
                service_data['internal_host'] = internal_vip
            services.update({service: service_data})

        keystone_client = clients.get_keystone_client(
            'admin',
            passwords['OVERCLOUD_ADMIN_PASSWORD'],
            'admin',
            overcloud_endpoint)
        keystone.setup_endpoints(
            services,
            client=keystone_client,
            os_auth_url=overcloud_endpoint,
            public_host=overcloud_ip)

        compute_client = clients.get_nova_bm_client(
            'admin',
            passwords['OVERCLOUD_ADMIN_PASSWORD'],
            'admin',
            overcloud_endpoint)
        compute_client.flavors.create('m1.demo', 512, 1, 10, 'auto')

    def get_parser(self, prog_name):
        parser = super(DeployOvercloud, self).get_parser(prog_name)
        main_group = parser.add_mutually_exclusive_group(required=True)
        main_group.add_argument(
            '--plan',
            help=_("The Name or UUID of the Tuskar plan to deploy.")
        )
        main_group.add_argument(
            '--templates', nargs='?', const=TRIPLEO_HEAT_TEMPLATES,
            help=_("The directory containing the Heat templates to deploy"))
        parser.add_argument('-t', '--timeout', metavar='<TIMEOUT>',
                            type=int, default=240,
                            help=_('Deployment timeout in minutes.'))
        parser.add_argument('--control-scale', type=int)
        parser.add_argument('--compute-scale', type=int)
        parser.add_argument('--ceph-storage-scale', type=int)
        parser.add_argument('--block-storage-scale', type=int)
        parser.add_argument('--swift-storage-scale', type=int)
        parser.add_argument('--control-flavor',
                            help=_("Nova flavor to use for control nodes."))
        parser.add_argument('--compute-flavor',
                            help=_("Nova flavor to use for compute nodes."))
        parser.add_argument('--ceph-storage-flavor',
                            help=_("Nova flavor to use for ceph storage "
                                   "nodes."))
        parser.add_argument('--block-storage-flavor',
                            help=_("Nova flavor to use for cinder storage "
                                   "nodes."))
        parser.add_argument('--swift-storage-flavor',
                            help=_("Nova flavor to use for swift storage "
                                   "nodes."))
        parser.add_argument('--neutron-flat-networks')
        parser.add_argument('--neutron-physical-bridge')
        parser.add_argument('--neutron-bridge-mappings')
        parser.add_argument('--neutron-public-interface')
        parser.add_argument('--hypervisor-neutron-public-interface',
                            default='nic1')
        parser.add_argument('--neutron-network-type')
        parser.add_argument('--neutron-tunnel-types')
        parser.add_argument('--neutron-disable-tunneling',
                            dest='neutron_disable_tunneling',
                            action="store_const", const=True),
        parser.add_argument('--neutron-network-vlan-ranges')
        parser.add_argument('--neutron-mechanism-drivers')
        parser.add_argument('--libvirt-type')
        parser.add_argument('--ntp-server')
        parser.add_argument(
            '--tripleo-root',
            default=os.environ.get('TRIPLEO_ROOT', '/etc/tripleo')
        )
        parser.add_argument(
            '--nodes-json',
            default=os.environ.get('NODES_JSON', 'instackenv.json')
        )
        parser.add_argument(
            '--no-proxy',
            default=os.environ.get('no_proxy', '')
        )
        parser.add_argument(
            '-O', '--output-dir', metavar='<OUTPUT DIR>',
            help=_('Directory to write Tuskar template files into. It will be '
                   'created if it does not exist. If not provided a temporary '
                   'directory will be used.')
        )
        parser.add_argument(
            '-e', '--environment-file', metavar='<HEAT ENVIRONMENT FILE>',
            action='append', dest='environment_files',
            help=_('Environment files to be passed to the heat stack-create '
                   'or heat stack-update command. (Can be specified more than '
                   'once.)')
        )
        reg_group = parser.add_argument_group('Registration Parameters')
        reg_group.add_argument(
            '--rhel-reg',
            action='store_true',
            help=_('Register overcloud nodes to the customer portal or a '
                   'satellite')
        )
        reg_group.add_argument(
            '--reg-method',
            choices=['satellite', 'portal'],
            default='satellite',
            help=_('RHEL registration method to use for the overcloud nodes')
        )
        reg_group.add_argument(
            '--reg-org',
            default='',
            help=_('Organization key to use for registration')
        )
        reg_group.add_argument(
            '--reg-force',
            action='store_true',
            help=_('Register the system even if it is already registered')
        )
        reg_group.add_argument(
            '--reg-sat-url',
            default='',
            help=_('Satellite server to register overcloud nodes')
        )
        reg_group.add_argument(
            '--reg-activation-key',
            default='',
            help=_('Activation key to use for registration')
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        clients = self.app.client_manager
        orchestration_client = clients.rdomanager_oscplugin.orchestration()

        stack = self._get_stack(orchestration_client)
        stack_create = stack is None

        self._pre_heat_deploy()

        if parsed_args.rhel_reg:
            if parsed_args.reg_method == 'satellite':
                sat_required_args = (parsed_args.reg_org and
                                     parsed_args.reg_sat_url and
                                     parsed_args.reg_activation_key)
                if not sat_required_args:
                    print(("ERROR: In order to use satellite registration, "
                           "you must specify --reg-org, --reg-sat-url, and "
                           "--reg-activation-key."), file=sys.stderr)
                    return
            else:
                portal_required_args = (parsed_args.reg_org and
                                        parsed_args.reg_activation_key)
                if not portal_required_args:
                    print(("ERROR: In order to use portal registration, you "
                           "must specify --reg-org, and "
                           "--reg-activation-key."), file=sys.stderr)
                    return

        if parsed_args.templates:
            self._deploy_tripleo_heat_templates(stack, parsed_args)
        else:
            self._deploy_tuskar(stack, parsed_args)

        # Get a new copy of the stack after stack update/create. If it was a
        # create then the previous stack object would be None.
        stack = self._get_stack(orchestration_client)

        self._create_overcloudrc(stack, parsed_args)

        self._update_nodesjson(stack)

        if stack_create:
            self._deploy_postconfig(stack, parsed_args)

        overcloud_endpoint = self._get_overcloud_endpoint(stack)
        print("Overcloud Endpoint: {0}".format(overcloud_endpoint))
        print("Overcloud Deployed")
