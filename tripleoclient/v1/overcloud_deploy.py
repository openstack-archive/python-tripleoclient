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

import argparse
import collections
import json
import logging
import os
import re
import six
import sys
import tempfile
import time
import uuid

from cliff import command
from heatclient.common import event_utils
from heatclient.common import template_utils
from keystoneclient import exceptions as kscexc
from openstackclient.common import exceptions as oscexc
from openstackclient.common import utils as osc_utils
from openstackclient.i18n import _
from os_cloud_config import keystone
from os_cloud_config import keystone_pki
from os_cloud_config.utils import clients
from tripleo_common import update

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils


class DeployOvercloud(command.Command):
    """Deploy Overcloud"""

    log = logging.getLogger(__name__ + ".DeployOvercloud")
    predeploy_errors = 0
    predeploy_warnings = 0

    def set_overcloud_passwords(self, parameters, parsed_args):
        """Add passwords to the parameters dictionary

        :param parameters: A dictionary for the passwords to be added to
        :type parameters: dict
        """

        undercloud_ceilometer_snmpd_password = utils.get_config_value(
            "auth", "undercloud_ceilometer_snmpd_password")

        passwords = utils.generate_overcloud_passwords()
        ceilometer_pass = passwords['OVERCLOUD_CEILOMETER_PASSWORD']
        ceilometer_secret = passwords['OVERCLOUD_CEILOMETER_SECRET']
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

    def _update_paramaters(self, args, network_client, stack):
        parameters = constants.PARAMETERS.copy()

        if stack is None:
            parameters.update(constants.NEW_STACK_PARAMETERS)

        self.log.debug("Generating overcloud passwords")
        self.set_overcloud_passwords(parameters, args)

        self.log.debug("Getting ctlplane from Neutron")
        net = network_client.api.find_attr('networks', 'ctlplane')
        parameters['NeutronControlPlaneID'] = net['id']
        timestamp = int(time.time())
        parameters['DeployIdentifier'] = timestamp

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
                ('NeutronTunnelIdRanges', 'neutron_tunnel_id_ranges'),
                ('NeutronTunnelTypes', 'neutron_tunnel_types'),
                ('NeutronVniRanges', 'neutron_vni_ranges'),
                ('NovaComputeLibvirtType', 'libvirt_type'),
            )
            param_args = param_args + new_stack_args

            if args.neutron_disable_tunneling is not None:
                neutron_enable_tunneling = (
                    not args.neutron_disable_tunneling)
                parameters.update({
                    'NeutronEnableTunnelling': neutron_enable_tunneling,
                })

        # Update parameters from commandline
        for param, arg in param_args:
            if getattr(args, arg, None) is not None:
                # these must be converted to [] which is what Heat expects
                if param.endswith(('NeutronTunnelIdRanges',
                                   'NeutronVniRanges')):
                    parameters[param] = [getattr(args, arg)]
                else:
                    parameters[param] = getattr(args, arg)

        # Scaling needs extra parameters
        number_controllers = int(parameters.get('ControllerCount', 0))
        if number_controllers > 1:
            if not args.ntp_server:
                raise exceptions.InvalidConfiguration(
                    'Specify --ntp-server when using multiple controllers '
                    '(with HA).')

            parameters.update({
                'NeutronL3HA': True,
                'NeutronAllowL3AgentFailover': False,
            })
        else:
            parameters.update({
                'NeutronL3HA': False,
                'NeutronAllowL3AgentFailover': False,
            })

        dhcp_agents_per_network = (min(number_controllers, 3) if
                                   number_controllers else 1)

        parameters.update({
            'NeutronDhcpAgentsPerNetwork': dhcp_agents_per_network,
        })

        if int(parameters.get('CephStorageCount', 0)) > 0:

            if stack is None:
                parameters.update({
                    'CephClusterFSID': six.text_type(uuid.uuid1()),
                    'CephMonKey': utils.create_cephx_key(),
                    'CephAdminKey': utils.create_cephx_key()
                })

        return parameters

    def _create_registration_env(self, args):
        tht_root = args.templates

        environment = os.path.join(
            tht_root,
            constants.RHEL_REGISTRATION_EXTRACONFIG_NAME,
            'environment-rhel-registration.yaml')
        registry = os.path.join(
            tht_root,
            constants.RHEL_REGISTRATION_EXTRACONFIG_NAME,
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
        os.close(handle)
        return [registry, environment, user_env_file]

    def _create_parameters_env(self, parameters):
        parameter_defaults = {"parameter_defaults": parameters}
        handle, parameter_defaults_env_file = tempfile.mkstemp()
        with open(parameter_defaults_env_file, 'w') as temp_file:
            temp_file.write(json.dumps(parameter_defaults))
        os.close(handle)
        return [parameter_defaults_env_file]

    def _heat_deploy(self, stack, stack_name, template_path, parameters,
                     environments, timeout):
        """Verify the Baremetal nodes are available and do a stack update"""

        self.log.debug("Processing environment files")
        env_files, env = (
            template_utils.process_multiple_environments_and_files(
                environments))
        if stack:
            update.add_breakpoints_cleanup_into_env(env)

        self.log.debug("Getting template contents")
        template_files, template = template_utils.get_template_contents(
            template_path)

        files = dict(list(template_files.items()) + list(env_files.items()))

        clients = self.app.client_manager
        orchestration_client = clients.tripleoclient.orchestration

        self.log.debug("Deploying stack: %s", stack_name)
        self.log.debug("Deploying template: %s", template)
        self.log.debug("Deploying parameters: %s", parameters)
        self.log.debug("Deploying environment: %s", env)
        self.log.debug("Deploying files: %s", files)

        stack_args = {
            'stack_name': stack_name,
            'template': template,
            'environment': env,
            'files': files
        }

        if timeout:
            stack_args['timeout_mins'] = timeout

        if stack is None:
            self.log.info("Performing Heat stack create")
            action = 'CREATE'
            marker = None
            orchestration_client.stacks.create(**stack_args)
        else:
            self.log.info("Performing Heat stack update")
            # Make sure existing parameters for stack are reused
            stack_args['existing'] = 'true'
            # Find the last top-level event to use for the first marker
            events = event_utils.get_events(orchestration_client,
                                            stack_id=stack_name,
                                            event_args={'sort_dir': 'desc',
                                                        'limit': 1})
            marker = events[0].id if events else None
            action = 'UPDATE'

            orchestration_client.stacks.update(stack.id, **stack_args)

        verbose_events = self.app_args.verbose_level > 0
        create_result = utils.wait_for_stack_ready(
            orchestration_client, stack_name, marker, action, verbose_events)
        if not create_result:
            if stack is None:
                raise exceptions.DeploymentError("Heat Stack create failed.")
            else:
                raise exceptions.DeploymentError("Heat Stack update failed.")

    def _pre_heat_deploy(self):
        """Setup before the Heat stack create or update has been done."""
        clients = self.app.client_manager
        compute_client = clients.compute

        self.log.debug("Checking hypervisor stats")
        if utils.check_hypervisor_stats(compute_client) is None:
            raise exceptions.DeploymentError(
                "Expected hypervisor stats not met")
        return True

    def _deploy_tripleo_heat_templates(self, stack, parsed_args):
        """Deploy the fixed templates in TripleO Heat Templates"""
        clients = self.app.client_manager
        network_client = clients.network

        parameters = self._update_paramaters(
            parsed_args, network_client, stack)

        utils.check_nodes_count(
            self.app.client_manager.tripleoclient.baremetal,
            stack,
            parameters,
            {
                'ControllerCount': 1,
                'ComputeCount': 1,
                'ObjectStorageCount': 0,
                'BlockStorageCount': 0,
                'CephStorageCount': 0,
            }
        )

        tht_root = parsed_args.templates

        print("Deploying templates in the directory {0}".format(
            os.path.abspath(tht_root)))

        self.log.debug("Creating Environment file")
        # TODO(jprovazn): env file generated by create_environment_file()
        # is not very usable any more, scale params are included in
        # parameters and keystone cert is generated on create only
        env_path = utils.create_environment_file()
        environments = []
        add_registry = False

        if stack is None:
            self.log.debug("Creating Keystone certificates")
            keystone_pki.generate_certs_into_json(env_path, False)
            environments.append(env_path)
            add_registry = True

        environments.extend(self._create_parameters_env(parameters))
        if parsed_args.rhel_reg:
            reg_env = self._create_registration_env(parsed_args)
            environments.extend(reg_env)
            add_registry = True
        if parsed_args.environment_files:
            environments.extend(parsed_args.environment_files)
            add_registry = True

        if add_registry:
            # default resource registry file should be passed only
            # when creating a new stack, or when custom environments are
            # specified, otherwise it might overwrite
            # resource_registries in existing stack
            resource_registry_path = os.path.join(
                tht_root, constants.RESOURCE_REGISTRY_NAME)
            environments.insert(0, resource_registry_path)

        overcloud_yaml = os.path.join(tht_root, constants.OVERCLOUD_YAML_NAME)

        self._heat_deploy(stack, parsed_args.stack, overcloud_yaml, parameters,
                          environments, parsed_args.timeout)

    def _deploy_postconfig(self, stack, parsed_args):
        self.log.debug("_deploy_postconfig(%s)" % parsed_args)

        overcloud_endpoint = utils.get_overcloud_endpoint(stack)
        overcloud_ip = six.moves.urllib.parse.urlparse(
            overcloud_endpoint).hostname

        no_proxy = [os.environ.get('no_proxy'), overcloud_ip]
        os.environ['no_proxy'] = ','.join(
            [x for x in no_proxy if x is not None])

        service_ips = utils.get_service_ips(stack)

        utils.remove_known_hosts(overcloud_ip)

        keystone_ip = service_ips.get('KeystoneAdminVip')
        if not keystone_ip:
            keystone_ip = overcloud_ip

        # Note (spredzy): This was deprecated at the begining of
        # the Mitaka cycle. Should be good to remove for the
        # next N cycle.
        keystone.initialize(
            keystone_ip,
            utils.get_password('OVERCLOUD_ADMIN_TOKEN'),
            'admin@example.com',
            utils.get_password('OVERCLOUD_ADMIN_PASSWORD'),
            public=overcloud_ip,
            user=parsed_args.overcloud_ssh_user)

        # NOTE(bcrochet): Bad hack. Remove the ssl_port info from the
        # os_cloud_config.SERVICES dictionary
        for service_name, data in keystone.SERVICES.iteritems():
            data.pop('ssl_port', None)

        services = {}
        for service, data in six.iteritems(constants.SERVICE_LIST):
            service_data = data.copy()
            service_data.pop('password_field', None)
            password_field = data.get('password_field')
            if password_field:
                service_data['password'] = utils.get_password(password_field)

            service_name = re.sub('v[0-9]+', '',
                                  service.capitalize() + 'InternalVip')
            internal_vip = service_ips.get(service_name)
            if internal_vip:
                service_data['internal_host'] = internal_vip
            services.update({service: service_data})

        # Note (spredzy): This was deprecated at the begining of
        # the Mitaka cycle. Should be good to remove for the
        # next N cycle.
        try:
            keystone_client = clients.get_keystone_client(
                'admin',
                utils.get_password('OVERCLOUD_ADMIN_PASSWORD'),
                'admin',
                overcloud_endpoint)
            keystone.setup_endpoints(
                services,
                client=keystone_client,
                os_auth_url=overcloud_endpoint,
                public_host=overcloud_ip)
        except kscexc.Conflict:
            pass
        else:
            self.log.warning("Setting up keystone endpoints via "
                             "os-cloud-config. This behavior is "
                             "deprecated and will be removed in "
                             "a future release.  Please update "
                             "your heat templates to a version "
                             "that does Keystone initialization "
                             "via Puppet.")

        compute_client = clients.get_nova_bm_client(
            'admin',
            utils.get_password('OVERCLOUD_ADMIN_PASSWORD'),
            'admin',
            overcloud_endpoint)
        compute_client.flavors.create('m1.demo', 512, 1, 10, 'auto')

    def _validate_args(self, parsed_args):
        network_type = parsed_args.neutron_network_type
        tunnel_types = parsed_args.neutron_tunnel_types
        tunnel_disabled = parsed_args.neutron_disable_tunneling
        neutron_network_vlan_ranges = parsed_args.neutron_network_vlan_ranges
        if network_type == 'vlan' and not neutron_network_vlan_ranges:
            raise oscexc.CommandError(
                "Neutron network VLAN ranges must be specified when the "
                "network type is set to VLAN")
        elif network_type and tunnel_types:
            # Validate that neutron_network_type is in neutron_tunnel_types
            if network_type not in tunnel_types:
                raise oscexc.CommandError("Neutron network type must be in "
                                          "Neutron tunnel types "
                                          "(%s) " % tunnel_types)
        elif not tunnel_disabled:
            if network_type and not tunnel_types:
                raise oscexc.CommandError("Neutron tunnel types must be "
                                          "specified when Neutron network "
                                          "type is specified")
            elif tunnel_types and not network_type:
                raise oscexc.CommandError("Neutron network type must be "
                                          "specified when Neutron tunnel "
                                          "types is specified")

    def _predeploy_verify_capabilities(self, parsed_args):
        self.predeploy_errors = 0
        self.predeploy_warnings = 0
        self.log.debug("Starting _pre_verify_capabilities")

        bm_client = self.app.client_manager.tripleoclient.baremetal

        self._check_boot_images()

        self._check_flavors_exist(parsed_args)

        self._check_ironic_boot_configuration(bm_client)

        flavor_profile_map = self._collect_flavor_profiles([
            parsed_args.control_flavor,
            parsed_args.compute_flavor,
            parsed_args.ceph_storage_flavor,
            parsed_args.block_storage_flavor,
            parsed_args.swift_storage_flavor,
        ])
        node_profile_map = self._collect_node_profiles()

        for target, flavor, scale in [
            ('control', parsed_args.control_flavor,
                parsed_args.control_scale),
            ('compute', parsed_args.compute_flavor,
                parsed_args.compute_scale),
            ('ceph-storage', parsed_args.ceph_storage_flavor,
                parsed_args.ceph_storage_scale),
            ('block-storage', parsed_args.block_storage_flavor,
                parsed_args.block_storage_scale),
            ('swift-storage', parsed_args.swift_storage_flavor,
                parsed_args.swift_storage_scale),
        ]:
            if scale == 0 or flavor is None:
                self.log.debug("Skipping verification of %s profiles because "
                               "none will be deployed", flavor)
                continue
            self._check_profiles(
                target, flavor, scale,
                flavor_profile_map,
                node_profile_map)

        if (node_profile_map.get(None) and
            any([parsed_args.block_storage_flavor,
                 parsed_args.ceph_storage_flavor,
                 parsed_args.compute_flavor,
                 parsed_args.control_flavor,
                 parsed_args.swift_storage_flavor])):
            self.predeploy_warnings += 1
            self.log.warning(
                "There are %d ironic nodes with no profile that will "
                "not be used: %s",
                len(node_profile_map[None]),
                ', '.join(node_profile_map[None])
            )

        return self.predeploy_errors, self.predeploy_warnings

    __kernel_id = None
    __ramdisk_id = None

    def _image_ids(self):
        if self.__kernel_id is not None and self.__ramdisk_id is not None:
            return self.__kernel_id, self.__ramdisk_id

        image_client = self.app.client_manager.image
        kernel_id, ramdisk_id = None, None
        try:
            kernel_id = osc_utils.find_resource(
                image_client.images, 'bm-deploy-kernel').id
        except AttributeError:
            self.log.exception("Please make sure there is only one image "
                               "named 'bm-deploy-kernel' in glance.")
        except oscexc.CommandError:
            self.log.exception("Error finding 'bm-deploy-kernel' in "
                               "glance.")

        try:
            ramdisk_id = osc_utils.find_resource(
                image_client.images, 'bm-deploy-ramdisk').id
        except AttributeError:
            self.log.exception("Please make sure there is only one image "
                               "named 'bm-deploy-ramdisk' in glance.")
        except oscexc.CommandError:
            self.log.exception("Error finding 'bm-deploy-ramdisk' in "
                               "glance.")

        self.log.debug("Using kernel ID: {0} and ramdisk ID: {1}".format(
            kernel_id, ramdisk_id))

        self.__kernel_id = kernel_id
        self.__ramdisk_id = ramdisk_id
        return kernel_id, ramdisk_id

    def _collect_node_profiles(self):
        """Gather a map of profile -> [node_uuid] for ironic boot profiles"""
        bm_client = self.app.client_manager.tripleoclient.baremetal

        # map of profile capability -> [node_uuid, ...]
        profile_map = collections.defaultdict(list)

        for node in bm_client.node.list(maintenance=False):
            node = bm_client.node.get(node.uuid)
            profiles = re.findall(r'profile:(.*?)(?:,|$)',
                                  node.properties.get('capabilities', ''))
            if not profiles:
                profile_map[None].append(node.uuid)
            for p in profiles:
                profile_map[p].append(node.uuid)

        return dict(profile_map)

    def _collect_flavor_profiles(self, flavors):
        compute_client = self.app.client_manager.compute

        flavor_profiles = {}

        for flavor in compute_client.flavors.list():
            if flavor.name not in flavors:
                self.log.debug("Flavor {} isn't used in this deployment, "
                               "skipping it".format(flavor.name))
                continue

            profile = flavor.get_keys().get('capabilities:profile')
            if profile == '':
                flavor_profiles[flavor.name] = None
            else:
                flavor_profiles[flavor.name] = profile

            if flavor.get_keys().get('capabilities:boot_option', '') \
                    != 'local':
                self.predeploy_warnings += 1
                self.log.error(
                    'Flavor %s "capabilities:boot_option" is not set to '
                    '"local". Nodes must have ability to PXE boot from '
                    'deploy image.', flavor.name)
                self.log.error(
                    'Recommended solution: openstack flavor set --property '
                    '"cpu_arch"="x86_64" --property '
                    '"capabilities:boot_option"="local" ' + flavor.name)

        return flavor_profiles

    def _check_profiles(self, target, flavor, scale,
                        flavor_profile_map,
                        node_profile_map):
        if flavor_profile_map.get(flavor) is None:
            self.predeploy_errors += 1
            self.log.error(
                'Warning: The flavor selected for --%s-flavor "%s" has no '
                'profile associated', target, flavor)
            self.log.error(
                'Recommendation: assign a profile with openstack flavor set '
                '--property "capabilities:profile"="PROFILE_NAME" %s',
                flavor)
            return

        if len(node_profile_map.get(flavor_profile_map[flavor], [])) < scale:
            self.predeploy_errors += 1
            self.log.error(
                "Error: %s of %s requested ironic nodes tagged to profile %s "
                "(for flavor %s)",
                len(node_profile_map.get(flavor_profile_map[flavor], [])),
                scale, flavor_profile_map[flavor], flavor
            )
            self.log.error(
                "Recommendation: tag more nodes using ironic node-update "
                "<NODE ID> replace properties/capabilities=profile:%s,"
                "boot_option:local", flavor_profile_map[flavor])

    def _check_boot_images(self):
        kernel_id, ramdisk_id = self._image_ids()
        message = ("No image with the name '{}' found - make "
                   "sure you've uploaded boot images")
        if kernel_id is None:
            self.predeploy_errors += 1
            self.log.error(message.format('bm-deploy-kernel'))
        if ramdisk_id is None:
            self.predeploy_errors += 1
            self.log.error(message.format('bm-deploy-ramdisk'))

    def _check_flavors_exist(self, parsed_args):
        """Ensure that selected flavors (--ROLE-flavor) exist in nova."""
        compute_client = self.app.client_manager.compute

        flavors = {f.name: f for f in compute_client.flavors.list()}

        message = "Provided --{}-flavor, '{}', does not exist"

        for target, flavor, scale in (
            ('control', parsed_args.control_flavor,
                parsed_args.control_scale),
            ('compute', parsed_args.compute_flavor,
                parsed_args.compute_scale),
            ('ceph-storage', parsed_args.ceph_storage_flavor,
                parsed_args.ceph_storage_scale),
            ('block-storage', parsed_args.block_storage_flavor,
                parsed_args.block_storage_scale),
            ('swift-storage', parsed_args.swift_storage_flavor,
                parsed_args.swift_storage_scale),
        ):
            if flavor is None or scale == 0:
                self.log.debug("--{}-flavor not used".format(target))
            elif flavor not in flavors:
                self.predeploy_errors += 1
                self.log.error(message.format(target, flavor))

    def _check_ironic_boot_configuration(self, bm_client):
        for node in bm_client.node.list(detail=True, maintenance=False):
            self.log.debug("Checking config for Node {0}".format(node.uuid))
            self._check_node_boot_configuration(node)

    def _check_node_boot_configuration(self, node):
        kernel_id, ramdisk_id = self._image_ids()
        self.log.debug("Doing boot checks for {}".format(node.uuid))
        message = ("Node uuid={uuid} has an incorrectly configured "
                   "{property}. Expected \"{expected}\" but got "
                   "\"{actual}\".")
        if node.driver_info.get('deploy_ramdisk') != ramdisk_id:
            self.predeploy_errors += 1
            self.log.error(message.format(
                uuid=node.uuid,
                property='driver_info/deploy_ramdisk',
                expected=ramdisk_id,
                actual=node.driver_info.get('deploy_ramdisk')
            ))
        if node.driver_info.get('deploy_kernel') != kernel_id:
            self.predeploy_errors += 1
            self.log.error(message.format(
                uuid=node.uuid,
                property='driver_info/deploy_kernel',
                expected=ramdisk_id,
                actual=node.driver_info.get('deploy_kernel')
            ))
        if 'boot_option:local' not in node.properties.get('capabilities', ''):
            self.predeploy_warnings += 1
            self.log.warning(message.format(
                uuid=node.uuid,
                property='properties/capabilities',
                expected='boot_option:local',
                actual=node.properties.get('capabilities')
            ))

    def get_parser(self, prog_name):
        # add_help doesn't work properly, set it to False:
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False
        )
        parser.add_argument(
            '--templates', nargs='?', const=constants.TRIPLEO_HEAT_TEMPLATES,
            help=_("The directory containing the Heat templates to deploy"),
            required=True
        )
        parser.add_argument('--stack',
                            help=_("Stack name to create or update"),
                            default='overcloud')
        parser.add_argument('-t', '--timeout', metavar='<TIMEOUT>',
                            type=int, default=240,
                            help=_('Deployment timeout in minutes.'))
        parser.add_argument('--control-scale', type=int,
                            help=_('New number of control nodes.'))
        parser.add_argument('--compute-scale', type=int,
                            help=_('New number of compute nodes.'))
        parser.add_argument('--ceph-storage-scale', type=int,
                            help=_('New number of ceph storage nodes.'))
        parser.add_argument('--block-storage-scale', type=int,
                            help=_('New number of cinder storage nodes.'))
        parser.add_argument('--swift-storage-scale', type=int,
                            help=_('New number of swift storage nodes.'))
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
        parser.add_argument('--neutron-flat-networks',
                            help=_('Comma separated list of physical_network '
                                   'names with which flat networks can be '
                                   'created. Use * to allow flat networks '
                                   'with arbitrary physical_network names. '
                                   '(DEPRECATED)'))
        parser.add_argument('--neutron-physical-bridge',
                            help=_('Deprecated.'))
        parser.add_argument('--neutron-bridge-mappings',
                            help=_('Comma separated list of bridge mappings. '
                                   '(default: datacentre:br-ex) '
                                   '(DEPRECATED)'))
        parser.add_argument('--neutron-public-interface',
                            help=_('Deprecated.'))
        parser.add_argument('--neutron-network-type',
                            help=_('The network type for tenant networks. '
                                   '(DEPRECATED)'))
        parser.add_argument('--neutron-tunnel-types',
                            help=_('Network types supported by the agent '
                                   '(gre and/or vxlan). '
                                   '(DEPRECATED)'))
        parser.add_argument('--neutron-tunnel-id-ranges',
                            default="1:1000",
                            help=_("Ranges of GRE tunnel IDs to make "
                                   "available for tenant network allocation "
                                   "(DEPRECATED)"),)
        parser.add_argument('--neutron-vni-ranges',
                            default="1:1000",
                            help=_("Ranges of VXLAN VNI IDs to make "
                                   "available for tenant network allocation "
                                   "(DEPRECATED)"),)
        parser.add_argument('--neutron-disable-tunneling',
                            dest='neutron_disable_tunneling',
                            action="store_const", const=True,
                            help=_('Disables tunneling. (DEPRECATED)')),
        parser.add_argument('--neutron-network-vlan-ranges',
                            help=_('Comma separated list of '
                                   '<physical_network>:<vlan_min>:<vlan_max> '
                                   'or <physical_network> specifying '
                                   'physical_network names usable for VLAN '
                                   'provider and tenant networks, as well as '
                                   'ranges of VLAN tags on each available for '
                                   'allocation to tenant networks. '
                                   '(ex: datacentre:1:1000) (DEPRECATED)'))
        parser.add_argument('--neutron-mechanism-drivers',
                            help=_('An ordered list of extension driver '
                                   'entrypoints to be loaded from the '
                                   'neutron.ml2.extension_drivers namespace. '
                                   '(DEPRECATED)'))
        parser.add_argument('--libvirt-type',
                            default='kvm',
                            choices=['kvm', 'qemu'],
                            help=_('Libvirt domain type. (default: kvm)'))
        parser.add_argument('--ntp-server',
                            help=_('The NTP for overcloud nodes. '))
        parser.add_argument(
            '--no-proxy',
            default=os.environ.get('no_proxy', ''),
            help=_('A comma separated list of hosts that should not be '
                   'proxied.')
        )
        parser.add_argument(
            '--overcloud-ssh-user',
            default='heat-admin',
            help=_('User for ssh access to overcloud nodes')
        )
        parser.add_argument(
            '-e', '--environment-file', metavar='<HEAT ENVIRONMENT FILE>',
            action='append', dest='environment_files',
            help=_('Environment files to be passed to the heat stack-create '
                   'or heat stack-update command. (Can be specified more than '
                   'once.)')
        )
        parser.add_argument(
            '--validation-errors-fatal',
            action='store_true',
            default=False,
            help=_('Exit if there are errors from the configuration '
                   'pre-checks. Ignoring these errors will likely cause your '
                   'deploy to fail.')
        )
        parser.add_argument(
            '--validation-warnings-fatal',
            action='store_true',
            default=False,
            help=_('Exit if there are warnings from the configuration '
                   'pre-checks.')
        )
        reg_group = parser.add_argument_group('Registration Parameters')
        reg_group.add_argument(
            '--rhel-reg',
            action='store_true',
            help=_('Register overcloud nodes to the customer portal or a '
                   'satellite.')
        )
        reg_group.add_argument(
            '--reg-method',
            choices=['satellite', 'portal'],
            default='satellite',
            help=_('RHEL registration method to use for the overcloud nodes.')
        )
        reg_group.add_argument(
            '--reg-org',
            default='',
            help=_('Organization key to use for registration.')
        )
        reg_group.add_argument(
            '--reg-force',
            action='store_true',
            help=_('Register the system even if it is already registered.')
        )
        reg_group.add_argument(
            '--reg-sat-url',
            default='',
            help=_('Satellite server to register overcloud nodes.')
        )
        reg_group.add_argument(
            '--reg-activation-key',
            default='',
            help=_('Activation key to use for registration.')
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        self._validate_args(parsed_args)

        errors, warnings = self._predeploy_verify_capabilities(parsed_args)
        if errors > 0:
            self.log.error(
                "Configuration has %d errors, fix them before proceeding. "
                "Ignoring these errors is likely to lead to a failed deploy.",
                errors)
            if parsed_args.validation_warnings_fatal or \
                    parsed_args.validation_errors_fatal:
                return
        if warnings > 0:
            self.log.error(
                "Configuration has %d warnings, fix them before proceeding. ",
                warnings)
            if parsed_args.validation_warnings_fatal:
                return
        else:
            self.log.info("SUCCESS: No warnings or errors in deploy "
                          "configuration, proceeding.")

        clients = self.app.client_manager
        orchestration_client = clients.tripleoclient.orchestration

        stack = utils.get_stack(orchestration_client, parsed_args.stack)
        stack_create = stack is None
        if stack_create:
            self.log.info("No stack found, will be doing a stack create")
        else:
            self.log.info("Stack found, will be doing a stack update")

        try:
            self._pre_heat_deploy()

            if parsed_args.rhel_reg:
                if parsed_args.reg_method == 'satellite':
                    sat_required_args = (parsed_args.reg_org and
                                         parsed_args.reg_sat_url and
                                         parsed_args.reg_activation_key)
                    if not sat_required_args:
                        raise exceptions.DeploymentError(
                            "ERROR: In order to use satellite registration, "
                            "you must specify --reg-org, --reg-sat-url, and "
                            "--reg-activation-key.")
                else:
                    portal_required_args = (parsed_args.reg_org and
                                            parsed_args.reg_activation_key)
                    if not portal_required_args:
                        raise exceptions.DeploymentError(
                            "ERROR: In order to use portal registration, you "
                            "must specify --reg-org, and "
                            "--reg-activation-key.")

            self._deploy_tripleo_heat_templates(stack, parsed_args)

            # Get a new copy of the stack after stack update/create. If it was
            # a create then the previous stack object would be None.
            stack = utils.get_stack(orchestration_client, parsed_args.stack)

            utils.create_overcloudrc(stack, parsed_args.no_proxy)
            utils.create_tempest_deployer_input()

            if stack_create:
                self._deploy_postconfig(stack, parsed_args)

            overcloud_endpoint = utils.get_overcloud_endpoint(stack)
            print("Overcloud Endpoint: {0}".format(overcloud_endpoint))
            print("Overcloud Deployed")
            return True
        except exceptions.DeploymentError as err:
            print("Deployment failed: ", err, file=sys.stderr)
            return False
