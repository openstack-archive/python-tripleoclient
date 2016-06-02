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
import csv
import json
import logging
import time
import yaml

from cliff import command
from cliff import lister
import ironic_inspector_client
from openstackclient.common import utils as osc_utils
from openstackclient.i18n import _
from oslo_utils import units
from tripleo_common.utils import nodes

from tripleoclient import exceptions
from tripleoclient import utils


def _csv_to_nodes_dict(nodes_csv):
    """Convert CSV to a list of dicts formatted for os_cloud_config

    Given a CSV file in the format below, convert it into the
    structure expected by os_cloud_config JSON files.

    pm_type, pm_addr, pm_user, pm_password, mac
    """

    data = []

    for row in csv.reader(nodes_csv):
        node = {
            "pm_user": row[2],
            "pm_addr": row[1],
            "pm_password": row[3],
            "pm_type": row[0],
            "mac": [
                row[4]
            ]
        }
        data.append(node)

    return data


class ValidateInstackEnv(command.Command):
    """Validate `instackenv.json` which is used in `baremetal import`."""

    auth_required = False
    log = logging.getLogger(__name__ + ".ValidateInstackEnv")

    def get_parser(self, prog_name):
        parser = super(ValidateInstackEnv, self).get_parser(prog_name)
        parser.add_argument(
            '-f', '--file', dest='instackenv',
            help="Path to the instackenv.json file.",
            default='instackenv.json')
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        self.error_count = 0

        with open(parsed_args.instackenv, 'r') as net_file:
            env_data = json.load(net_file)

        maclist = []
        baremetal_ips = []
        for node in env_data['nodes']:
            self.log.info("Checking node %s" % node['pm_addr'])

            try:
                if len(node['pm_password']) == 0:
                    self.log.error('ERROR: Password 0 length.')
                    self.error_count += 1
            except Exception as e:
                self.log.error('ERROR: Password does not exist: %s', e)
                self.error_count += 1
            try:
                if len(node['pm_user']) == 0:
                    self.log.error('ERROR: User 0 length.')
                    self.error_count += 1
            except Exception as e:
                self.log.error('ERROR: User does not exist: %s', e)
                self.error_count += 1
            try:
                if len(node['mac']) == 0:
                    self.log.error('ERROR: MAC address 0 length.')
                    self.error_count += 1
                maclist.extend(node['mac'])
            except Exception as e:
                self.log.error('ERROR: MAC address does not exist: %s', e)
                self.error_count += 1

            if node['pm_type'] == "pxe_ssh":
                self.log.debug("Identified virtual node")

            if node['pm_type'] == "pxe_ipmitool":
                self.log.debug("Identified baremetal node")

                cmd = ('ipmitool -R 1 -I lanplus -H %s -U %s -P %s chassis '
                       'status' % (node['pm_addr'], node['pm_user'],
                                   node['pm_password']))
                self.log.debug("Executing: %s", cmd)
                status = utils.run_shell(cmd)
                if status != 0:
                    self.log.error('ERROR: ipmitool failed')
                    self.error_count += 1
                baremetal_ips.append(node['pm_addr'])

        if not utils.all_unique(baremetal_ips):
            self.log.error('ERROR: Baremetals IPs are not all unique.')
            self.error_count += 1
        else:
            self.log.debug('Baremetal IPs are all unique.')

        if not utils.all_unique(maclist):
            self.log.error('ERROR: MAC addresses are not all unique.')
            self.error_count += 1
        else:
            self.log.debug('MAC addresses are all unique.')

        if self.error_count == 0:
            print('SUCCESS: found 0 errors')
        else:
            print('FAILURE: found %d errors' % self.error_count)


class ImportBaremetal(command.Command):
    """Import baremetal nodes from a JSON, YAML or CSV file"""

    log = logging.getLogger(__name__ + ".ImportBaremetal")

    def get_parser(self, prog_name):
        parser = super(ImportBaremetal, self).get_parser(prog_name)
        parser.add_argument('-s', '--service-host', dest='service_host',
                            help='Nova compute service host to register nodes '
                            'with')
        parser.add_argument(
            '--json', dest='json', action='store_true',
            help=_('Deprecated, now detected via file extension.'))
        parser.add_argument(
            '--csv', dest='csv', action='store_true',
            help=_('Deprecated, now detected via file extension.'))
        parser.add_argument('--deploy-kernel',
                            default='bm-deploy-kernel',
                            help='Image with deploy kernel.')
        parser.add_argument('--deploy-ramdisk',
                            default='bm-deploy-ramdisk',
                            help='Image with deploy ramdisk.')
        parser.add_argument('--no-deploy-image', action='store_true',
                            help='Skip setting the deploy kernel and ramdisk.')
        parser.add_argument('--instance-boot-option',
                            choices=['local', 'netboot'], default='local',
                            help='Whether to set instances for booting from '
                            'local hard drive (local) or network (netboot).')
        parser.add_argument('file_in', type=argparse.FileType('r'))
        parser.add_argument(
            '--initial-state',
            choices=['enroll', 'available'],
            default='available',
            help='Provision state for newly-enrolled nodes.'
        )

        return parser

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)

        if parsed_args.json or parsed_args.file_in.name.endswith('.json'):
            nodes_config = json.load(parsed_args.file_in)
        elif parsed_args.csv or parsed_args.file_in.name.endswith('.csv'):
            nodes_config = _csv_to_nodes_dict(parsed_args.file_in)
        elif parsed_args.file_in.name.endswith('.yaml'):
            nodes_config = yaml.safe_load(parsed_args.file_in)
        else:
            raise exceptions.InvalidConfiguration(
                _("Invalid file extension for %s, must be json, yaml or csv") %
                parsed_args.file_in.name)

        if 'nodes' in nodes_config:
            nodes_config = nodes_config['nodes']

        client = self.app.client_manager.baremetal
        if parsed_args.initial_state == "enroll":
            api_version = client.http_client.os_ironic_api_version
            if [int(part) for part in api_version.split('.')] < [1, 11]:
                raise exceptions.InvalidConfiguration(
                    _("OS_BAREMETAL_API_VERSION must be >=1.11 for use of "
                      "'enroll' provision state; currently %s") % api_version)

        for node in nodes_config:
            caps = utils.capabilities_to_dict(node.get('capabilities', {}))
            caps.setdefault('boot_option', parsed_args.instance_boot_option)
            node['capabilities'] = utils.dict_to_capabilities(caps)

        new_nodes = nodes.register_all_nodes(
            parsed_args.service_host,
            nodes_config,
            client=client,
            keystone_client=self.app.client_manager.identity,
            glance_client=self.app.client_manager.image,
            kernel_name=(parsed_args.deploy_kernel if not
                         parsed_args.no_deploy_image else None),
            ramdisk_name=(parsed_args.deploy_ramdisk if not
                          parsed_args.no_deploy_image else None))

        if parsed_args.initial_state == "available":
            manageable_node_uuids = list(utils.set_nodes_state(
                client, new_nodes, "manage", "manageable",
                skipped_states={'manageable', 'available'}
            ))
            manageable_nodes = [
                n for n in new_nodes if n.uuid in manageable_node_uuids
            ]
            list(utils.set_nodes_state(
                client, manageable_nodes, "provide", "available",
                skipped_states={'available'}
            ))


class StartBaremetalIntrospectionBulk(command.Command):
    """Start bulk introspection on all baremetal nodes"""

    log = logging.getLogger(__name__ + ".StartBaremetalIntrospectionBulk")

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)
        client = self.app.client_manager.baremetal
        inspector_client = self.app.client_manager.baremetal_introspection

        node_uuids = []

        print("Setting nodes for introspection to manageable...")
        self.log.debug("Moving available/enroll nodes to manageable state.")
        available_nodes = utils.nodes_in_states(client,
                                                ("available", "enroll"))
        for uuid in utils.set_nodes_state(client, available_nodes, 'manage',
                                          'manageable'):
            self.log.debug("Node {0} has been set to manageable.".format(uuid))

        manageable_nodes = utils.nodes_in_states(client, ("manageable",))
        for node in manageable_nodes:
            node_uuids.append(node.uuid)

            print("Starting introspection of node: {0}".format(node.uuid))
            inspector_client.introspect(node.uuid)

        print("Waiting for introspection to finish...")
        errors = []
        successful_node_uuids = set()
        results = inspector_client.wait_for_finish(node_uuids)
        for uuid, status in results.items():
            if status['error'] is None:
                print("Introspection for UUID {0} finished successfully."
                      .format(uuid))
                successful_node_uuids.add(uuid)
            else:
                print("Introspection for UUID {0} finished with error: {1}"
                      .format(uuid, status['error']))
                errors.append("%s: %s" % (uuid, status['error']))

        print("Setting manageable nodes to available...")

        self.log.debug("Moving manageable nodes to available state.")
        successful_nodes = [n for n in manageable_nodes
                            if n.uuid in successful_node_uuids]
        for uuid in utils.set_nodes_state(
                client, successful_nodes, 'provide',
                'available', skipped_states=("available", "active")):
            print("Node {0} has been set to available.".format(uuid))

        if errors:
            raise exceptions.IntrospectionError(
                "Introspection completed with errors:\n%s" % '\n'.join(errors))
        else:
            print("Introspection completed.")


class StatusBaremetalIntrospectionBulk(lister.Lister):
    """Get the status of all baremetal nodes"""

    log = logging.getLogger(__name__ + ".StatusBaremetalIntrospectionBulk")

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)
        client = self.app.client_manager.baremetal
        inspector_client = self.app.client_manager.baremetal_introspection

        statuses = []

        for node in client.node.list():
            self.log.debug("Getting introspection status of Ironic node {0}"
                           .format(node.uuid))

            statuses.append((node.uuid,
                             inspector_client.get_status(node.uuid)))

        return (
            ("Node UUID", "Finished", "Error"),
            list((node_uuid, status['finished'], status['error'])
                 for (node_uuid, status) in statuses)
        )


class ConfigureReadyState(command.Command):
    """Configure all baremetal nodes for enrollment"""

    log = logging.getLogger(__name__ + ".ConfigureReadyState")
    sleep_time = 15
    loops = 120

    def _configure_bios(self, nodes):
        nodes_with_reboot_request = set()

        for node, profile in nodes:
            if (profile in self.ready_state_config and
                    'bios_settings' in self.ready_state_config[profile]):

                print("Configuring BIOS for node {0}".format(node.uuid))
                settings = self.ready_state_config[profile]['bios_settings']
                resp = self.bm_client.node.vendor_passthru(
                    node.uuid, 'set_bios_config', http_method='POST',
                    args=settings)

                if resp.commit_required:
                    nodes_with_reboot_request.add(node)
                    self.bm_client.node.vendor_passthru(
                        node.uuid, 'commit_bios_config', http_method='POST')

        # NOTE(ifarkas): give the DRAC card some time to process the job
        time.sleep(self.sleep_time)

        return nodes_with_reboot_request

    def _wait_for_drac_config_jobs(self, nodes):
        for node in nodes:
            print("Waiting for DRAC config jobs to finish on node {0}"
                  .format(node.uuid))

            for _r in range(self.loops):
                resp = self.bm_client.node.vendor_passthru(
                    node.uuid, 'list_unfinished_jobs', http_method='GET')
                if not resp.unfinished_jobs:
                    break

                time.sleep(self.sleep_time)
            else:
                msg = ("Timed out waiting for DRAC config jobs on node {0}"
                       .format(node.uuid))
                raise exceptions.Timeout(msg)

    def _change_power_state(self, nodes, target_power_state):
        for node in nodes:
            print("Changing power state on "
                  "node {0} to {1}".format(node.uuid, target_power_state))
            self.bm_client.node.set_power_state(node.uuid, target_power_state)

    def _apply_changes(self, nodes):
        self._change_power_state(nodes, 'reboot')
        self._wait_for_drac_config_jobs(nodes)

    def get_parser(self, prog_name):
        parser = super(ConfigureReadyState, self).get_parser(prog_name)
        parser.add_argument('file', help='JSON file containing the '
                            'ready-state configuration for each profile')

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        self.bm_client = self.app.client_manager.baremetal

        with open(parsed_args.file, 'r') as fp:
            self.ready_state_config = json.load(fp)

        drac_nodes = []
        for node in self.bm_client.node.list(detail=True):
            if 'drac' not in node.driver:
                continue

            selected_profile = utils.node_get_capabilities(node).get('profile')
            if selected_profile is None:
                continue

            drac_nodes.append((node, selected_profile))

        changed_nodes = self._configure_bios(drac_nodes)
        self._apply_changes(changed_nodes)

        self._change_power_state([node for node, profile in drac_nodes], 'off')


class ConfigureBaremetalBoot(command.Command):
    """Configure baremetal boot for all nodes"""

    log = logging.getLogger(__name__ + ".ConfigureBaremetalBoot")
    loops = 12
    sleep_time = 10

    def get_parser(self, prog_name):
        parser = super(ConfigureBaremetalBoot, self).get_parser(prog_name)
        parser.add_argument('--deploy-kernel',
                            default='bm-deploy-kernel',
                            help='Image with deploy kernel.')
        parser.add_argument('--deploy-ramdisk',
                            default='bm-deploy-ramdisk',
                            help='Image with deploy ramdisk.')
        parser.add_argument('--root-device',
                            help='Define the root device for nodes. '
                            'Can be either a list of device names (without '
                            '/dev) to choose from or one of two strategies: '
                            'largest or smallest. For it to work this command '
                            'should be run after the introspection.')
        parser.add_argument('--root-device-minimum-size',
                            type=int, default=4,
                            help='Minimum size (in GiB) of the detected '
                            'root device. Used with --root-device.')
        parser.add_argument('--overwrite-root-device-hints',
                            action='store_true',
                            help='Whether to overwrite existing root device '
                            'hints when --root-device is used.')
        return parser

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)
        bm_client = self.app.client_manager.baremetal

        image_client = self.app.client_manager.image

        try:
            kernel_id = osc_utils.find_resource(
                image_client.images, parsed_args.deploy_kernel).id
        except AttributeError:
            self.log.error("Please make sure that an image named \"%s\" exists"
                           " in Glance and is the only image with this name."
                           % parsed_args.deploy_ramdisk)
            return

        try:
            ramdisk_id = osc_utils.find_resource(
                image_client.images, parsed_args.deploy_ramdisk).id
        except AttributeError:
            self.log.error("Please make sure that an image named \"%s\" exists"
                           " in Glance and is the only image with this name."
                           % parsed_args.deploy_ramdisk)
            return

        self.log.debug("Using kernel ID: {0} and ramdisk ID: {1}".format(
            kernel_id, ramdisk_id))

        for node in bm_client.node.list(maintenance=False):
            # NOTE(bnemec): Ironic won't let us update the node while the
            # power_state is transitioning.
            # Make sure we have the current node state, and not a cached one
            # from the list call above, which may have happened minutes ago.
            node_detail = bm_client.node.get(node.uuid)
            if node_detail.power_state is None:
                self.log.warning('Node %s power state is in transition. '
                                 'Waiting up to %d seconds for it to '
                                 'complete.',
                                 node_detail.uuid,
                                 self.loops * self.sleep_time)
                for _r in range(self.loops):
                    time.sleep(self.sleep_time)
                    node_detail = bm_client.node.get(node.uuid)
                    if node_detail.power_state is not None:
                        break
                else:
                    msg = ('Timed out waiting for node %s power state.' %
                           node.uuid)
                    raise exceptions.Timeout(msg)

            # Get the full node info
            capabilities = node_detail.properties.get('capabilities', None)

            # Only update capabilities to add boot_option if it doesn't exist.
            if capabilities:
                if 'boot_option' not in capabilities:
                    capabilities = "boot_option:local,%s" % capabilities
            else:
                capabilities = "boot_option:local"

            self.log.debug("Configuring boot for Node {0}".format(
                node.uuid))

            bm_client.node.update(node.uuid, [
                {
                    'op': 'add',
                    'path': '/properties/capabilities',
                    'value': capabilities,
                },
                {
                    'op': 'add',
                    'path': '/driver_info/deploy_ramdisk',
                    'value': ramdisk_id,
                },
                {
                    'op': 'add',
                    'path': '/driver_info/deploy_kernel',
                    'value': kernel_id,
                },
            ])

            self._apply_root_device_strategy(
                node_detail, parsed_args.root_device,
                parsed_args.root_device_minimum_size,
                parsed_args.overwrite_root_device_hints)

    def _apply_root_device_strategy(self, node, strategy, minimum_size,
                                    overwrite=False):
        if not strategy:
            return

        if node.properties.get('root_device') and not overwrite:
            # This is a correct situation, we still want to allow people to
            # fine-tune the root device setting for a subset of nodes.
            # However, issue a warning, so that they know which nodes were not
            # updated during this run.
            self.log.warning('Root device hints are already set for node %s '
                             'and overwriting is not requested, skipping',
                             node.uuid)
            self.log.warning('You may unset them by running $ ironic '
                             'node-update %s remove properties/root_device',
                             node.uuid)
            return

        inspector_client = self.app.client_manager.baremetal_introspection
        try:
            data = inspector_client.get_data(node.uuid)
        except ironic_inspector_client.ClientError:
            raise exceptions.RootDeviceDetectionError(
                'No introspection data found for node %s, '
                'root device cannot be detected' % node.uuid)
        except AttributeError:
            raise RuntimeError('Ironic inspector client version 1.2.0 or '
                               'newer is required for detecting root device')

        try:
            disks = data['inventory']['disks']
        except KeyError:
            raise exceptions.RootDeviceDetectionError(
                'Malformed introspection data for node %s: '
                'disks list is missing' % node.uuid)

        minimum_size *= units.Gi
        disks = [d for d in disks if d.get('size', 0) >= minimum_size]

        if not disks:
            raise exceptions.RootDeviceDetectionError(
                'No suitable disks found for node %s' % node.uuid)

        if strategy == 'smallest':
            disks.sort(key=lambda d: d['size'])
            root_device = disks[0]
        elif strategy == 'largest':
            disks.sort(key=lambda d: d['size'], reverse=True)
            root_device = disks[0]
        else:
            disk_names = [x.strip() for x in strategy.split(',')]
            disks = {d['name']: d for d in disks}
            for candidate in disk_names:
                try:
                    root_device = disks['/dev/%s' % candidate]
                except KeyError:
                    continue
                else:
                    break
            else:
                raise exceptions.RootDeviceDetectionError(
                    'Cannot find a disk with any of names %(strategy)s '
                    'for node %(node)s' %
                    {'strategy': strategy, 'node': node.uuid})

        hint = None
        for hint_name in ('wwn', 'serial'):
            if root_device.get(hint_name):
                hint = {hint_name: root_device[hint_name]}
                break

        if hint is None:
            # I don't think it might actually happen, but just in case
            raise exceptions.RootDeviceDetectionError(
                'Neither WWN nor serial number are known for device %(dev)s '
                'on node %(node)s; root device hints cannot be used' %
                {'dev': root_device['name'], 'node': node.uuid})

        # During the introspection process we got local_gb assigned according
        # to the default strategy. Now we need to update it.
        new_size = root_device['size'] / units.Gi
        # This -1 is what we always do to account for partitioning
        new_size -= 1

        bm_client = self.app.client_manager.baremetal
        bm_client.node.update(
            node.uuid,
            [{'op': 'add', 'path': '/properties/root_device', 'value': hint},
             {'op': 'add', 'path': '/properties/local_gb', 'value': new_size}])

        self.log.info('Updated root device for node %(node)s, new device '
                      'is %(dev)s, new local_gb is %(local_gb)d',
                      {'node': node.uuid, 'dev': root_device,
                       'local_gb': new_size})


class ShowNodeCapabilities(lister.Lister):
    """List the capabilities for all Nodes"""

    log = logging.getLogger(__name__ + ".ShowNodeProfile")

    def take_action(self, parsed_args):
        self.log.warning('This command is deprecated and will be removed soon '
                         'please use "openstack overcloud profiles list" to '
                         'get the list of all nodes and their profiles')
        bm_client = self.app.client_manager.baremetal
        rows = []
        for node in bm_client.node.list():
            node_detail = bm_client.node.get(node.uuid)
            capabilities = node_detail.properties.get('capabilities')
            rows.append((node.uuid, capabilities))
        return (("Node UUID", "Node Capabilities"), rows, )
