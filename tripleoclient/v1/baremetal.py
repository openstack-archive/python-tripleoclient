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
from openstackclient.common import utils as osc_utils
from openstackclient.i18n import _
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
        new_nodes = nodes.register_all_nodes(
            parsed_args.service_host,
            nodes_config,
            client=client,
            keystone_client=self.app.client_manager.identity)

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

            # NOTE(dtantsur): PXE firmware on virtual machines misbehaves when
            # a lot of nodes start DHCPing simultaneously: it ignores NACK from
            # DHCP server, tries to get the same address, then times out. Work
            # around it by using sleep, anyway introspection takes much longer.
            time.sleep(5)

        print("Waiting for introspection to finish...")
        errors = []
        successful_node_uuids = set()
        for uuid, status in utils.wait_for_node_introspection(
                inspector_client, node_uuids):
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
        for node in nodes:
            print("Configuring BIOS for node {0}".format(node.uuid))
            self.bm_client.node.vendor_passthru(
                node.uuid, 'configure_bios_settings', http_method='POST')

        # NOTE(ifarkas): give the DRAC card some time to process the job
        time.sleep(self.sleep_time)

    def _configure_root_raid_volumes(self, nodes):
        for node in nodes:
            print("Configuring root RAID volume for node {0}"
                  .format(node.uuid))
            self.bm_client.node.vendor_passthru(
                node.uuid, 'create_raid_configuration',
                {'create_root_volume': True, 'create_nonroot_volumes': False},
                'POST')

        # NOTE(ifarkas): give the DRAC card some time to process the job
        time.sleep(self.sleep_time)

    def _configure_nonroot_raid_volumes(self, nodes):
        for node in nodes:
            print("Configuring non-root RAID volume for node {0}"
                  .format(node.uuid))
            self.bm_client.node.vendor_passthru(
                node.uuid, 'create_raid_configuration',
                {'create_root_volume': False, 'create_nonroot_volumes': True},
                'POST')

        # NOTE(ifarkas): give the DRAC card some time to process the job
        time.sleep(self.sleep_time)

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

    def _delete_raid_volumes(self, nodes):
        nodes_with_reboot_request = set()

        for node in nodes:
            print("Deleting RAID volumes on node {0}".format(node.uuid))

            resp = self.bm_client.node.vendor_passthru(
                node.uuid, 'list_virtual_disks', http_method='GET')
            virtual_disks = resp.virtual_disks

            changed_raid_controllers = set()
            for disk in virtual_disks:
                self.bm_client.node.vendor_passthru(
                    node.uuid, 'delete_virtual_disk',
                    {'virtual_disk': disk['id']}, 'POST')
                changed_raid_controllers.add(disk['controller'])

            if changed_raid_controllers:
                nodes_with_reboot_request.add(node)

            for controller in changed_raid_controllers:
                self.bm_client.node.vendor_passthru(
                    node.uuid, 'apply_pending_raid_config',
                    {'raid_controller': controller}, 'POST')

        # NOTE(ifarkas): give the DRAC card some time to process the job
        time.sleep(self.sleep_time)

        return nodes_with_reboot_request

    def _change_power_state(self, nodes, target_power_state):
        for node in nodes:
            print("Changing power state on "
                  "node {0} to {1}".format(node.uuid, target_power_state))
            self.bm_client.node.set_power_state(node.uuid, target_power_state)

    def _run_introspection(self, nodes):
        inspector_client = self.app.client_manager.baremetal_introspection
        node_uuids = []

        for node in nodes:
            print("Starting introspection on node {0}".format(node.uuid))
            inspector_client.introspect(node.uuid)
            node_uuids.append(node.uuid)

        print("Waiting for introspection to finish")
        for uuid, status in utils.wait_for_node_introspection(
                inspector_client, node_uuids):
            if status['error'] is None:
                print("Introspection for node {0} finished successfully."
                      .format(uuid))
            else:
                print("Introspection for node {0} finished with error: {1}"
                      .format(uuid, status['error']))

    def get_parser(self, prog_name):
        parser = super(ConfigureReadyState, self).get_parser(prog_name)
        parser.add_argument('--delete-existing-raid-volumes',
                            dest='delete_raid_volumes', action='store_true')

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        self.bm_client = self.app.client_manager.baremetal
        drac_nodes = [node for node in self.bm_client.node.list(detail=True)
                      if 'drac' in node.driver]

        if parsed_args.delete_raid_volumes:
            changed_nodes = self._delete_raid_volumes(drac_nodes)
            self._change_power_state(changed_nodes, 'reboot')
            self._wait_for_drac_config_jobs(changed_nodes)

        self._configure_root_raid_volumes(drac_nodes)
        self._configure_bios(drac_nodes)
        self._change_power_state(drac_nodes, 'reboot')
        self._wait_for_drac_config_jobs(drac_nodes)

        self._run_introspection(drac_nodes)

        self._configure_nonroot_raid_volumes(drac_nodes)
        self._change_power_state(drac_nodes, 'reboot')
        self._wait_for_drac_config_jobs(drac_nodes)

        self._change_power_state(drac_nodes, 'off')


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
