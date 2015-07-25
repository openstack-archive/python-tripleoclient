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
import sys
import time

from cliff import command
from cliff import lister
from ironic_discoverd import client as discoverd_client
from openstackclient.common import utils as osc_utils
from os_cloud_config import nodes

from rdomanager_oscplugin import exceptions
from rdomanager_oscplugin import utils


def _csv_to_nodes_dict(nodes_csv):
    """Convert CSV to a list of dicts formatted for os_cloud_config

    Given a CSV file in the format below, convert it into the
    structure expected by os_could_config JSON files.

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


class ImportBaremetal(command.Command):
    """Import baremetal nodes from a JSON or CSV file"""

    log = logging.getLogger(__name__ + ".ImportBaremetal")

    def get_parser(self, prog_name):
        parser = super(ImportBaremetal, self).get_parser(prog_name)
        parser.add_argument('-s', '--service-host', dest='service_host',
                            help='Nova compute service host to register nodes '
                            'with')
        parser.add_argument('--json', dest='json', action='store_true')
        parser.add_argument('--csv', dest='csv', action='store_true')
        parser.add_argument('file_in', type=argparse.FileType('r'))
        return parser

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)

        # We need JSON or CSV to be specified, not both.
        if parsed_args.json == parsed_args.csv:
            print("ERROR: Either --json or --csv needs to be specified.",
                  file=sys.stderr)
            return

        if parsed_args.json is True:
            nodes_json = json.load(parsed_args.file_in)
            if 'nodes' in nodes_json:
                nodes_json = nodes_json['nodes']
        else:
            nodes_json = _csv_to_nodes_dict(parsed_args.file_in)

        nodes.register_all_nodes(
            parsed_args.service_host,
            nodes_json,
            client=self.app.client_manager.rdomanager_oscplugin.baremetal(),
            keystone_client=self.app.client_manager.identity)


class IntrospectionParser(object):

    def get_parser(self, prog_name):
        parser = super(IntrospectionParser, self).get_parser(prog_name)
        parser.add_argument(
            '--discoverd-url',
            default=osc_utils.env('DISCOVERD_URL', default=None),
            help='discoverd URL, defaults to localhost (env: DISCOVERD_URL).')
        return parser


class StartBaremetalIntrospectionBulk(IntrospectionParser, command.Command):
    """Start bulk introspection on all baremetal nodes"""

    log = logging.getLogger(__name__ + ".StartBaremetalIntrospectionBulk")

    def get_parser(self, prog_name):
        parser = super(
            StartBaremetalIntrospectionBulk, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)
        client = self.app.client_manager.rdomanager_oscplugin.baremetal()

        auth_token = self.app.client_manager.auth_ref.auth_token

        node_uuids = []

        print("Setting available nodes to manageable...")
        self.log.debug("Moving available nodes to manageable state.")
        available_nodes = [node for node in client.node.list()
                           if node.provision_state == "available"]
        for uuid in utils.set_nodes_state(client, available_nodes, 'manage',
                                          'manageable'):
            self.log.debug("Node {0} has been set to manageable.".format(uuid))

        for node in client.node.list():
            if node.provision_state != "manageable":
                continue

            node_uuids.append(node.uuid)

            print("Starting introspection of node: {0}".format(node.uuid))
            discoverd_client.introspect(
                node.uuid,
                base_url=parsed_args.discoverd_url,
                auth_token=auth_token)

            # NOTE(dtantsur): PXE firmware on virtual machines misbehaves when
            # a lot of nodes start DHCPing simultaneously: it ignores NACK from
            # DHCP server, tries to get the same address, then times out. Work
            # around it by using sleep, anyway introspection takes much longer.
            time.sleep(5)

        print("Waiting for discovery to finish...")
        for uuid, status in utils.wait_for_node_discovery(
                discoverd_client, auth_token, parsed_args.discoverd_url,
                node_uuids):
            if status['error'] is None:
                print("Discovery for UUID {0} finished successfully."
                      .format(uuid))
            else:
                print("Discovery for UUID {0} finished with error: {1}"
                      .format(uuid, status['error']))

        clients = self.app.client_manager
        baremetal_client = clients.rdomanager_oscplugin.baremetal()
        print("Setting manageable nodes to available...")

        self.log.debug("Moving manageable nodes to available state.")
        available_nodes = [node for node in client.node.list()
                           if node.provision_state == "manageable"]
        for uuid in utils.set_nodes_state(
                baremetal_client, baremetal_client.node.list(), 'provide',
                'available', skipped_states=("available", "active")):
            print("Node {0} has been set to available.".format(uuid))

        print("Discovery completed.")


class StatusBaremetalIntrospectionBulk(IntrospectionParser, lister.Lister):
    """Get the status of all baremetal nodes"""

    log = logging.getLogger(__name__ + ".StatusBaremetalIntrospectionBulk")

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)
        client = self.app.client_manager.rdomanager_oscplugin.baremetal()

        statuses = []

        for node in client.node.list():
            self.log.debug("Getting introspection status of Ironic node {0}"
                           .format(node.uuid))
            auth_token = self.app.client_manager.auth_ref.auth_token
            statuses.append((node.uuid, discoverd_client.get_status(
                node.uuid,
                base_url=parsed_args.discoverd_url,
                auth_token=auth_token)))

        return (
            ("Node UUID", "Finished", "Error"),
            list((node_uuid, status['finished'], status['error'])
                 for (node_uuid, status) in statuses)
        )


class ConfigureReadyState(IntrospectionParser, command.Command):
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

            for _ in range(self.loops):
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
        auth_token = self.app.client_manager.auth_ref.auth_token
        node_uuids = []

        for node in nodes:
            print("Starting introspection on node {0}".format(node.uuid))
            discoverd_client.introspect(
                node.uuid,
                base_url=self.discoverd_url,
                auth_token=auth_token)
            node_uuids.append(node.uuid)

        print("Waiting for discovery to finish")
        for uuid, status in utils.wait_for_node_discovery(
                discoverd_client, auth_token, self.discoverd_url,
                node_uuids):
            if status['error'] is None:
                print("Discovery for node {0} finished successfully."
                      .format(uuid))
            else:
                print("Discovery for node {0} finished with error: {1}"
                      .format(uuid, status['error']))

    def get_parser(self, prog_name):
        parser = super(ConfigureReadyState, self).get_parser(prog_name)
        parser.add_argument('--delete-existing-raid-volumes',
                            dest='delete_raid_volumes', action='store_true')

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        self.bm_client = (
            self.app.client_manager.rdomanager_oscplugin.baremetal())
        self.discoverd_url = parsed_args.discoverd_url
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

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)
        bm_client = self.app.client_manager.rdomanager_oscplugin.baremetal()

        image_client = self.app.client_manager.image
        try:
            kernel_id = osc_utils.find_resource(
                image_client.images, 'bm-deploy-kernel').id
        except AttributeError:
            print("ERROR: Please make sure there is only one image named "
                  "'bm-deploy-kernel' in glance.",
                  file=sys.stderr)
            return

        try:
            ramdisk_id = osc_utils.find_resource(
                image_client.images, 'bm-deploy-ramdisk').id
        except AttributeError:
            print("ERROR: Please make sure there is only one image named "
                  "'bm-deploy-ramdisk' in glance.",
                  file=sys.stderr)
            return

        self.log.debug("Using kernel ID: {0} and ramdisk ID: {1}".format(
            kernel_id, ramdisk_id))

        for node in bm_client.node.list(maintenance=False):
            # NOTE(bnemec): Ironic won't let us update the node while the
            # power_state is transitioning.
            if node.power_state is None:
                self.log.warning('Node %s power state is in transition. '
                                 'Waiting up to %d seconds for it to '
                                 'complete.',
                                 node.uuid,
                                 self.loops * self.sleep_time)
                for _ in range(self.loops):
                    time.sleep(self.sleep_time)
                    node = bm_client.node.get(node.uuid)
                    if node.power_state is not None:
                        break
                else:
                    msg = ('Timed out waiting for node %s power state.' %
                           node.uuid)
                    raise exceptions.Timeout(msg)

            # Get the full node info
            node_detail = bm_client.node.get(node.uuid)
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
