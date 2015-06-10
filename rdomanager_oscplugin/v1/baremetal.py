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
        parser.add_argument('--no-poll', dest='poll', action='store_false')
        parser.set_defaults(poll=True)
        return parser

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)
        client = self.app.client_manager.rdomanager_oscplugin.baremetal()

        auth_token = self.app.client_manager.auth_ref.auth_token

        node_uuids = []

        available_nodes = [node for node in client.node.list()
                           if node.provision_state == "available"]
        utils.set_nodes_state(client, available_nodes, 'manage', 'manageable')

        for node in client.node.list():

            node_uuids.append(node.uuid)

            self.log.debug("Starting introspection of Ironic node {0}".format(
                node.uuid))
            discoverd_client.introspect(
                node.uuid,
                base_url=parsed_args.discoverd_url,
                auth_token=auth_token)

        if parsed_args.poll:
            print("Waiting for discovery to finish")
            for uuid, status in utils.wait_for_node_discovery(
                    discoverd_client, auth_token, parsed_args.discoverd_url,
                    node_uuids):
                if status['error'] is None:
                    print("Discovery for UUID {0} finished successfully."
                          .format(uuid))
                else:
                    print("Discovery for UUID {0} finished with error: {1}"
                          .format(uuid, status['error']))


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


class ConfigureBaremetalBoot(command.Command):
    """Configure baremetal note boot for all nodes"""

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

        for node in bm_client.node.list():
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

            self.log.debug("Configuring boot for Node {0}".format(
                node.uuid))

            bm_client.node.update(node.uuid, [
                {
                    'op': 'add',
                    'path': '/properties/capabilities',
                    'value': 'boot_option:local',
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
