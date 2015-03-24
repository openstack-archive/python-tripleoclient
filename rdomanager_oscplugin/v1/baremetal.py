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

from ironic_discoverd import client as discoverd_client
from os_cloud_config import nodes

from cliff import command


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


class ImportPlugin(command.Command):
    """Baremetal Import plugin"""

    log = logging.getLogger(__name__ + ".ImportPlugin")

    def get_parser(self, prog_name):
        parser = super(ImportPlugin, self).get_parser(prog_name)
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
        else:
            nodes_json = _csv_to_nodes_dict(parsed_args.file_in)

        nodes.register_all_nodes(
            parsed_args.service_host,
            nodes_json,
            client=self.app.client_manager.rdomanager_oscplugin.baremetal(),
            keystone_client=self.app.client_manager.identity)


class IntrospectionAllPlugin(command.Command):
    """Baremetal introspection all plugin"""

    log = logging.getLogger(__name__ + ".IntrospectionAll")

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)
        client = self.app.client_manager.rdomanager_oscplugin.baremetal()

        for node in client.node.list():
            self.log.debug("Starting introspection of Ironic node {0}".format(
                node.uuid))
            auth_token = self.app.client_manager.auth_ref.auth_token
            discoverd_client.introspect(node.uuid, auth_token=auth_token)
