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

import logging
import uuid

from cliff import command
from openstackclient.common import utils
from openstackclient.i18n import _
from tripleo_common import scale

from tripleoclient import constants
from tripleoclient.workflows import baremetal


class DeleteNode(command.Command):
    """Delete overcloud nodes."""

    log = logging.getLogger(__name__ + ".DeleteNode")

    def get_parser(self, prog_name):
        parser = super(DeleteNode, self).get_parser(prog_name)
        parser.add_argument('nodes', metavar='<node>', nargs="+",
                            help=_('Node ID(s) to delete'))
        parser.add_argument('--stack', dest='stack',
                            help=_('Name or ID of heat stack to scale '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME'))
        parser.add_argument(
            '--templates', nargs='?', const=constants.TRIPLEO_HEAT_TEMPLATES,
            help=_("The directory containing the Heat templates to deploy")
        )
        parser.add_argument(
            '-e', '--environment-file', metavar='<HEAT ENVIRONMENT FILE>',
            action='append', dest='environment_files',
            help=_('Environment files to be passed to the heat stack-create '
                   'or heat stack-update command. (Can be specified more than '
                   'once.)')
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        scale_manager = scale.ScaleManager(
            heatclient=clients.orchestration,
            stack_id=parsed_args.stack,
            tht_dir=parsed_args.templates,
            environment_files=parsed_args.environment_files)
        print("deleting nodes {0} from stack {1}".format(parsed_args.nodes,
                                                         parsed_args.stack))
        scale_manager.scaledown(parsed_args.nodes)


class ProvideNode(command.Command):
    """Mark nodes as available based on UUIDs or current 'manageable' state."""

    log = logging.getLogger(__name__ + ".ProvideNode")

    def get_parser(self, prog_name):
        parser = super(ProvideNode, self).get_parser(prog_name)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('node_uuids',
                           nargs="*",
                           metavar="<node_uuid>",
                           default=[],
                           help=_('Ironic UUIDs for the node(s) to be '
                                  'provided'))
        group.add_argument("--all-manageable",
                           action='store_true',
                           help=_("Provide all nodes currently in 'manageable'"
                                  " state"))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        queue_name = str(uuid.uuid4())

        if parsed_args.node_uuids:
            baremetal.provide(self.app.client_manager,
                              node_uuids=parsed_args.node_uuids,
                              queue_name=queue_name)
        else:
            baremetal.provide_manageable_nodes(self.app.client_manager,
                                               queue_name=queue_name)


class IntrospectNode(command.Command):
    """Introspect specified nodes or all nodes in 'manageable' state."""

    log = logging.getLogger(__name__ + ".IntrospectNode")

    def get_parser(self, prog_name):
        parser = super(IntrospectNode, self).get_parser(prog_name)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('node_uuids',
                           nargs="*",
                           metavar="<node_uuid>",
                           default=[],
                           help=_('Ironic UUIDs for the node(s) to be '
                                  'introspected'))
        group.add_argument("--all-manageable",
                           action='store_true',
                           help=_("Introspect all nodes currently in "
                                  "'manageable' state"))
        parser.add_argument('--provide',
                            action='store_true',
                            help=_('Provide (make available) the nodes once '
                                   'introspected'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        queue_name = str(uuid.uuid4())
        nodes = parsed_args.node_uuids

        if nodes:
            baremetal.introspect(self.app.client_manager,
                                 node_uuids=nodes,
                                 queue_name=queue_name)
        else:
            baremetal.introspect_manageable_nodes(self.app.client_manager,
                                                  queue_name=queue_name)

        if parsed_args.provide:
            if nodes:
                baremetal.provide(self.app.client_manager,
                                  node_uuids=nodes,
                                  queue_name=queue_name)
            else:
                baremetal.provide_manageable_nodes(self.app.client_manager,
                                                   queue_name=queue_name)
