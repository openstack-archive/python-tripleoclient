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

from cliff import command
from openstackclient.common import utils
from tripleo_common import scale


class DeleteNode(command.Command):
    """Delete overcloud nodes."""

    log = logging.getLogger(__name__ + ".DeleteNode")

    def get_parser(self, prog_name):
        parser = super(DeleteNode, self).get_parser(prog_name)
        parser.add_argument('nodes', metavar='<node>', nargs="+",
                            help='Node ID(s) to delete')
        parser.add_argument('--stack', dest='stack',
                            help='Name or ID of heat stack to scale '
                                 '(default=Env: OVERCLOUD_STACK_NAME)',
                            default=utils.env('OVERCLOUD_STACK_NAME'))
        parser.add_argument('--plan', dest='plan',
                            help='Name or ID of tuskar plan to scale '
                                 '(default=Env: OVERCLOUD_PLAN_NAME)',
                            default=utils.env('OVERCLOUD_PLAN_NAME'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        management = self.app.client_manager.rdomanager_oscplugin.management()
        orchestration = (self.app.client_manager.rdomanager_oscplugin.
                         orchestration())
        scale_manager = scale.ScaleManager(
            tuskarclient=management,
            heatclient=orchestration,
            plan_id=parsed_args.plan,
            stack_id=parsed_args.stack)
        print("deleting nodes {0} from stack {1}".format(parsed_args.nodes,
                                                         parsed_args.plan))
        scale_manager.scaledown(parsed_args.nodes)
