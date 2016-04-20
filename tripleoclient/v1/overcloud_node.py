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

from tripleoclient import constants


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
        parser.add_argument(
            '--templates', nargs='?', const=constants.TRIPLEO_HEAT_TEMPLATES,
            help="The directory containing the Heat templates to deploy"
        )
        parser.add_argument(
            '-e', '--environment-file', metavar='<HEAT ENVIRONMENT FILE>',
            action='append', dest='environment_files',
            help='Environment files to be passed to the heat stack-create '
                   'or heat stack-update command. (Can be specified more than '
                   'once.)'
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
