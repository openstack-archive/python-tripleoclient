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
from tripleo_common import update

TRIPLEO_HEAT_TEMPLATES = "/usr/share/openstack-tripleo-heat-templates/"


class UpdateOvercloud(command.Command):
    """Updates packages on overcloud nodes"""

    auth_required = False
    log = logging.getLogger(__name__ + ".UpdateOvercloud")

    def get_parser(self, prog_name):
        parser = super(UpdateOvercloud, self).get_parser(prog_name)
        parser.add_argument('stack', nargs='?',
                            help='Name or ID of heat stack to scale '
                                 '(default=Env: OVERCLOUD_STACK_NAME)',
                            default=utils.env('OVERCLOUD_STACK_NAME'))
        main_group = parser.add_mutually_exclusive_group(required=True)
        main_group.add_argument('--plan', dest='plan',
                                help='Name or ID of tuskar plan to scale '
                                     '(default=Env: OVERCLOUD_PLAN_NAME)',
                                default=utils.env('OVERCLOUD_PLAN_NAME'))
        main_group.add_argument(
            '--templates', nargs='?', const=TRIPLEO_HEAT_TEMPLATES,
            help="The directory containing the Heat templates to deploy"
        )
        parser.add_argument('-i', '--interactive', dest='interactive',
                            action='store_true')
        parser.add_argument('-a', '--abort', dest='abort_update',
                            action='store_true')
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
        osc_plugin = self.app.client_manager.rdomanager_oscplugin
        if parsed_args.templates:
            management = None
        else:
            management = osc_plugin.management()

        orchestration = osc_plugin.orchestration()
        update_manager = update.PackageUpdateManager(
            tuskarclient=management,
            heatclient=orchestration,
            novaclient=self.app.client_manager.compute,
            plan_id=parsed_args.plan,
            stack_id=parsed_args.stack,
            tht_dir=parsed_args.templates,
            environment_files=parsed_args.environment_files)
        if parsed_args.abort_update:
            print("cancelling package update on stack {0}".format(
                parsed_args.stack))
            update_manager.cancel()
        else:
            status, resources = update_manager.get_status()
            if status not in ['IN_PROGRESS', 'WAITING']:
                print("starting package update on stack {0}".format(
                    parsed_args.stack))
                update_manager.update()

        if parsed_args.interactive:
            update_manager.do_interactive_update()
        else:
            print("stack {0} status: {1}".format(parsed_args.stack, status))
