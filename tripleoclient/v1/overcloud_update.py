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

from osc_lib.command import command
from osc_lib.i18n import _
from osc_lib import utils
from tripleo_common import update

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient.workflows import templates


class UpdateOvercloud(command.Command):
    """Updates packages on overcloud nodes"""

    log = logging.getLogger(__name__ + ".UpdateOvercloud")

    def get_parser(self, prog_name):
        parser = super(UpdateOvercloud, self).get_parser(prog_name)
        parser.add_argument('stack', nargs='?',
                            help=_('Name or ID of heat stack to scale '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME'))
        parser.add_argument(
            '--templates', nargs='?', const=constants.TRIPLEO_HEAT_TEMPLATES,
            help=_("The directory containing the Heat templates to deploy. "
                   "This argument is deprecated. The command now utilizes "
                   "a deployment plan, which should be updated prior to "
                   "running this command, should that be required. Otherwise "
                   "this argument will be silently ignored."),
        )
        parser.add_argument('-i', '--interactive', dest='interactive',
                            action='store_true')
        parser.add_argument('-a', '--abort', dest='abort_update',
                            action='store_true')
        parser.add_argument(
            '-e', '--environment-file', metavar='<HEAT ENVIRONMENT FILE>',
            action='append', dest='environment_files',
            help=_("Environment files to be passed to the heat stack-create "
                   "or heat stack-update command. (Can be specified more than "
                   "once.) This argument is deprecated. The command now "
                   "utilizes a deployment plan, which should be updated prior "
                   "to running this command, should that be required. "
                   "Otherwise this argument will be silently ignored."),
        )
        parser.add_argument(
            '--answers-file',
            help=_('Path to a YAML file with arguments and parameters.')
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        workflow = clients.workflow_engine
        stack_fields = templates.process_templates(
            workflow, container=parsed_args.stack)

        update_manager = update.PackageUpdateManager(
            heatclient=clients.orchestration,
            novaclient=clients.compute,
            stack_id=parsed_args.stack,
            stack_fields=stack_fields)
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
            status, _ = update_manager.get_status()
            if status not in ['COMPLETE']:
                raise exceptions.DeploymentError("Stack update failed.")
        else:
            status, _ = update_manager.get_status()
            print("stack {0} status: {1}".format(parsed_args.stack,
                                                 status))
