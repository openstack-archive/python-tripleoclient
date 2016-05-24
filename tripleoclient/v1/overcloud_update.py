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
import yaml

from cliff import command
from openstackclient.common import exceptions as oscexc
from openstackclient.common import utils
from openstackclient.i18n import _
from tripleo_common import update

from tripleoclient import constants


class UpdateOvercloud(command.Command):
    """Updates packages on overcloud nodes"""

    auth_required = False
    log = logging.getLogger(__name__ + ".UpdateOvercloud")

    def get_parser(self, prog_name):
        parser = super(UpdateOvercloud, self).get_parser(prog_name)
        parser.add_argument('stack', nargs='?',
                            help=_('Name or ID of heat stack to scale '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME'))
        parser.add_argument(
            '--templates', nargs='?', const=constants.TRIPLEO_HEAT_TEMPLATES,
            help=_("The directory containing the Heat templates to deploy"),
        )
        parser.add_argument('-i', '--interactive', dest='interactive',
                            action='store_true')
        parser.add_argument('-a', '--abort', dest='abort_update',
                            action='store_true')
        parser.add_argument(
            '-e', '--environment-file', metavar='<HEAT ENVIRONMENT FILE>',
            action='append', dest='environment_files',
            help=_('Environment files to be passed to the heat stack-create '
                   'or heat stack-update command. (Can be specified more than '
                   'once.)')
        )
        parser.add_argument(
            '--answers-file',
            help=_('Path to a YAML file with arguments and parameters.')
        )
        return parser

    def take_action(self, parsed_args):
        if parsed_args.templates is None and parsed_args.answers_file is None:
            raise oscexc.CommandError(
                "You must specify either --templates or --answers-file")

        if parsed_args.answers_file is not None:
            with open(parsed_args.answers_file, 'r') as answers_file:
                answers = yaml.load(answers_file)

                if parsed_args.templates is None:
                    parsed_args.templates = answers['templates']
                if 'environments' in answers:
                    if parsed_args.environment_files is not None:
                        answers.environments.extend(
                            parsed_args.environment_files)
                    parsed_args.environment_files = answers['environments']

        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        update_manager = update.PackageUpdateManager(
            heatclient=clients.orchestration,
            novaclient=clients.compute,
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
