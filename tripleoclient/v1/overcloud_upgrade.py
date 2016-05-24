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
from openstackclient.common import utils
from openstackclient.i18n import _
from tripleo_common import upgrade

from tripleoclient import constants


class UpgradeOvercloud(command.Command):
    """Performs a major upgrade on overcloud nodes"""

    log = logging.getLogger(__name__ + ".UpgradeOvercloud")

    def get_parser(self, prog_name):
        parser = super(UpgradeOvercloud, self).get_parser(prog_name)
        parser.add_argument(
            'stage',
            metavar="<prepare|start|finish>",
            choices=['prepare', 'start', 'finish'],
            help=_('Stage of upgrade to perform.')
        )
        parser.add_argument(
            '--stack',
            dest='stack',
            help=_('Name or ID of heat stack to upgrade '
                   '(default=Env: OVERCLOUD_STACK_NAME)'),
            default=utils.env('OVERCLOUD_STACK_NAME'))
        parser.add_argument(
            '-e', '--environment-file', metavar='<HEAT ENVIRONMENT FILE>',
            action='append', dest='environment_files',
            help=_('Environment files to be passed to the heat stack-update '
                   'command. (Can be specified more than once.)')
        )
        template_group = parser.add_mutually_exclusive_group(required=True)
        template_group.add_argument(
            '--templates', nargs='?', const=constants.TRIPLEO_HEAT_TEMPLATES,
            help=_("The directory containing the Heat templates used for "
                   "the upgraded deployment. Cannot be specified with "
                   "--answers-file."),
        )
        template_group.add_argument(
            '--answers-file',
            help=_('Path to a YAML file with arguments and parameters. Cannot '
                   'be used with --templates.')
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        if parsed_args.answers_file is not None:
            with open(parsed_args.answers_file, 'r') as answers_file:
                answers = yaml.load(answers_file)

                parsed_args.templates = (constants.TRIPLEO_HEAT_TEMPLATES if
                                         answers.get('templates') is None else
                                         answers.get('templates'))
                if 'environments' in answers:
                    if parsed_args.environment_files is not None:
                        answers.environments.extend(
                            parsed_args.environment_files)
                    parsed_args.environment_files = answers['environments']

        clients = self.app.client_manager

        upgrade_manager = upgrade.StackUpgradeManager(
            heatclient=clients.orchestration,
            stack_id=parsed_args.stack,
            tht_dir=parsed_args.templates,
            environment_files=parsed_args.environment_files)
        status = upgrade_manager.get_status()
        if status not in ['IN_PROGRESS', 'WAITING']:
            print("Starting stack upgrade on stack {0}".format(
                parsed_args.stack))
            stage_func = {
                "prepare": upgrade_manager.upgrade_pre,
                "start": upgrade_manager.upgrade,
                "finish": upgrade_manager.upgrade_post,
            }
            stage_func[parsed_args.stage]()
        else:
            print("Could not start upgrade. Stack operation already in "
                  "progress on stack {0}".format(parsed_args.stack))

        print("stack {0} status: {1}".format(parsed_args.stack, status))
