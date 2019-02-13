#   Copyright 2019 Red Hat, Inc.
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

import argparse
import logging

from osc_lib.command import command
from osc_lib.i18n import _

from tripleoclient import constants
from tripleoclient import utils as oooutils

from tripleoclient.workflows import validations

LOG = logging.getLogger(__name__ + ".TripleoValidator")


class _CommaListGroupAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        opts = constants.VALIDATION_GROUPS
        for value in values.split(','):
                if value not in opts:
                    message = ("Invalid choice: {value} (choose from {choice})"
                               .format(value=value,
                                       choice=opts))
                    raise argparse.ArgumentError(self, message)
        setattr(namespace, self.dest, values.split(','))


class TripleOValidatorList(command.Command):
    """List the available validations"""

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False
        )

        parser.add_argument(
            '--output',
            action='store',
            default='table',
            choices=['table', 'json', 'yaml'],
            help=_("Change the default output. "
                   "Defaults to: json "
                   "i.e. --output json"
                   " --output yaml")
        )

        parser.add_argument(
            '--group',
            metavar='<group>[,<group>,...]',
            action=_CommaListGroupAction,
            default=[],
            help=_("List specific group validations, "
                   "if more than one group is required "
                   "separate the group names with commas"
                   "Defaults to: [] "
                   "i.e. --group pre-upgrade,prep "
                   " --group openshift-on-openstack")
        )

        return parser

    def _run_validator_list(self, parsed_args):
        clients = self.app.client_manager

        workflow_input = {
            "group_names": parsed_args.group
        }

        LOG.debug(_('Launch listing the validations'))
        try:
            output = validations.list_validations(clients, workflow_input)
            if parsed_args.output == 'json':
                out = oooutils.get_validations_json({'validations': output})
            elif parsed_args.output == 'yaml':
                out = oooutils.get_validations_yaml({'validations': output})
            else:
                out = oooutils.get_validations_table({'validations': output})
            print(out)
        except Exception as e:
            print(_("Validations listing finished with errors"))
            print('Output: {}'.format(e))

    def take_action(self, parsed_args):
        self._run_validator_list(parsed_args)
