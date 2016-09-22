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

import argparse
import json
import logging
import yaml

from osc_lib.command import command
from osc_lib.i18n import _

from tripleoclient import exceptions
from tripleoclient.workflows import parameters


class SetParameters(command.Command):
    """Set a parameters for a plan"""

    log = logging.getLogger(__name__ + ".CreatePlan")

    def get_parser(self, prog_name):
        parser = super(SetParameters, self).get_parser(prog_name)
        parser.add_argument(
            'name',
            help=_('The name of the plan, which is used for the Swift '
                   'container, Mistral environment and Heat stack names.'))
        parser.add_argument('file_in', type=argparse.FileType('r'))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if parsed_args.file_in.name.endswith('.json'):
            params = json.load(parsed_args.file_in)
        elif parsed_args.file_in.name.endswith('.yaml'):
            params = yaml.safe_load(parsed_args.file_in)
        else:
            raise exceptions.InvalidConfiguration(
                _("Invalid file extension for %s, must be json or yaml") %
                parsed_args.file_in.name)

        if 'parameter_defaults' in params:
            params = params['parameter_defaults']

        clients = self.app.client_manager
        workflow_client = clients.workflow_engine

        name = parsed_args.name

        parameters.update_parameters(
            workflow_client,
            container=name,
            parameters=params
        )
