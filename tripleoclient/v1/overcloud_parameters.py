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
import logging
import simplejson
import yaml

from osc_lib.i18n import _

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils
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
            params = simplejson.load(parsed_args.file_in)
        elif parsed_args.file_in.name.endswith('.yaml'):
            params = yaml.safe_load(parsed_args.file_in)
        else:
            raise exceptions.InvalidConfiguration(
                _("Invalid file extension for %s, must be json or yaml") %
                parsed_args.file_in.name)

        if 'parameter_defaults' in params:
            params = params['parameter_defaults']

        with utils.TempDirs() as tmp:
            utils.run_ansible_playbook(
                playbook='cli-update-params.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=utils.playbook_verbosity(self=self),
                extra_vars={
                    "container": parsed_args.name
                },
                extra_vars_file={
                    "parameters": params
                }
            )


class GenerateFencingParameters(command.Command):
    """Generate fencing parameters"""

    log = logging.getLogger(__name__ + ".GenerateFencing")

    def get_parser(self, prog_name):
        parser = super(GenerateFencingParameters, self).get_parser(prog_name)
        parser.add_argument('-a', '--action', dest='fence_action',
                            help=_('DEPRECATED: This option is ignored.'))
        parser.add_argument('--delay', type=int,
                            help=_('Wait DELAY seconds before fencing is '
                                   'started'))
        parser.add_argument('--ipmi-lanplus',
                            dest='ipmi_lanplus',
                            default=True,
                            action='store_true',
                            help=_('DEPRECATED: This is the default.'))
        parser.add_argument('--ipmi-no-lanplus',
                            dest='ipmi_lanplus',
                            action='store_false',
                            help=_('Do not use Lanplus. Defaults to: false'))
        parser.add_argument('--ipmi-cipher', type=int,
                            help=_('Ciphersuite to use (same as ipmitool -C '
                                   'parameter.'))
        parser.add_argument('--ipmi-level',
                            help=_('Privilegel level on IPMI device. Valid '
                                   'levels: callback, user, operator, '
                                   'administrator.'))
        parser.add_argument('--output', type=argparse.FileType('w'),
                            help=_('Write parameters to a file'))
        parser.add_argument('instackenv', type=argparse.FileType('r'))
        return parser

    def take_action(self, parsed_args):
        nodes_config = utils.parse_env_file(parsed_args.instackenv)
        parsed_args.instackenv.close()
        result = parameters.generate_fencing_parameters(
            clients=self.app.client_manager,
            nodes_json=nodes_config,
            delay=parsed_args.delay,
            ipmi_level=parsed_args.ipmi_level,
            ipmi_cipher=parsed_args.ipmi_cipher,
            ipmi_lanplus=parsed_args.ipmi_lanplus,
        )

        fencing_parameters = yaml.safe_dump(result, default_flow_style=False)
        if parsed_args.output:
            parsed_args.output.write(fencing_parameters)
            parsed_args.output.close()
        else:
            print(fencing_parameters)
