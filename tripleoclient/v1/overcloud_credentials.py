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

import logging

from osc_lib.i18n import _

from tripleoclient import command
from tripleoclient.workflows import deployment
from tripleoclient import utils


class OvercloudCredentials(command.Command):
    """Create the overcloudrc files"""

    log = logging.getLogger(__name__ + ".OvercloudCredentials")

    def get_parser(self, prog_name):
        parser = super(OvercloudCredentials, self).get_parser(prog_name)
        parser.add_argument(
                'stack',
                help=_("The name of the stack you want to "
                       "create rc files for."))
        parser.add_argument(
            '--directory',
            default=".",
            nargs='?',
            help=_("The directory to create the rc files. "
                   "Defaults to the current directory."))
        parser.add_argument(
            '--working-dir',
            action='store',
            help=_('The working directory that contains the input, output, '
                   'and generated files for the deployment.\n'
                   'Defaults to "$HOME/overcloud-deploy/<stack>"')
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        if not parsed_args.working_dir:
            working_dir = utils.get_default_working_dir(parsed_args.stack)
        else:
            working_dir = parsed_args.working_dir
        rc_params = utils.get_rc_params(
            working_dir)
        endpoint = utils.get_overcloud_endpoint(working_dir)
        admin_vip = utils.get_stack_saved_output_item(
            'KeystoneAdminVip', working_dir)
        deployment.create_overcloudrc(
            parsed_args.stack, endpoint, admin_vip, rc_params,
            output_dir=parsed_args.directory)
