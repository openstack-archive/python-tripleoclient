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

from tripleoclient import command
from tripleoclient import utils
from tripleoclient.workflows import deployment


class OvercloudCredentials(command.Command):
    """Create the overcloudrc files"""

    log = logging.getLogger(__name__ + ".OvercloudCredentials")

    def get_parser(self, prog_name):
        parser = super(OvercloudCredentials, self).get_parser(prog_name)
        parser.add_argument('plan', help=("The name of the plan you want to "
                                          "create rc files for."))
        parser.add_argument('--directory', default=".", nargs='?', help=(
            "The directory to create the rc files. Defaults to the current "
            "directory."))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        clients = self.app.client_manager
        plan = parsed_args.plan
        dir_ = parsed_args.directory

        overcloudrcs = deployment.create_overcloudrc(clients, container=plan)
        utils.write_overcloudrc(plan, overcloudrcs, dir_)
