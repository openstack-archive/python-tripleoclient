#   Copyright 2016 Red Hat, Inc.
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
import os.path
import re

from tripleo_common.actions import deployment as deployment_actions

from tripleoclient import command
from tripleoclient import exceptions


class RemoteExecute(command.Command):
    """Execute a Heat software config on the servers."""

    log = logging.getLogger(__name__ + ".RemoteExecute")

    def get_parser(self, prog_name):
        parser = super(RemoteExecute, self).get_parser(prog_name)
        parser.add_argument('-s', '--server_name', dest='server_name',
                            help='Nova server_name or partial name to match.')
        parser.add_argument('-g', '--group', dest='group',
                            default='script',
                            help='Heat Software config "group" type. '
                                 'Defaults to "script".')
        parser.add_argument('file_in', type=argparse.FileType('r'))
        return parser

    def take_action(self, parsed_args):

        self.log.debug("take_action({})".format(parsed_args))
        config = parsed_args.file_in.read()
        parsed_args.file_in.close()
        tripleoclients = self.app.client_manager.tripleoclient

        # no special characters here
        config_name = re.sub(
            r'[^\w]*', '', os.path.basename(parsed_args.file_in.name)
        )

        if not parsed_args.server_name:
            raise Exception('Please specify the -s (--server_name) option.')

        context = tripleoclients.create_mistral_context()
        init_deploy = deployment_actions.OrchestrationDeployAction(
            server_id=self.app.client_manager.compute.servers.list(
                search_opts={
                    'name': parsed_args.server_name
                }
            ),
            config=config,
            name=config_name,
            group=parsed_args.group
        )
        init_deploy_return = init_deploy.run(context=context)
        if init_deploy_return.is_success():
            print(init_deploy_return)
        else:
            raise exceptions.DeploymentError(
                'Execution failed: {}'.format(
                    init_deploy_return
                )
            )
