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

import logging

from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from osc_lib import utils as osc_utils

from tripleoclient import command
from tripleoclient import utils
from tripleoclient.workflows import plan_management
from tripleoclient.workflows import stack_management


class DeleteOvercloud(command.Command):
    """Delete overcloud stack and plan"""

    log = logging.getLogger(__name__ + ".DeleteOvercloud")

    def get_parser(self, prog_name):
        parser = super(DeleteOvercloud, self).get_parser(prog_name)
        parser.add_argument('stack', nargs='?',
                            help=_('Name or ID of heat stack to delete'
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=osc_utils.env('OVERCLOUD_STACK_NAME'))
        parser.add_argument('-y', '--yes',
                            help=_('Skip yes/no prompt (assume yes).'),
                            default=False,
                            action="store_true")
        return parser

    def _validate_args(self, parsed_args):
        if parsed_args.stack in (None, ''):
            raise oscexc.CommandError(
                "You must specify a stack name")

    def _stack_delete(self, clients, stack_name):
        orchestration_client = clients.orchestration

        print("Deleting stack {s}...".format(s=stack_name))
        stack = utils.get_stack(orchestration_client, stack_name)
        if stack is None:
            self.log.warning("No stack found ('{s}'), skipping delete".
                             format(s=stack_name))
        else:
            try:
                stack_management.delete_stack(
                    clients,
                    stack=stack.id
                )
            except Exception as e:
                raise oscexc.CommandError(
                    "Error occurred during stack delete {}".
                    format(e))

    def _plan_delete(self, clients, stack_name):
        print("Deleting plan {s}...".format(s=stack_name))
        try:
            plan_management.delete_deployment_plan(
                clients,
                container=stack_name)
        except Exception as err:
            raise oscexc.CommandError(
                "Error occurred while deleting plan {}".format(err))

    def take_action(self, parsed_args):
        self.log.debug("take_action({args})".format(args=parsed_args))

        self._validate_args(parsed_args)

        if not parsed_args.yes:
            confirm = utils.prompt_user_for_confirmation(
                message=_("Are you sure you want to delete this overcloud "
                          "[y/N]? "),
                logger=self.log)
            if not confirm:
                raise oscexc.CommandError("Action not confirmed, exiting.")

        clients = self.app.client_manager

        self._stack_delete(clients, parsed_args.stack)
        self._plan_delete(clients, parsed_args.stack)
        print("Success.")
