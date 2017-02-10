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
import uuid

from osc_lib.command import command
from osc_lib.i18n import _
from osc_lib import utils

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils as oooutils
from tripleoclient.workflows import package_update


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
                            action='store_true',
                            help=_('DEPRECATED. Please use the command'
                                   '"openstack overcloud update abort"'))
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
            help=_('Path to a YAML file with arguments and parameters. '
                   'DEPRECATED. Not necessary when used with a plan. Will '
                   'be silently ignored, and removed in the "P" release.')
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        stack = oooutils.get_stack(clients.orchestration,
                                   parsed_args.stack)

        stack_name = stack.stack_name
        if parsed_args.interactive:
            timeout = 0

            status = package_update.update_and_wait(
                self.log, clients, stack, stack_name,
                self.app_args.verbose_level, timeout)
            if status not in ['COMPLETE']:
                raise exceptions.DeploymentError("Package update failed.")
        else:
            package_update.update(clients, container=stack_name,
                                  queue_name=str(uuid.uuid4()))
            print("Package update on stack {0} initiated.".format(
                parsed_args.stack))


class AbortUpdateOvercloud(command.Command):
    """Aborts a package update on overcloud nodes"""

    log = logging.getLogger(__name__ + ".AbortUpdateOvercloud")

    def get_parser(self, prog_name):
        parser = super(AbortUpdateOvercloud, self).get_parser(prog_name)
        parser.add_argument('stack', nargs='?',
                            help=_('Name or ID of heat stack to abort a '
                                   'running update '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        heat = clients.orchestration

        stack = oooutils.get_stack(heat, parsed_args.stack)

        package_update.abort_update(clients, stack_id=stack.id)


class ClearBreakpointsOvercloud(command.Command):
    """Clears a set of breakpoints on a currently updating overcloud"""

    log = logging.getLogger(__name__ + ".ClearBreakpointsOvercloud")

    def get_parser(self, prog_name):
        parser = super(ClearBreakpointsOvercloud, self).get_parser(prog_name)
        parser.add_argument('stack', nargs='?',
                            help=_('Name or ID of heat stack to clear a '
                                   'breakpoint or set of breakpoints '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME'))
        parser.add_argument('--ref',
                            action='append',
                            dest='refs',
                            help=_('Breakpoint to clear'))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        heat = clients.orchestration

        stack = oooutils.get_stack(heat, parsed_args.stack)

        package_update.clear_breakpoints(clients, stack_id=stack.id,
                                         refs=parsed_args.refs)
