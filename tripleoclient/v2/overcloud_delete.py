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
from tripleoclient import constants
from tripleoclient import utils


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
        parser.add_argument('-s', '--skip-ipa-cleanup',
                            help=_('Skip removing overcloud hosts, services, '
                                   'and DNS records from FreeIPA. This is '
                                   'particularly relevant for deployments '
                                   'using certificates from FreeIPA for TLS. '
                                   'By default, overcloud hosts, services, '
                                   'and DNS records will be removed from '
                                   'FreeIPA before deleting the overcloud. '
                                   'Using this option might require you to '
                                   'manually cleanup FreeIPA later.'),
                            default=False,
                            action="store_true")
        return parser

    def _validate_args(self, parsed_args):
        if parsed_args.stack in (None, ''):
            raise oscexc.CommandError("You must specify a stack name")

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

        if parsed_args.skip_ipa_cleanup:
            playbooks = ["cli-overcloud-delete.yaml"]
        else:
            # Order is important, let's make sure we cleanup FreeIPA before we
            # start removing infrastructure.
            playbooks = ["cli-cleanup-ipa.yml", "cli-overcloud-delete.yaml"]

        with utils.TempDirs() as tmp:
            utils.run_ansible_playbook(
                playbooks,
                constants.ANSIBLE_INVENTORY,
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=utils.playbook_verbosity(self=self),
                extra_vars={
                    "stack_name": parsed_args.stack
                }
            )

        print("Success.")
