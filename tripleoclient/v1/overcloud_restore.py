#   Copyright 2021 Red Hat, Inc.
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
import os
import yaml

from osc_lib import exceptions as oscexc
from osc_lib.command import command
from osc_lib.i18n import _
from osc_lib import utils as osc_utils

from tripleoclient import constants
from tripleoclient import utils

LOG = logging.getLogger(__name__ + ".RestoreOvercloud")

INVENTORY = constants.ANSIBLE_INVENTORY.format('overcloud')


class RestoreOvercloud(command.Command):
    """Restore the Overcloud"""

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False
        )

        parser.add_argument(
            '--inventory',
            default=INVENTORY,
            help=_("Tripleo inventory file generated with "
                   "tripleo-ansible-inventory command. "
                   "Defaults to: " + INVENTORY)
        )

        parser.add_argument(
            '--stack',
            nargs='?',
            help=_('Name or ID of the stack to be used'
                   '(default=Env: OVERCLOUD_STACK_NAME)'),
            default=osc_utils.env('OVERCLOUD_STACK_NAME'))

        parser.add_argument(
            '--node-name',
            required=True,
            help=_("Controller name is a required parameter "
                   "which defines the controller node to be "
                   "restored.")
        )

        parser.add_argument(
            '--extra-vars',
            default=None,
            action='store',
            help=_("Set additional variables as Dict or as "
                   "an absolute path of a JSON or YAML file type. "
                   "i.e. --extra-vars '{\"key\": \"val\", "
                   " \"key2\": \"val2\"}' "
                   "i.e. --extra-vars /path/to/my_vars.yaml "
                   "i.e. --extra-vars /path/to/my_vars.json. "
                   "For more information about the variables that "
                   "can be passed, visit: https://opendev.org/openstack/"
                   "tripleo-ansible/src/branch/master/tripleo_ansible/"
                   "roles/backup_and_restore/defaults/main.yml.")
        )

        return parser

    def _parse_extra_vars(self, raw_extra_vars):

        if raw_extra_vars is None:
            return {}
        if os.path.exists(raw_extra_vars):
            with open(raw_extra_vars, 'r') as fp:
                extra_vars = yaml.safe_load(fp.read())
        else:
            try:
                extra_vars = yaml.safe_load(raw_extra_vars)
            except yaml.YAMLError as exc:
                raise RuntimeError(
                    _('--extra-vars is not an existing file and cannot be '
                      'parsed as YAML / JSON: %s') % exc)

        return extra_vars

    def _run_restore_overcloud(self, parsed_args):
        """Backup defined overcloud nodes."""

        if parsed_args.stack in (None, ''):
            raise oscexc.CommandError("You must specify a stack name")

        extra_vars = self._parse_extra_vars(parsed_args.extra_vars)
        node = parsed_args.node_name
        parameter = 'tripleo_backup_and_restore_overcloud_restore_name'
        extra_vars[parameter] = node

        self._run_ansible_playbook(
              playbook='cli-overcloud-restore-node.yaml',
              inventory=parsed_args.inventory,
              tags=None,
              skip_tags=None,
              extra_vars=extra_vars,
              ssh_user='stack'
              )

    def _run_ansible_playbook(self,
                              playbook,
                              inventory,
                              tags,
                              skip_tags,
                              extra_vars,
                              ssh_user):
        """Run ansible playbook"""

        with utils.TempDirs() as tmp:
            utils.run_ansible_playbook(
                playbook=playbook,
                inventory=inventory,
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                tags=tags,
                skip_tags=skip_tags,
                verbosity=utils.playbook_verbosity(self=self),
                extra_vars=extra_vars,
                ssh_user=ssh_user
            )

    def take_action(self, parsed_args):

        self._run_restore_overcloud(parsed_args)

        print(
            '\n'
            ' #############################################################\n'
            ' #                  Disclaimer                               #\n'
            ' # Backup verification is the End Users responsibility       #\n'
            ' # Please verify backup integrity before any possible        #\n'
            ' # disruptive actions against the Overcloud. The resulting  #\n'
            ' # backup file path will be shown on a successful execution. #\n'
            ' #                                                           #\n'
            ' # .-Stay safe and avoid future issues-.                     #\n'
            ' #############################################################\n'
            )
