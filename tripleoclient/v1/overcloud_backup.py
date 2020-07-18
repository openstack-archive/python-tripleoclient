#   Copyright 2020 Red Hat, Inc.
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
from tripleoclient import utils

LOG = logging.getLogger(__name__ + ".BackupOvercloud")


class BackupOvercloud(command.Command):
    """Backup the Overcloud"""

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False
        )

        parser.add_argument(
            '--init',
            default=False,
            action='store_true',
            help=_("Initialize enviornment for backup,"
                   "which will check for package install"
                   "status and configured ReaR.")
        )

        parser.add_argument(
            '--inventory',
            default='/home/stack/tripleo-inventory.yaml',
            help=_("Tripleo inventory file generated with"
                   "tripleo-ansible-inventory command.")
        )

        parser.add_argument(
            '--storage-ip',
            help=_("Storage IP is an optional parameter"
                   "which allows for an ip of a storage"
                   "server to be specified, overriding the"
                   "default undercloud.")
        )

        return parser

    def _run_backup_Overcloud(self, parsed_args):
        """Backup defined overcloud nodes."""

        if parsed_args.init is False:
            playbook = 'cli-overcloud-backup.yaml'
            skip_tags = None
        elif parsed_args.init is True:
            playbook = 'prepare-overcloud-backup.yaml'
            skip_tags = 'bar_create_recover_image, bar_setup_nfs_server'

        if parsed_args.storage_ip:
            extra_vars = {
                "tripleo_backup_and_restore_nfs_server": parsed_args.storage_ip
                }
        else:
            extra_vars = None

        LOG.debug(_('Starting Overcloud Backup'))
        with utils.TempDirs() as tmp:
            utils.run_ansible_playbook(
                playbook=playbook,
                inventory=parsed_args.inventory,
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                skip_tags=skip_tags,
                verbosity=utils.playbook_verbosity(self=self),
                extra_vars=extra_vars
                )

    def take_action(self, parsed_args):

        self._run_backup_Overcloud(parsed_args)
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
