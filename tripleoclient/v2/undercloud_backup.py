#   Copyright 2018 Red Hat, Inc.
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

LOG = logging.getLogger(__name__ + ".BackupUndercloud")


class BackupUndercloud(command.Command):
    """Backup the undercloud"""

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False
        )

        # Parameter to choose the files to backup
        parser.add_argument(
            '--add-path',
            action='append',
            default=['/home/stack/'],
            help=_("Add additional files to backup. "
                   "Defaults to: /home/stack/ "
                   "i.e. --add-path /this/is/a/folder/ "
                   " --add-path /this/is/a/texfile.txt")
        )
        parser.add_argument(
            "--exclude-path",
            default=[],
            action="append",
            help=_("Exclude path when performing the Undercloud Backup, "
                   "this option can be specified multiple times. "
                   "Defaults to: none "
                   "i.e. --exclude-path /this/is/a/folder/ "
                   " --exclude-path /this/is/a/texfile.txt")
        )
        parser.add_argument(
            '--save-swift',
            default=False,
            action='store_true',
            help=_("Save backup to swift. "
                   "Defaults to: False "
                   "Special attention should be taken that "
                   "Swift itself is backed up if you call this multiple times "
                   "the backup size will grow exponentially")
        )
        return parser

    def _run_backup_undercloud(self, parsed_args):

        merge_paths = sorted(list(set(parsed_args.add_path)))
        for exc in parsed_args.exclude_path:
            if exc in merge_paths:
                merge_paths.remove(exc)

        files_to_backup = ','.join(merge_paths)

        # Define the backup sources_path (files to backup).
        # This is a comma separated string.
        # I.e. "/this/is/a/folder/,/this/is/a/texfile.txt"
        extra_vars = {"sources_path": files_to_backup}
        if parsed_args.save_swift:
            extra_vars.update({"save_swift": True})

        LOG.debug(_('Launch the Undercloud Backup'))
        with utils.TempDirs() as tmp:
            utils.run_ansible_playbook(
                playbook='cli-undercloud-backup.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=utils.playbook_verbosity(self=self),
                extra_vars=extra_vars
            )

    def take_action(self, parsed_args):

        self._run_backup_undercloud(parsed_args)
        print(
            '\n'
            ' #############################################################\n'
            ' #                  Disclaimer                               #\n'
            ' # Backup verification is the End Users responsibility       #\n'
            ' # Please verify backup integrity before any possible        #\n'
            ' # disruptive actions against the Undercloud. The resulting  #\n'
            ' # backup file path will be shown on a successful execution. #\n'
            ' #                                                           #\n'
            ' # .-Stay safe and avoid future issues-.                     #\n'
            ' #############################################################\n'
        )
