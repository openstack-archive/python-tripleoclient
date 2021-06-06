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
import os
import yaml

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

        parser.add_argument(
            '--init',
            const='rear',
            nargs='?',
            action='store',
            help=_("Initialize environment for backup, "
                   "using 'rear' or 'nfs' as args "
                   "which will check for package install "
                   "and configured ReaR or NFS server. "
                   "Defaults to: rear. "
                   "i.e. --init rear. "
                   "WARNING: This flag will be deprecated "
                   "and replaced by '--setup-rear' and "
                   "'--setup-nfs'.")
        )

        # New flags for tripleo-ansible backup and restore role.
        parser.add_argument(
            '--setup-nfs',
            default=False,
            action='store_true',
            help=_("Setup the NFS server on the backup node "
                   "which will install required packages "
                   "and configuration on the host 'BackupNode' "
                   "in the ansible inventory.")

        )

        parser.add_argument(
            '--setup-rear',
            default=False,
            action='store_true',
            help=_("Setup ReaR on the 'Undercloud' host which will "
                   "install and configure ReaR.")
        )

        parser.add_argument(
            '--inventory',
            action='store',
            default='/home/stack/tripleo-inventory.yaml',
            help=_("Tripleo inventory file generated with "
                   "tripleo-ansible-inventory command. "
                   "Defaults to: /home/stack/tripleo-inventory.yaml.")
        )

        # Parameter to choose the files to backup
        parser.add_argument(
            '--add-path',
            action='append',
            default=['/home/stack/'],
            help=_("Add additional files to backup. "
                   "Defaults to: /home/stack/ "
                   "i.e. --add-path /this/is/a/folder/ "
                   " --add-path /this/is/a/texfile.txt.")
        )

        parser.add_argument(
            "--exclude-path",
            default=[],
            action="append",
            help=_("Exclude path when performing the Undercloud Backup, "
                   "this option can be specified multiple times. "
                   "Defaults to: none "
                   "i.e. --exclude-path /this/is/a/folder/ "
                   " --exclude-path /this/is/a/texfile.txt.")
        )

        parser.add_argument(
            '--save-swift',
            default=False,
            action='store_true',
            help=_("Save backup to swift. "
                   "Defaults to: False "
                   "Special attention should be taken that "
                   "Swift itself is backed up if you call this multiple times "
                   "the backup size will grow exponentially.")
        )

        parser.add_argument(
            '--extra-vars',
            default=None,
            action='store',
            help=_("Set additional variables as Dict or as "
                   "an absolute path of a JSON or YAML file type. "
                   "i.e. --extra-vars '{\"key\": \"val\", "
                   "\"key2\": \"val2\"}' "
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
            return raw_extra_vars
        elif os.path.exists(raw_extra_vars):
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

    def _run_backup_undercloud(self, parsed_args):

        extra_vars = self._parse_extra_vars(parsed_args.extra_vars)

        if not (os.path.isfile(parsed_args.inventory) and
                os.access(parsed_args.inventory, os.R_OK)):
            raise RuntimeError(
               _('The inventory file {} does not exist or is not '
                 'readable'.format(parsed_args.inventory)))

        if parsed_args.setup_nfs is True or parsed_args.init == 'nfs':

            self._run_ansible_playbook(
                              playbook='prepare-nfs-backup.yaml',
                              inventory=parsed_args.inventory,
                              tags='bar_setup_nfs_server',
                              skip_tags=None,
                              extra_vars=extra_vars
                              )
        if parsed_args.setup_rear is True or parsed_args.init == 'rear':

            self._run_ansible_playbook(
                              playbook='prepare-undercloud-backup.yaml',
                              inventory=parsed_args.inventory,
                              tags='bar_setup_rear',
                              skip_tags=None,
                              extra_vars=extra_vars
                              )

        if (parsed_args.setup_nfs is False and
           parsed_args.setup_rear is False and
           parsed_args.init is None):

            self._run_ansible_playbook(
                              playbook='cli-undercloud-backup.yaml',
                              inventory=parsed_args.inventory,
                              tags='bar_create_recover_image',
                              skip_tags=None,
                              extra_vars=extra_vars
                              )

    def _legacy_backup_undercloud(self, parsed_args):
        """Legacy backup undercloud.

        This will allow for easier removal once the functionality
        is no longer needed.
        """

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
        self._run_ansible_playbook(
            playbook='cli-undercloud-backup-legacy.yaml',
            inventory='localhost, ',
            tags=None,
            skip_tags=None,
            extra_vars=extra_vars
            )

    def _run_ansible_playbook(self,
                              playbook,
                              inventory,
                              tags,
                              skip_tags,
                              extra_vars):
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
                extra_vars=extra_vars
            )

    def take_action(self, parsed_args):

        if len(parsed_args.add_path) > 1 or parsed_args.save_swift:

            LOG.warning("The following flags will be deprecated:"
                        "[--add-path, --exclude-path, --init, --save-swift]")

            self._legacy_backup_undercloud(parsed_args)

        else:
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
