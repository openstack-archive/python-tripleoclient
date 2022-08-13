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
import os
import yaml

from osc_lib.command import command
from osc_lib.i18n import _

from tripleoclient import constants
from tripleoclient import utils

INVENTORY = constants.ANSIBLE_INVENTORY.format('overcloud')


class BackupOvercloud(command.Command):
    """Backup the Overcloud"""

    log = logging.getLogger(__name__ + ".BackupOvercloud")

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
                   "using 'rear', 'nfs' or 'ironic' as args "
                   "which will check for package install "
                   "and configured ReaR or NFS server. "
                   "Defaults to: rear. "
                   "i.e. --init rear. "
                   "WARNING: This flag will be deprecated "
                   "and replaced by '--setup-rear' ,"
                   "'--setup-nfs' and '--setup-ironic'.")
        )

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
            help=_("Setup ReaR on the overcloud 'Controller' hosts which will "
                   "install and configure ReaR.")
        )

        parser.add_argument(
            '--setup-ironic',
            default=False,
            action='store_true',
            help=_("Setup ReaR on the overcloud 'Controller' hosts which will "
                   "install and configure ReaR with ironic")
        )

        parser.add_argument(
            '--cron',
            default=False,
            action='store_true',
            help=_("Sets up a new cron job that by default will "
                   "execute a weekly backup at Sundays midnight, "
                   "but that can be customized by using the "
                   "tripleo_backup_and_restore_cron extra-var.")
        )

        parser.add_argument(
            '--inventory',
            default=INVENTORY,
            help=_("Tripleo inventory file generated with "
                   "tripleo-ansible-inventory command. "
                   "Defaults to: " + INVENTORY)
        )

        parser.add_argument(
            '--storage-ip',
            help=_("Storage IP is an optional parameter "
                   "which allows for an ip of a storage "
                   "server to be specified, overriding the "
                   "default undercloud. "
                   "WARNING: This flag will be deprecated in "
                   "favor of '--extra-vars' which will allow "
                   "to pass this and other variables.")
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
            extra_vars = {}
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

    def _run_backup_overcloud(self, parsed_args):
        """Backup defined overcloud nodes."""

        extra_vars = self._parse_extra_vars(parsed_args.extra_vars)

        if parsed_args.storage_ip:
            storage_ip = parsed_args.storage_ip

            extra_vars[
                'tripleo_backup_and_restore_nfs_server'
            ] = storage_ip

        if not (os.path.isfile(parsed_args.inventory) and
                os.access(parsed_args.inventory, os.R_OK)):
            raise RuntimeError(
                _('The inventory file {} does not exist or is not '
                    'readable'.format(parsed_args.inventory)))

        if parsed_args.setup_nfs is True or parsed_args.init == 'nfs':

            self.log.debug(_('Setting up NFS Backup node'))
            self._run_ansible_playbook(
                            playbook='prepare-nfs-backup.yaml',
                            inventory=parsed_args.inventory,
                            tags='bar_setup_nfs_server',
                            skip_tags=None,
                            extra_vars=extra_vars
                            )

        if parsed_args.setup_rear is True or parsed_args.init == 'rear':

            self.log.debug(_('Installing ReaR on controller nodes'))
            self._run_ansible_playbook(
                            playbook='prepare-overcloud-backup.yaml',
                            inventory=parsed_args.inventory,
                            tags='bar_setup_rear',
                            skip_tags=None,
                            extra_vars=extra_vars
                            )

        if parsed_args.setup_ironic is True or parsed_args.init == 'ironic':

            self.log.debug(_('Installing Rear/Ironic on nodes'))
            self._run_ansible_playbook(
                            playbook='cli-overcloud-conf-ironic.yaml',
                            inventory=parsed_args.inventory,
                            tags='bar_setup_rear',
                            skip_tags=None,
                            extra_vars=extra_vars
                            )

        if parsed_args.cron is True:

            self.log.debug(_('Programming cron backup'))
            self._run_ansible_playbook(
                            playbook='cli-overcloud-backup-cron.yaml',
                            inventory=parsed_args.inventory,
                            tags=None,
                            skip_tags=None,
                            extra_vars=extra_vars
                            )

        if (parsed_args.setup_nfs is False and
           parsed_args.setup_rear is False and
           parsed_args.setup_ironic is False and
           parsed_args.cron is False and
           parsed_args.init is None):

            self.log.debug(_('Starting Overcloud Backup'))
            self._run_ansible_playbook(
                            playbook='cli-overcloud-backup.yaml',
                            inventory=parsed_args.inventory,
                            tags='bar_create_recover_image',
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

        if parsed_args.init:

            self.log.warning("The following flags will be deprecated:"
                             "[--init, --storage-ip]")

        self._run_backup_overcloud(parsed_args)
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


class BackupSnapshot(command.Command):
    """Takes and LVM snapshot ignoring all the rest
       of the parameters passed. To be able to take
       a snapshot, the following conditions must
       be met:
       - The disk must be configured to use LVM
       - There must be an lv called lv_snapshot
       - lv_snapshot must be 8GB or more
       This operation will destroy the lv_snapshot volume
       and replace it with snapshots of the disks.
    """

    log = logging.getLogger(__name__ + ".BackupSnapshotOvercloud")

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
            '--remove',
            default=False,
            action='store_true',
            help=_("Removes all the snapshot volumes "
                   "that were created.")
        )

        parser.add_argument(
            '--revert',
            default=False,
            action='store_true',
            help=_("Reverts all the disks to the moment "
                   "when the snapshot was created.")
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
            extra_vars = {}
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

    def _run_snapshot_overcloud(self, parsed_args):
        """Snapshot defined overcloud nodes."""

        extra_vars = self._parse_extra_vars(parsed_args.extra_vars)

        if not (os.path.isfile(parsed_args.inventory) and
                os.access(parsed_args.inventory, os.R_OK)):
            raise RuntimeError(
                _('The inventory file {} does not exist or is not '
                    'readable'.format(parsed_args.inventory)))

        if parsed_args.remove is True and parsed_args.revert is True:
            raise RuntimeError(
                _('--revert and --remove are mutually exclusive'))
        if parsed_args.remove is True and parsed_args.revert is False:
            tags = 'remove_snapshots'
        if parsed_args.revert is True and parsed_args.remove is False:
            tags = 'revert_snapshots'
        if parsed_args.remove is False and parsed_args.revert is False:
            tags = 'create_snapshots'

        self.log.debug(_('Starting Overcloud Snapshot'))
        self._run_ansible_playbook(
                    playbook='cli-overcloud-snapshot.yaml',
                    inventory=parsed_args.inventory,
                    tags=tags,
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
        self._run_snapshot_overcloud(parsed_args)
