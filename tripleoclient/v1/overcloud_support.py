#   Copyright 2017 Red Hat, Inc.
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
import os

from osc_lib.i18n import _

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils
from tripleoclient.workflows import package_update


class ReportExecute(command.Command):
    """Run sosreport on selected servers."""

    log = logging.getLogger(__name__ + ".ReportExecute")

    def get_parser(self, prog_name):
        parser = super(ReportExecute, self).get_parser(prog_name)
        parser.add_argument('server_name',
                            help=_('Server name, group name, or partial name'
                                   ' to match. For example "Controller" will'
                                   ' match all controllers for an'
                                   ' environment.'))
        parser.add_argument('-c', '--container', dest='container',
                            default='overcloud_support',
                            action='store_true',
                            help=_('DEPRECATED: Swift Container to store'
                                   ' logs to'))
        parser.add_argument('-o',
                            '--output',
                            dest='destination',
                            default='/var/lib/tripleo/support',
                            help=_('Output directory for the report'))
        parser.add_argument('--stack',
                            help=_("Stack name to use for log collection."),
                            default='overcloud')
        parser.add_argument('--skip-container-delete', dest='skip_delete',
                            default=False,
                            help=_('DEPRECATED: Do not delete the container '
                                   'after the files have been downloaded. '
                                   'Ignored if --collect-only or '
                                   '--download-only is provided.'),
                            action='store_true')
        parser.add_argument('-t', '--timeout', dest='timeout', type=int,
                            default=None,
                            help=_('Maximum time to wait for the log '
                                   'collection and container deletion '
                                   'workflows to finish.'))
        parser.add_argument('-n', '--concurrency', dest='concurrency',
                            type=int, default=None,
                            help=_('Number of parallel log collection and '
                                   'object deletion tasks to run.'))
        group = parser.add_mutually_exclusive_group(required=False)
        group.add_argument('--collect-only', dest='collect_only',
                           help=_('DEPRECATED: Skip log downloads, only '
                                  'collect logs and put in the container'),
                           default=False,
                           action='store_true')
        group.add_argument('--download-only', dest='download_only',
                           help=_('DEPRECATED: Skip generation, only '
                                  'download from the provided container'),
                           default=False,
                           action='store_true')
        parser.add_argument('-v',
                            '--verbose',
                            dest='verbosity',
                            type=int,
                            default=1)
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action({})'.format(parsed_args))

        playbook = os.path.join(
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            'cli-support-collect-logs.yaml')

        inventory = utils.get_tripleo_ansible_inventory(
                    inventory_file='/home/stack/'
                    'tripleo-ansible-inventory.yaml',
                    ssh_user='tripleo-admin',
                    stack=parsed_args.stack,
                    return_inventory_file_path=True)

        clients = self.app.client_manager
        key = package_update.get_key(clients)

        # The playbook we're using for this relies on this file
        # existing in this location. So we need to write it and
        # set the permissions appropriately. Not required after
        # Train.
        with open('/home/stack/.ssh/id_rsa_tripleo', 'w') as key_file:
            key_file.write(key)

        os.chmod('/home/stack/.ssh/id_rsa_tripleo', 0o600)

        extra_vars = {
            'server_name': parsed_args.server_name,
            'sos_destination': parsed_args.destination,
        }

        with utils.TempDirs() as tmp:
            utils.run_ansible_playbook(
                logger=self.log,
                ansible_config='/etc/ansible/ansible.cfg',
                playbook=playbook,
                inventory=inventory,
                python_interpreter='/usr/bin/python3',
                workdir=tmp,
                verbosity=parsed_args.verbosity,
                forks=parsed_args.concurrency,
                timeout=parsed_args.timeout,
                extra_vars=extra_vars
            )
