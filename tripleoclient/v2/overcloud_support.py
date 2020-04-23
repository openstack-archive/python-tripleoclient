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

from osc_lib.i18n import _

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils


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
        parser.add_argument('--stack',
                            help=_("Stack name to use for log collection."),
                            default='overcloud')
        # Deprecated in U
        parser.add_argument('-c',
                            '--container',
                            dest='container',
                            default=None,
                            help=_('This option no-longer has any effect.'))
        parser.add_argument('-o',
                            '--output',
                            dest='destination',
                            default='/var/lib/tripleo/support',
                            help=_('Output directory for the report'))
        # Deprecated in U
        parser.add_argument('--skip-container-delete',
                            dest='skip_delete',
                            default=False,
                            help=_('This option no-longer has any effect.'),
                            action='store_true')
        # Deprecated in U
        parser.add_argument('-t',
                            '--timeout',
                            dest='timeout',
                            type=int,
                            default=None,
                            help=_('This option no-longer has any effect.'))
        # Deprecated in U
        parser.add_argument('-n',
                            '--concurrency',
                            dest='concurrency',
                            type=int,
                            default=None,
                            help=_('This option no-longer has any effect.'))
        # Deprecated in U
        parser.add_argument('--collect-only',
                            dest='collect_only',
                            help=_('This option no-longer has any effect.'),
                            default=False,
                            action='store_true')
        # Deprecated in U
        parser.add_argument('--download-only',
                            dest='download_only',
                            help=_('This option no-longer has any effect.'),
                            default=False,
                            action='store_true')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action({})'.format(parsed_args))

        extra_vars = {
            'server_name': parsed_args.server_name,
            'sos_destination': parsed_args.destination,
        }

        with utils.TempDirs() as tmp:
            utils.run_ansible_playbook(
                playbook='cli-support-collect-logs.yaml',
                inventory=constants.ANSIBLE_INVENTORY.format(
                    parsed_args.stack
                ),
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=utils.playbook_verbosity(self=self),
                extra_vars=extra_vars
            )
