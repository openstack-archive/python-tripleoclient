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
from tripleoclient.workflows import support


class ReportExecute(command.Command):
    """Run sosreport on selected servers."""

    log = logging.getLogger(__name__ + ".ReportExecute")

    def get_parser(self, prog_name):
        parser = super(ReportExecute, self).get_parser(prog_name)
        parser.add_argument('server_name',
                            help=_('Nova server_name or partial name to match.'
                                   ' For example "controller" will match all '
                                   'controllers for an environment.'))
        parser.add_argument('-c', '--container', dest='container',
                            default='overcloud_support',
                            help=_('Swift Container to store logs to'))
        parser.add_argument('-o', '--output', dest='destination',
                            default='support_logs',
                            help=_('Output directory for the report'))
        parser.add_argument('--skip-container-delete', dest='skip_delete',
                            default=False,
                            help=_('Do not delete the container after the '
                                   'files have been downloaded. Ignored '
                                   'if --collect-only or --download-only '
                                   'is provided.'),
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
                           help=_('Skip log downloads, only collect logs and '
                                  'put in the container'),
                           default=False,
                           action='store_true')
        group.add_argument('--download-only', dest='download_only',
                           help=_('Skip generation, only download from '
                                  'the provided container'),
                           default=False,
                           action='store_true')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action({})'.format(parsed_args))

        clients = self.app.client_manager
        container = parsed_args.container
        server_name = parsed_args.server_name
        destination = parsed_args.destination
        timeout = parsed_args.timeout
        concurrency = parsed_args.concurrency

        if not server_name:
            raise Exception(_('Please specify the server_name option.'))

        if not parsed_args.download_only:
            print(_('Starting log collection... (This may take a while)'))
            try:
                support.fetch_logs(clients, container, server_name,
                                   timeout=timeout, concurrency=concurrency)
            except Exception as err:
                self.log.error('Unable to fetch logs, {}'.format(err))
                raise err

        if not parsed_args.collect_only:
            try:
                support.download_files(clients, container, destination)
            except Exception as err:
                self.log.error('Unable to download files, {}'.format(err))
                raise err

        if not parsed_args.collect_only and not parsed_args.download_only and \
                not parsed_args.skip_delete:
            print(_('Deleting container') + ' {}...'.format(container))
            try:
                support.delete_container(clients, container, timeout=timeout,
                                         concurrency=concurrency)
            except Exception as err:
                self.log.error('Unable to delete container, {}'.format(err))
                raise err
