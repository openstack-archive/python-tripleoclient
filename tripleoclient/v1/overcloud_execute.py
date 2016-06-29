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

import argparse
import logging
import os.path
import re
import uuid

from osc_lib.command import command


class RemoteExecute(command.Command):
    """Execute a Heat software config on the servers."""

    log = logging.getLogger(__name__ + ".RemoteExecute")

    def get_parser(self, prog_name):
        parser = super(RemoteExecute, self).get_parser(prog_name)
        parser.add_argument('-s', '--server_name', dest='server_name',
                            help='Nova server_name or partial name to match.')
        parser.add_argument('-g', '--group', dest='group',
                            default='script',
                            help='Heat Software config "group" type. '
                                 'Defaults to "script".')
        parser.add_argument('file_in', type=argparse.FileType('r'))
        return parser

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)
        config = parsed_args.file_in.read()
        workflow_client = self.app.client_manager.workflow_engine
        tripleoclients = self.app.client_manager.tripleoclient
        queue_name = str(uuid.uuid4())
        messaging_websocket = tripleoclients.messaging_websocket(queue_name)

        # no special characters here
        config_name = re.sub('[^\w]*', '',
                             os.path.basename(parsed_args.file_in.name))

        if not parsed_args.server_name:
            raise Exception('Please specify the -s (--server_name) option.')

        workflow_input = {
            'server_name': parsed_args.server_name,
            'config_name': config_name,
            'group': parsed_args.group,
            'config': config,
            'queue_name': queue_name
        }

        workflow_client.executions.create(
            'tripleo.deployment.v1.deploy_on_servers',
            workflow_input=workflow_input
        )

        while True:
            body = messaging_websocket.recv()['body']
            if 'tripleo.deployment.v1.deploy_on_server' == body['type']:
                payload = body['payload']
                status = 'SUCCESS'
                if payload['status_code'] != 0:
                    status = 'FAILED'
                print('%s :: -- %s --' % (payload['server_name'], status))
                if payload['stdout']:
                    print('stdout\n: %s\n' % payload['stdout'])
                if payload['stderr']:
                    print('stderr\n: %s\n' % payload['stderr'])
            if 'tripleo.deployment.v1.deploy_on_servers' == body['type']:
                break

        messaging_websocket.cleanup()
