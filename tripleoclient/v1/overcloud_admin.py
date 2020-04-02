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

from oslo_config import cfg
from oslo_log import log as logging

from osc_lib.i18n import _
from osc_lib import utils

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils
from tripleoclient.workflows import deployment

CONF = cfg.CONF
logging.register_options(CONF)
logging.setup(CONF, '')


class Authorize(command.Command):
    "Deploy the ssh keys needed by Mistral."

    log = logging.getLogger(__name__ + ".AdminAuthorize")

    def get_parser(self, prog_name):
        parser = super(Authorize, self).get_parser(prog_name)

        parser.add_argument('--stack', dest='stack',
                            help=_('Name or ID of heat stack '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud'))

        parser.add_argument(
            '--overcloud-ssh-user',
            default='heat-admin',
            help=_('User for ssh access to overcloud nodes')
        )
        parser.add_argument(
            '--overcloud-ssh-key',
            default=None,
            help=_('Key path for ssh access to overcloud nodes. When'
                   'undefined the key will be autodetected.')
        )
        parser.add_argument(
            '--overcloud-ssh-network',
            help=_('Network name to use for ssh access to overcloud nodes.'),
            default='ctlplane'
        )
        parser.add_argument(
            '--overcloud-ssh-enable-timeout',
            help=_('This option no longer has any effect.'),
            type=int,
            default=constants.ENABLE_SSH_ADMIN_TIMEOUT
        )
        parser.add_argument(
            '--overcloud-ssh-port-timeout',
            help=_('Timeout for the ssh port to become active.'),
            type=int,
            default=constants.ENABLE_SSH_ADMIN_SSH_PORT_TIMEOUT
        )

        return parser

    def take_action(self, parsed_args):

        self.log.debug("take_action({})".format(parsed_args))
        clients = self.app.client_manager
        stack = oooutils.get_stack(clients.orchestration, parsed_args.stack)
        deployment.get_hosts_and_enable_ssh_admin(
            stack,
            parsed_args.overcloud_ssh_network,
            parsed_args.overcloud_ssh_user,
            self.get_key_pair(parsed_args),
            parsed_args.overcloud_ssh_port_timeout,
            verbosity=oooutils.playbook_verbosity(self=self)
        )
