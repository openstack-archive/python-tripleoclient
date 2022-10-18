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

import os
from oslo_config import cfg
from oslo_log import log as logging

from osc_lib.i18n import _
from osc_lib import utils

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils
from tripleoclient.constants import ANSIBLE_TRIPLEO_PLAYBOOKS

CONF = cfg.CONF


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
            default='tripleo-admin',
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
            help=_('DEPRECATED: Network name to use for ssh access to '
                   'overcloud nodes. This has no effect now.'),
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
        parser.add_argument(
            '--static-inventory',
            dest='static_inventory',
            action='store',
            default=None,
            help=_('Path to an existing ansible inventory to '
                   'use. If not specified, one will be '
                   'generated in '
                   '~/tripleo-ansible-inventory.yaml')
        )
        parser.add_argument(
            '--limit',
            dest='limit_hosts',
            action='store',
            default='all',
            help=_('Define which hosts or group of hosts to '
                   'run the Admin Authorize tasks against.')
        )

        return parser

    def take_action(self, parsed_args):
        logging.register_options(CONF)
        logging.setup(CONF, '')
        self.log.debug("take_action({})".format(parsed_args))
        ansible_dir = os.path.join(oooutils.get_default_working_dir(
                                        parsed_args.stack
                                        ),
                                   'config-download',
                                   parsed_args.stack)

        if parsed_args.overcloud_ssh_network:
            self.log.warning('The --overcloud-ssh-network option is '
                             'deprecated and has no effect now.')

        if not parsed_args.static_inventory:
            inventory = os.path.join(ansible_dir,
                                     'tripleo-ansible-inventory.yaml')
        else:
            inventory = parsed_args.static_inventory

        key_file = oooutils.get_key(parsed_args.stack)

        if not parsed_args.limit_hosts:
            hosts = parsed_args.stack
        else:
            hosts = parsed_args.limit_hosts

        host_list = [str(h) for h in oooutils.parse_ansible_inventory(
            inventory, hosts
        )]

        oooutils.run_ansible_playbook(
            playbook='cli-enable-ssh-admin.yaml',
            inventory=inventory,
            workdir=ansible_dir,
            key=parsed_args.overcloud_ssh_key,
            playbook_dir=ANSIBLE_TRIPLEO_PLAYBOOKS,
            ssh_user=parsed_args.overcloud_ssh_user,
            extra_vars={
                "ANSIBLE_PRIVATE_KEY_FILE": key_file,
                "ssh_servers": host_list
            },
            ansible_timeout=parsed_args.overcloud_ssh_port_timeout
        )
