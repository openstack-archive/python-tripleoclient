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

from tripleoclient.exceptions import OvercloudUpgradeNotConfirmed

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils
from tripleoclient.workflows import package_update

CONF = cfg.CONF
logging.register_options(CONF)
logging.setup(CONF, '')


class ExternalUpgradeRun(command.Command):
    """Run external major upgrade Ansible playbook

       This will run the external major upgrade Ansible playbook,
       executing tasks from the undercloud. The upgrade playbooks are
       made available after completion of the 'overcloud upgrade
       prepare' command.

    """

    log = logging.getLogger(__name__ + ".ExternalUpgradeRun")

    def get_parser(self, prog_name):
        parser = super(ExternalUpgradeRun, self).get_parser(prog_name)
        parser.add_argument('--static-inventory',
                            dest='static_inventory',
                            action="store",
                            default=None,
                            help=_('Path to an existing ansible inventory to '
                                   'use. If not specified, one will be '
                                   'generated in '
                                   '~/tripleo-ansible-inventory.yaml')
                            )
        parser.add_argument("--ssh-user",
                            dest="ssh_user",
                            action="store",
                            default="tripleo-admin",
                            help=_("DEPRECATED: Only tripleo-admin should be "
                                   "used as ssh user.")
                            )
        parser.add_argument('--tags',
                            dest='tags',
                            action="store",
                            default="",
                            help=_('A string specifying the tag or comma '
                                   'separated list of tags to be passed '
                                   'as --tags to ansible-playbook. ')
                            )
        parser.add_argument('--skip-tags',
                            dest='skip_tags',
                            action="store",
                            default="",
                            help=_('A string specifying the tag or comma '
                                   'separated list of tags to be passed '
                                   'as --skip-tags to ansible-playbook. ')
                            )
        parser.add_argument('--stack', dest='stack',
                            help=_('Name or ID of heat stack '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud'))
        parser.add_argument('-e', '--extra-vars', dest='extra_vars',
                            action='append',
                            help=('Set additional variables as key=value or '
                                  'yaml/json'),
                            default=[])
        parser.add_argument('--no-workflow', dest='no_workflow',
                            action='store_true',
                            default=False,
                            help=_('Run ansible-playbook directly via '
                                   'system command instead of running Ansible'
                                   'via the TripleO mistral workflows.')
                            )
        parser.add_argument('-y', '--yes', default=False,
                            action='store_true',
                            help=_("Use -y or --yes to skip the confirmation "
                                   "required before any upgrade "
                                   "operation. Use this with caution! "),
                            )

        parser.add_argument(
            '--limit',
            action='store',
            default=None,
            help=_("A string that identifies a single node or comma-separated"
                   "list of nodes the config-download Ansible playbook "
                   "execution will be limited to. For example: --limit"
                   " \"compute-0,compute-1,compute-5\".")
        )
        parser.add_argument(
            '--ansible-forks',
            action='store',
            default=None,
            type=int,
            help=_('The number of Ansible forks to use for the'
                   ' config-download ansible-playbook command.')
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if (not parsed_args.yes
                and not oooutils.prompt_user_for_confirmation(
                    constants.UPGRADE_PROMPT, self.log)):
            raise OvercloudUpgradeNotConfirmed(constants.UPGRADE_NO)

        clients = self.app.client_manager
        orchestration = clients.orchestration
        verbosity = self.app_args.verbose_level
        stack = parsed_args.stack

        ansible_dir = None
        key = None
        # Disable mistral
        if parsed_args.no_workflow:
            ansible_dir = oooutils.download_ansible_playbooks(orchestration,
                                                              stack)
            key = package_update.get_key(clients)

        # Run ansible:
        inventory = oooutils.get_tripleo_ansible_inventory(
            parsed_args.static_inventory, parsed_args.ssh_user, stack)
        limit_hosts = oooutils.playbook_limit_parse(
            limit_nodes=parsed_args.limit)
        playbook = 'all'
        extra_vars = oooutils.parse_extra_vars(parsed_args.extra_vars)

        oooutils.run_update_ansible_action(
            self.log, clients, stack, limit_hosts, inventory, playbook,
            constants.EXTERNAL_UPGRADE_PLAYBOOKS, parsed_args.ssh_user,
            (None if parsed_args.no_workflow else package_update),
            tags=parsed_args.tags, skip_tags=parsed_args.skip_tags,
            verbosity=verbosity, extra_vars=extra_vars, workdir=ansible_dir,
            priv_key=key, forks=parsed_args.ansible_forks)

        self.log.info("Completed Overcloud External Upgrade Run.")
