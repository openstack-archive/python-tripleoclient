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

from tripleoclient.exceptions import OvercloudUpdateNotConfirmed

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils
from tripleoclient.workflows import deployment


CONF = cfg.CONF


class ExternalUpdateRun(command.Command):
    """Run external minor update Ansible playbook

       This will run the external minor update Ansible playbook,
       executing tasks from the undercloud. The update playbooks are
       made available after completion of the 'overcloud update
       prepare' command.

    """

    log = logging.getLogger(__name__ + ".ExternalUpdateRun")

    def get_parser(self, prog_name):
        parser = super(ExternalUpdateRun, self).get_parser(prog_name)
        parser.add_argument('--static-inventory',
                            dest='static_inventory',
                            action="store",
                            default=None,
                            help=_('DEPRECATED: tripleo-ansible-inventory.yaml'
                                   ' in working dir will be used.')
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
        parser.add_argument(
            '--refresh',
            action='store_true',
            help=_('DEPRECATED: Refresh the config-download playbooks.'
                   'Use `overcloud update prepare` instead to refresh '
                   'playbooks.')
        )

        return parser

    def take_action(self, parsed_args):
        logging.register_options(CONF)
        logging.setup(CONF, '')
        self.log.debug("take_action(%s)" % parsed_args)
        oooutils.ensure_run_as_normal_user()

        if (not parsed_args.yes
                and not oooutils.prompt_user_for_confirmation(
                    constants.UPDATE_PROMPT, self.log)):
            raise OvercloudUpdateNotConfirmed(constants.UPDATE_NO)

        working_dir = oooutils.get_default_working_dir(parsed_args.stack)
        config_download_dir = os.path.join(working_dir, 'config-download')
        ansible_dir = os.path.join(config_download_dir, parsed_args.stack)
        inventory_path = os.path.join(ansible_dir,
                                      'tripleo-ansible-inventory.yaml')
        key = oooutils.get_key(parsed_args.stack)
        playbooks = [os.path.join(ansible_dir, p)
                     for p in constants.EXTERNAL_UPDATE_PLAYBOOKS]
        oooutils.run_ansible_playbook(
            playbook=playbooks,
            inventory=inventory_path,
            workdir=config_download_dir,
            tags=parsed_args.tags,
            extra_vars=parsed_args.extra_vars,
            skip_tags=parsed_args.skip_tags,
            limit_hosts=oooutils.playbook_limit_parse(
                limit_nodes=parsed_args.limit
            ),
            forks=parsed_args.ansible_forks,
            key=key,
            reproduce_command=True
        )

        deployment.snapshot_dir(ansible_dir)
        self.log.info("Completed Overcloud External Update Run.")
