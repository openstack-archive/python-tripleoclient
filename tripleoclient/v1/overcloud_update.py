#   Copyright 2015 Red Hat, Inc.
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
from tripleoclient.v1.overcloud_deploy import DeployOvercloud


CONF = cfg.CONF


class UpdatePrepare(DeployOvercloud):
    """Use Heat to update and render the new Ansible playbooks based
    on the updated templates.

    These playbooks will be rendered and used during the update run step
    to perform the minor update of the overcloud nodes.
    """

    log = logging.getLogger(__name__ + ".MinorUpdatePrepare")

    def get_parser(self, prog_name):
        parser = super(UpdatePrepare, self).get_parser(prog_name)

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

        # In case of update and upgrade we need to force the
        # config_download to false. The heat stack update will be performed
        # by DeployOvercloud class but skipping the config download part.
        parsed_args.stack_only = True

        # Add the update-prepare.yaml environment to set noops etc
        templates_dir = (parsed_args.templates or
                         constants.TRIPLEO_HEAT_TEMPLATES)
        parsed_args.environment_files = oooutils.prepend_environment(
            parsed_args.environment_files, templates_dir,
            constants.UPDATE_PREPARE_ENV)

        # Throw deprecation warning if service is enabled and
        # ask user if update should still be continued.
        if parsed_args.environment_files:
            oooutils.duplicate_param_check(
                user_environments=parsed_args.environment_files
            )
            oooutils.check_deprecated_service_is_enabled(
                parsed_args.environment_files)

        super(UpdatePrepare, self).take_action(parsed_args)
        self.log.info("Update init on stack {0} complete.".format(
                      parsed_args.stack))


class UpdateRun(command.Command):
    """Run minor update ansible playbooks on Overcloud nodes"""

    log = logging.getLogger(__name__ + ".MinorUpdateRun")

    def get_parser(self, prog_name):
        parser = super(UpdateRun, self).get_parser(prog_name)
        parser.add_argument(
            '--limit',
            action='store',
            required=True,
            help=_("A string that identifies a single node or comma-separated"
                   "list of nodes the config-download Ansible playbook "
                   "execution will be limited to. For example: --limit"
                   " \"compute-0,compute-1,compute-5\".")
        )
        parser.add_argument('--playbook',
                            nargs="*",
                            default=None,
                            help=_("Ansible playbook to use for the minor"
                                   " update. Can be used multiple times."
                                   " Set this to each of those playbooks in"
                                   " consecutive invocations of this command"
                                   " if you prefer to run them manually."
                                   " Note: make sure to run all playbooks so"
                                   " that all services are updated and running"
                                   " with the target version configuration.")
                            )
        parser.add_argument("--ssh-user",
                            dest="ssh_user",
                            action="store",
                            default="tripleo-admin",
                            help=_("DEPRECATED: Only tripleo-admin should be "
                                   "used as ssh user.")
                            )
        parser.add_argument('--static-inventory',
                            dest='static_inventory',
                            action="store",
                            default=None,
                            help=_('DEPRECATED: tripleo-ansible-inventory.yaml'
                                   ' in working dir will be used.')
                            )
        parser.add_argument('--stack', dest='stack',
                            help=_('Name or ID of heat stack '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud')
                            )
        parser.add_argument(
            '--tags',
            action='store',
            default=None,
            help=_('A list of tags to use when running the the config-download'
                   ' ansible-playbook command.')
        )
        parser.add_argument(
            '--skip-tags',
            action='store',
            default=None,
            help=_('A list of tags to skip when running the the'
                   ' config-download ansible-playbook command.')
        )
        parser.add_argument(
            '-y', '--yes',
            default=False,
            action='store_true',
            help=_("Use -y or --yes to skip the confirmation required before "
                   "any update operation. Use this with caution! "),
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
        logging.register_options(CONF)
        logging.setup(CONF, '')
        self.log.debug("take_action(%s)" % parsed_args)
        oooutils.ensure_run_as_normal_user()

        if (not parsed_args.yes
            and not oooutils.prompt_user_for_confirmation(
                    constants.UPDATE_PROMPT, self.log)):
            raise OvercloudUpdateNotConfirmed(constants.UPDATE_NO)
        # NOTE(cloudnull): The string option "all" was a special default
        #                  that is no longer relevant. To retain compatibility
        #                  this condition has been put in place.
        if not parsed_args.playbook or parsed_args.playbook == ['all']:
            playbook = constants.MINOR_UPDATE_PLAYBOOKS
        else:
            playbook = parsed_args.playbook

        ansible_dir = os.path.join(oooutils.get_default_working_dir(
                                        parsed_args.stack
                                        ),
                                   'config-download',
                                   parsed_args.stack)

        inventory = os.path.join(ansible_dir, 'tripleo-ansible-inventory.yaml')
        ansible_cfg = os.path.join(ansible_dir, 'ansible.cfg')
        key_file = oooutils.get_key(parsed_args.stack)

        oooutils.run_ansible_playbook(
            playbook=playbook,
            inventory=inventory,
            workdir=ansible_dir,
            playbook_dir=ansible_dir,
            skip_tags=parsed_args.skip_tags,
            tags=parsed_args.tags,
            ansible_cfg=ansible_cfg,
            ssh_user='tripleo-admin',
            limit_hosts=parsed_args.limit,
            reproduce_command=True,
            forks=parsed_args.ansible_forks,
            extra_env_variables={
                "ANSIBLE_BECOME": True,
                "ANSIBLE_PRIVATE_KEY_FILE": key_file
            }
        )
        self.log.info("Completed Minor Update Run.")
