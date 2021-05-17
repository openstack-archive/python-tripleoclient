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
from oslo_config import cfg
from oslo_log import log as logging

from osc_lib.i18n import _
from osc_lib import utils

from tripleoclient.exceptions import OvercloudUpdateNotConfirmed

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils
from tripleoclient.v1.overcloud_deploy import DeployOvercloud
from tripleoclient.workflows import package_update

CONF = cfg.CONF
logging.register_options(CONF)
logging.setup(CONF, '')


class UpdatePrepare(DeployOvercloud):
    """Run heat stack update for overcloud nodes to refresh heat stack outputs.

       The heat stack outputs are what we use later on to generate ansible
       playbooks which deliver the minor update workflow. This is used as the
       first step for a minor update of your overcloud.
    """

    log = logging.getLogger(__name__ + ".MinorUpdatePrepare")

    def get_parser(self, prog_name):
        parser = super(UpdatePrepare, self).get_parser(prog_name)
        parser.add_argument('-y', '--yes', default=False,
                            action='store_true',
                            help=_("Use -y or --yes to skip the confirmation "
                                   "required before any update operation. "
                                   "Use this with caution! "),
                            )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if (not parsed_args.yes
                and not oooutils.prompt_user_for_confirmation(
                    constants.UPDATE_PROMPT, self.log)):
            raise OvercloudUpdateNotConfirmed(constants.UPDATE_NO)

        clients = self.app.client_manager

        stack = oooutils.get_stack(clients.orchestration,
                                   parsed_args.stack)

        stack_name = stack.stack_name

        # In case of update and upgrade we need to force the
        # update_plan_only. The heat stack update is done by the
        # packag_update mistral action
        parsed_args.update_plan_only = True

        # Add the update-prepare.yaml environment to set noops etc
        templates_dir = (parsed_args.templates or
                         constants.TRIPLEO_HEAT_TEMPLATES)
        parsed_args.environment_files = oooutils.prepend_environment(
            parsed_args.environment_files, templates_dir,
            constants.UPDATE_PREPARE_ENV)

        # Throw deprecation warning if service is enabled and
        # ask user if update should still be continued.
        if parsed_args.environment_files:
            oooutils.check_deprecated_service_is_enabled(
                parsed_args.environment_files)

        super(UpdatePrepare, self).take_action(parsed_args)
        package_update.update(clients, container=stack_name)

        # "Mandatory" validation to make sure kernelargs contains
        # a TSX flag
        if not parsed_args.disable_validations:
            stack = oooutils.get_stack(clients.orchestration,
                                       parsed_args.stack)
            self._post_stack_validation(stack)

        package_update.get_config(clients, container=stack_name)
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
                            action="store",
                            default="all",
                            help=_("Ansible playbook to use for the minor "
                                   "update. Defaults to the special value "
                                   "\'all\' which causes all the update "
                                   "playbooks to be executed. That is the "
                                   "update_steps_playbook.yaml and then the"
                                   "deploy_steps_playbook.yaml. "
                                   "Set this to each of those playbooks in "
                                   "consecutive invocations of this command "
                                   "if you prefer to run them manually. Note: "
                                   "make sure to run both those playbooks so "
                                   "that all services are updated and running "
                                   "with the target version configuration.")
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
                            help=_('Path to an existing ansible inventory to '
                                   'use. If not specified, one will be '
                                   'generated in '
                                   '~/tripleo-ansible-inventory.yaml')
                            )
        parser.add_argument('--stack', dest='stack',
                            help=_('Name or ID of heat stack '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud')
                            )
        parser.add_argument('--no-workflow', dest='no_workflow',
                            action='store_true',
                            default=False,
                            help=_('Run ansible-playbook directly via '
                                   'system command instead of running Ansible'
                                   'via the TripleO mistral workflows.')
                            )
        parser.add_argument(
            '--tags',
            action='store',
            default=None,
            help=_('A list of tags to use when running the config-download'
                   ' ansible-playbook command.')
        )
        parser.add_argument(
            '--skip-tags',
            action='store',
            default=None,
            help=_('A list of tags to skip when running the'
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
        self.log.debug("take_action(%s)" % parsed_args)

        if (not parsed_args.yes
            and not oooutils.prompt_user_for_confirmation(
                    constants.UPDATE_PROMPT, self.log)):
            raise OvercloudUpdateNotConfirmed(constants.UPDATE_NO)

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
        playbook = parsed_args.playbook
        inventory = oooutils.get_tripleo_ansible_inventory(
            parsed_args.static_inventory, parsed_args.ssh_user, stack)
        limit_hosts = oooutils.playbook_limit_parse(
            limit_nodes=parsed_args.limit)
        oooutils.run_update_ansible_action(
            self.log,
            clients,
            stack,
            limit_hosts,
            inventory,
            playbook,
            constants.MINOR_UPDATE_PLAYBOOKS,
            parsed_args.ssh_user,
            (None if parsed_args.no_workflow else package_update),
            skip_tags=parsed_args.skip_tags,
            tags=parsed_args.tags,
            verbosity=verbosity,
            workdir=ansible_dir,
            priv_key=key,
            forks=parsed_args.ansible_forks
        )


class UpdateConverge(DeployOvercloud):
    """Converge the update on Overcloud nodes.

    This restores the plan and stack so that normal deployment
    workflow is back in place.
    """

    log = logging.getLogger(__name__ + ".UpdateConverge")

    def get_parser(self, prog_name):
        parser = super(UpdateConverge, self).get_parser(prog_name)
        parser.add_argument('-y', '--yes', default=False,
                            action='store_true',
                            help=_("Use -y or --yes to skip the confirmation "
                                   "required before any update operation. "
                                   "Use this with caution! "),
                            )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if (not parsed_args.yes
            and not oooutils.prompt_user_for_confirmation(
                    constants.UPDATE_PROMPT, self.log)):
            raise OvercloudUpdateNotConfirmed(constants.UPDATE_NO)

        # Add the update-converge.yaml environment to unset noops
        templates_dir = (parsed_args.templates or
                         constants.TRIPLEO_HEAT_TEMPLATES)
        parsed_args.environment_files = oooutils.prepend_environment(
            parsed_args.environment_files, templates_dir,
            constants.UPDATE_CONVERGE_ENV)

        super(UpdateConverge, self).take_action(parsed_args)
        self.log.info("Update converge on stack {0} complete.".format(
                      parsed_args.stack))
