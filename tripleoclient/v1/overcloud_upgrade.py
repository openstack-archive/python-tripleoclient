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

from tripleoclient.exceptions import OvercloudUpgradeNotConfirmed

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils
from tripleoclient.v1.overcloud_deploy import DeployOvercloud
from tripleoclient.workflows import deployment
from tripleoclient.workflows import parameters

CONF = cfg.CONF


class UpgradePrepare(DeployOvercloud):
    """Run heat stack update for overcloud nodes to refresh heat stack outputs.

       The heat stack outputs are what we use later on to generate ansible
       playbooks which deliver the major upgrade workflow. This is used as the
       first step for a major upgrade of your overcloud.
    """

    operation = "Prepare"

    template = constants.UPGRADE_PREPARE_ENV

    forbidden_params = []

    log = logging.getLogger(__name__ + ".UpgradePrepare")

    def get_parser(self, prog_name):
        parser = super(UpgradePrepare, self).get_parser(prog_name)

        return parser

    def take_action(self, parsed_args):
        logging.register_options(CONF)
        logging.setup(CONF, '')
        self.log.debug("take_action(%s)" % parsed_args)
        oooutils.ensure_run_as_normal_user()

        if (not parsed_args.yes
                and not oooutils.prompt_user_for_confirmation(
                    constants.UPGRADE_PROMPT, self.log)):
            raise OvercloudUpgradeNotConfirmed(constants.UPGRADE_NO)

        # Throw deprecation warning if service is enabled and
        # ask user if upgrade should still be continued.
        if parsed_args.environment_files:
            oooutils.duplicate_param_check(
                user_environments=parsed_args.environment_files
            )
            oooutils.check_deprecated_service_is_enabled(
                parsed_args.environment_files)

        # In case of update and upgrade we need to force the
        # stack_only to true. The heat stack update will be performed
        # by DeployOvercloud class but skipping the config download part.
        parsed_args.stack_only = True
        # Add the template attribute environment to set noops etc
        templates_dir = (parsed_args.templates or
                         constants.TRIPLEO_HEAT_TEMPLATES)
        parsed_args.environment_files = oooutils.prepend_environment(
            parsed_args.environment_files, templates_dir,
            self.template)
        # Parse all environment files looking for undesired
        # parameters
        parameters.check_forbidden_params(self.log,
                                          parsed_args.environment_files,
                                          self.forbidden_params)
        super(UpgradePrepare, self).take_action(parsed_args)

        deployment.get_hosts_and_enable_ssh_admin(
            parsed_args.stack,
            parsed_args.overcloud_ssh_network,
            parsed_args.overcloud_ssh_user,
            self.get_key_pair(parsed_args),
            parsed_args.overcloud_ssh_port_timeout,
            working_dir=self.working_dir,
            verbosity=oooutils.playbook_verbosity(self=self),
            heat_type=parsed_args.heat_type
        )

        self.log.info("Completed Overcloud Upgrade {} for stack "
                      "{}".format(self.operation, parsed_args.stack))


class UpgradeRun(command.Command):
    """Run major upgrade ansible playbooks on Overcloud nodes

       This will run the major upgrade ansible playbooks on the overcloud.
       By default all playbooks are executed, that is the
       upgrade_steps_playbook.yaml then the deploy_steps_playbook.yaml and
       then the post_upgrade_steps_playbook.yaml.
       The upgrade playbooks are made available after completion of the
       'overcloud upgrade prepare' command. This 'overcloud upgrade run'
       command is the second step in the major upgrade workflow.
    """

    log = logging.getLogger(__name__ + ".UpgradeRun")

    def get_parser(self, prog_name):
        parser = super(UpgradeRun, self).get_parser(prog_name)
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
                                   'as --tags to ansible-playbook.')
                            )
        parser.add_argument('--skip-tags',
                            dest='skip_tags',
                            action="store",
                            default="",
                            help=_('A string specifying the tag or comma '
                                   'separated list of tags to be passed '
                                   'as --skip-tags to ansible-playbook. '
                                   'The currently supported values are '
                                   '\'validation\' and \'pre-upgrade\'. '
                                   'In particular \'validation\' is useful '
                                   'if you must re-run following a failed '
                                   'upgrade and some services cannot be '
                                   'started. ')
                            )
        parser.add_argument('--stack', dest='stack',
                            help=_('Name or ID of heat stack '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud')
                            )
        parser.add_argument('-y', '--yes', default=False,
                            action='store_true',
                            help=_("Use -y or --yes to skip the confirmation "
                                   "required before any upgrade "
                                   "operation. Use this with caution! ")
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
                    constants.UPGRADE_PROMPT, self.log)):
            raise OvercloudUpgradeNotConfirmed(constants.UPGRADE_NO)

        working_dir = oooutils.get_default_working_dir(parsed_args.stack)
        config_download_dir = os.path.join(working_dir, 'config-download')
        ansible_dir = os.path.join(config_download_dir, parsed_args.stack)
        inventory_path = os.path.join(ansible_dir,
                                      'tripleo-ansible-inventory.yaml')
        # NOTE(cloudnull): The string option "all" was a special default
        #                  that is no longer relevant. To retain compatibility
        #                  this condition has been put in place.
        if not parsed_args.playbook or parsed_args.playbook == ['all']:
            playbook = [os.path.join(ansible_dir, p)
                        for p in constants.MAJOR_UPGRADE_PLAYBOOKS]
        else:
            playbook = parsed_args.playbook

        key = oooutils.get_key(parsed_args.stack)
        oooutils.run_ansible_playbook(
            playbook=playbook,
            inventory=inventory_path,
            workdir=config_download_dir,
            tags=parsed_args.tags,
            skip_tags=parsed_args.skip_tags,
            limit_hosts=oooutils.playbook_limit_parse(
                limit_nodes=parsed_args.limit
            ),
            forks=parsed_args.ansible_forks,
            key=key,
            reproduce_command=True
        )
        deployment.snapshot_dir(ansible_dir)
        self.log.info("Completed Overcloud Major Upgrade Run.")
