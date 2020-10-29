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
from tripleoclient import exceptions
from tripleoclient import utils as oooutils
from tripleoclient.v1.overcloud_deploy import DeployOvercloud
from tripleoclient.workflows import deployment
from tripleoclient.workflows import parameters

CONF = cfg.CONF
logging.register_options(CONF)
logging.setup(CONF, '')


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
        parser.add_argument('-y', '--yes', default=False,
                            action='store_true',
                            help=_("Use -y or --yes to skip the confirmation "
                                   "required before any upgrade "
                                   "operation. Use this with caution! "),
                            )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if (not parsed_args.yes
                and not oooutils.prompt_user_for_confirmation(
                    constants.UPGRADE_PROMPT, self.log)):
            raise OvercloudUpgradeNotConfirmed(constants.UPGRADE_NO)

        # Throw deprecation warning if service is enabled and
        # ask user if upgrade should still be continued.
        if parsed_args.environment_files:
            oooutils.check_deprecated_service_is_enabled(
                parsed_args.environment_files)

        clients = self.app.client_manager

        stack = oooutils.get_stack(clients.orchestration,
                                   parsed_args.stack)

        stack_name = stack.stack_name

        # In case of update and upgrade we need to force the
        # config_download to false. The heat stack update will be performed
        # by DeployOvercloud class but skipping the config download part.
        parsed_args.config_download = False
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

        # enable ssh admin for Ansible-via-Mistral as that's done only
        # when config_download is true
        deployment.get_hosts_and_enable_ssh_admin(
            stack,
            parsed_args.overcloud_ssh_network,
            parsed_args.overcloud_ssh_user,
            self.get_key_pair(parsed_args),
            parsed_args.overcloud_ssh_port_timeout,
            verbosity=oooutils.playbook_verbosity(self=self)
        )

        self.log.info("Completed Overcloud Upgrade {} for stack "
                      "{}".format(self.operation, stack_name))


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
        parser.add_argument('--no-workflow', dest='no_workflow',
                            action='store_true',
                            default=True,
                            help=_('This option no longer has any effect.')
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

    def _validate_skip_tags(self, skip_tags):
        tags_list = skip_tags.split(',')
        for tag in tags_list:
            tag = tag.strip()
            if tag and tag not in constants.MAJOR_UPGRADE_SKIP_TAGS:
                raise exceptions.InvalidConfiguration(
                    "Unexpected tag %s. Supported values are %s" % (
                        tag, constants.MAJOR_UPGRADE_SKIP_TAGS))
        return skip_tags

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if (not parsed_args.yes
                and not oooutils.prompt_user_for_confirmation(
                    constants.UPGRADE_PROMPT, self.log)):
            raise OvercloudUpgradeNotConfirmed(constants.UPGRADE_NO)

        # NOTE(cloudnull): The string option "all" was a special default
        #                  that is no longer relevant. To retain compatibility
        #                  this condition has been put in place.
        if not parsed_args.playbook or parsed_args.playbook == ['all']:
            playbook = constants.MAJOR_UPGRADE_PLAYBOOKS
        else:
            playbook = parsed_args.playbook

        _, ansible_dir = self.get_ansible_key_and_dir(
            no_workflow=parsed_args.no_workflow,
            stack=parsed_args.stack,
            orchestration=self.app.client_manager.orchestration
        )
        deployment.config_download(
            log=self.log,
            clients=self.app.client_manager,
            stack=oooutils.get_stack(
                self.app.client_manager.orchestration,
                parsed_args.stack
            ),
            output_dir=ansible_dir,
            verbosity=oooutils.playbook_verbosity(self=self),
            ansible_playbook_name=playbook,
            inventory_path=oooutils.get_tripleo_ansible_inventory(
                parsed_args.static_inventory,
                parsed_args.ssh_user,
                parsed_args.stack,
                return_inventory_file_path=True
            ),
            tags=parsed_args.tags,
            skip_tags=parsed_args.skip_tags,
            limit_hosts=oooutils.playbook_limit_parse(
                limit_nodes=parsed_args.limit
            ),
            forks=parsed_args.ansible_forks
        )
        self.log.info("Completed Overcloud Major Upgrade Run.")


class UpgradeConverge(UpgradePrepare):
    """Major upgrade converge - reset Heat resources in the stored plan

       This is the last step for completion of a overcloud major
       upgrade.  The main task is updating the plan and stack to
       unblock future stack updates. For the major upgrade workflow we
       have set specific values for some stack Heat resources. This
       unsets those back to their default values.
    """
    operation = "Converge"

    template = constants.UPGRADE_CONVERGE_ENV

    forbidden_params = constants.UPGRADE_CONVERGE_FORBIDDEN_PARAMS

    log = logging.getLogger(__name__ + ".UpgradeConverge")
