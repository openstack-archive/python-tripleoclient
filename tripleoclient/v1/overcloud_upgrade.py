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
from tripleoclient import exceptions
from tripleoclient import utils as oooutils
from tripleoclient.v1.overcloud_deploy import DeployOvercloud
from tripleoclient.workflows import deployment
from tripleoclient.workflows import package_update

CONF = cfg.CONF
logging.register_options(CONF)
logging.setup(CONF, '')


class UpgradePrepare(DeployOvercloud):
    """Run heat stack update for overcloud nodes to refresh heat stack outputs.

       The heat stack outputs are what we use later on to generate ansible
       playbooks which deliver the major upgrade workflow. This is used as the
       first step for a major upgrade of your overcloud.
    """

    log = logging.getLogger(__name__ + ".MajorUpgradePrepare")

    def get_parser(self, prog_name):
        parser = super(UpgradePrepare, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

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
        # update_plan_only. The heat stack update is done by the
        # packag_update mistral action
        parsed_args.update_plan_only = True
        # Add the upgrade-prepare.yaml environment to set noops etc
        templates_dir = (parsed_args.templates or
                         constants.TRIPLEO_HEAT_TEMPLATES)
        parsed_args.environment_files = oooutils.prepend_environment(
            parsed_args.environment_files, templates_dir,
            constants.UPGRADE_PREPARE_ENV)
        super(UpgradePrepare, self).take_action(parsed_args)
        package_update.update(clients, container=stack_name)
        package_update.get_config(clients, container=stack_name)

        overcloudrcs = deployment.create_overcloudrc(
            clients, container=stack_name)
        oooutils.write_overcloudrc(stack_name, overcloudrcs)

        # refresh stack info and enable ssh admin for Ansible-via-Mistral
        stack = oooutils.get_stack(clients.orchestration, parsed_args.stack)
        deployment.get_hosts_and_enable_ssh_admin(
            self.log, clients, stack, parsed_args.overcloud_ssh_network,
            parsed_args.overcloud_ssh_user, parsed_args.overcloud_ssh_key)

        self.log.info("Completed Overcloud Upgrade Prepare for stack "
                      "{0}".format(stack_name))


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

    log = logging.getLogger(__name__ + ".MajorUpgradeRun")

    def get_parser(self, prog_name):
        parser = super(UpgradeRun, self).get_parser(prog_name)
        # The nodes and roles options will be removed in the train version
        nodes_or_roles_or_limit = parser.add_mutually_exclusive_group(
            required=True)
        nodes_or_roles_or_limit.add_argument(
            '--nodes', action=command.DeprecatedActionStore, help=_(
                "DEPRECATED: This option will be remove in the future release"
                " Use the limit option instead."
                "A string that identifies a single node or comma-separated "
                "list of nodes to be upgraded in parallel in this upgrade run "
                "invocation. For example: --nodes \"compute-0, compute-1, "
                "compute-5\". "
                "NOTE: Using this parameter with nodes of controlplane roles "
                "(e.g. \"--nodes controller-1\") is NOT supported and WILL "
                "end badly unless you include ALL nodes of that role as a "
                "comma separated string. You should instead use the --roles "
                "parameter for controlplane roles and specify the role name.")
        )
        nodes_or_roles_or_limit.add_argument(
            '--roles', action=command.DeprecatedActionStore, help=_(
                "DEPRECATED: This option will be remove in the future release"
                " Use the limit option instead."
                "A string that identifies the role or comma-separated list of"
                "roles to be upgraded in this upgrade run invocation. "
                "NOTE: nodes of specified role(s) are upgraded in parallel. "
                "This is REQUIRED for controlplane roles. For non "
                "controlplane roles (e.g., \"Compute\"), you may consider "
                "instead using the --nodes argument to limit the upgrade to "
                "a specific node or list (comma separated string) of nodes.")
        )
        nodes_or_roles_or_limit.add_argument(
            '--limit', action='store', help=_(
                "A string that identifies a single node or comma-separated"
                "list of nodes to be upgraded in parallel in this upgrade"
                " run invocation. For example: --limit \"compute-0,"
                " compute-1, compute-5\".")
        )
        parser.add_argument('--playbook',
                            action="store",
                            default="all",
                            help=_("Ansible playbook to use for the major "
                                   "upgrade. Defaults to the special value "
                                   "\'all\' which causes all the upgrade "
                                   "playbooks to run. That is the "
                                   "upgrade_steps_playbook.yaml "
                                   "then deploy_steps_playbook.yaml and then "
                                   "post_upgrade_steps_playbook.yaml. Set "
                                   "this to each of those playbooks in "
                                   "consecutive invocations of this command "
                                   "if you prefer to run them manually. Note: "
                                   "you will have to run all of those "
                                   "playbooks so that all services are "
                                   "upgraded and running with the target "
                                   "version configuration.")
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
                                              default='overcloud'))

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
        clients = self.app.client_manager
        verbosity = self.app_args.verbose_level
        stack = parsed_args.stack

        # Run ansible:
        if parsed_args.limit:
            limit_hosts = parsed_args.limit
        else:
            roles = parsed_args.roles
            nodes = parsed_args.nodes
            limit_hosts = roles or nodes

        playbook = parsed_args.playbook
        inventory = oooutils.get_tripleo_ansible_inventory(
            parsed_args.static_inventory, parsed_args.ssh_user, stack)
        skip_tags = self._validate_skip_tags(parsed_args.skip_tags)
        oooutils.run_update_ansible_action(self.log, clients, limit_hosts,
                                           inventory, playbook,
                                           constants.MAJOR_UPGRADE_PLAYBOOKS,
                                           package_update,
                                           parsed_args.ssh_user,
                                           parsed_args.tags,
                                           skip_tags,
                                           verbosity)

        playbooks = (constants.MAJOR_UPGRADE_PLAYBOOKS
                     if playbook == 'all' else playbook)
        self.log.info(("Completed Overcloud Upgrade Run for {0} with "
                       "playbooks {1} ").format(limit_hosts, playbooks))


class UpgradeConvergeOvercloud(DeployOvercloud):
    """Major upgrade converge - reset Heat resources in the stored plan

       This is the last step for completion of a overcloud major
       upgrade.  The main task is updating the plan and stack to
       unblock future stack updates. For the major upgrade workflow we
       have set specific values for some stack Heat resources. This
       unsets those back to their default values.
    """

    log = logging.getLogger(__name__ + ".UpgradeConvergeOvercloud")

    def get_parser(self, prog_name):
        parser = super(UpgradeConvergeOvercloud, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager
        stack = oooutils.get_stack(clients.orchestration,
                                   parsed_args.stack)
        # Add the converge environment into the args to unset noop etc
        templates_dir = (parsed_args.templates or
                         constants.TRIPLEO_HEAT_TEMPLATES)
        parsed_args.environment_files = oooutils.prepend_environment(
            parsed_args.environment_files, templates_dir,
            constants.UPGRADE_CONVERGE_ENV)

        super(UpgradeConvergeOvercloud, self).take_action(parsed_args)
        self.log.info("Completed Overcloud Upgrade Converge for stack {0}"
                      .format(stack.stack_name))
