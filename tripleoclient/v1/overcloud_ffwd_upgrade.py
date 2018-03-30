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
import logging

from osc_lib.i18n import _

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils
from tripleoclient.v1.overcloud_deploy import DeployOvercloud
from tripleoclient.workflows import package_update


class FFWDUpgradePrepare(DeployOvercloud):
    """Run heat stack update for overcloud nodes to refresh heat stack outputs.

       The heat stack outputs are what we use later on to generate ansible
       playbooks which deliver the ffwd upgrade workflow. This is used as the
       first step for a fast forward upgrade of your overcloud.
    """

    log = logging.getLogger(__name__ + ".FFWDUpgradePrepare")

    def get_parser(self, prog_name):
        parser = super(FFWDUpgradePrepare, self).get_parser(prog_name)
        parser.add_argument('--container-registry-file',
                            dest='container_registry_file',
                            default=None,
                            help=_("File which contains the container "
                                   "registry data for the upgrade"),
                            )
        parser.add_argument('--ceph-ansible-playbook',
                            action="store",
                            default="/usr/share/ceph-ansible"
                                    "/site-docker.yml.sample",
                            help=_('Path to switch the ceph-ansible playbook '
                                   'used for upgrade. '),
                            )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        stack = oooutils.get_stack(clients.orchestration,
                                   parsed_args.stack)

        stack_name = stack.stack_name
        registry = oooutils.load_container_registry(
            self.log, parsed_args.container_registry_file)
        ceph_ansible_playbook = parsed_args.ceph_ansible_playbook
        # In case of update and upgrade we need to force the
        # update_plan_only. The heat stack update is done by the
        # packag_update mistral action
        parsed_args.update_plan_only = True

        # Add the prepare environment into the args to unset noop etc
        templates_dir = (parsed_args.templates or
                         constants.TRIPLEO_HEAT_TEMPLATES)
        if not parsed_args.environment_files:
            parsed_args.environment_files = []
        parsed_args.environment_files = oooutils.prepend_environment(
            parsed_args.environment_files, templates_dir,
            constants.FFWD_UPGRADE_PREPARE_ENV)

        super(FFWDUpgradePrepare, self).take_action(parsed_args)
        package_update.update(clients, container=stack_name,
                              container_registry=registry,
                              ceph_ansible_playbook=ceph_ansible_playbook)
        package_update.get_config(clients, container=stack_name)
        print("FFWD Upgrade Prepare on stack {0} complete.".format(
              parsed_args.stack))


class FFWDUpgradeRun(command.Command):
    """Run fast forward upgrade ansible playbooks on Overcloud nodes

       This will run the fast_forward_upgrade_playbook.yaml ansible playbook.
       This playbook was generated when you ran the 'ffwd-upgrade prepare'
       command. Running 'ffwd-upgrade run ' is the second step in the ffwd
       upgrade workflow.
    """
    log = logging.getLogger(__name__ + ".FFWDUpgradeRun")

    def get_parser(self, prog_name):
        parser = super(FFWDUpgradeRun, self).get_parser(prog_name)
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
                            default="heat-admin",
                            help=_("The ssh user name for connecting to "
                                   "the overcloud nodes.")
                            )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager
        # Run ansible:
        inventory = oooutils.get_tripleo_ansible_inventory(
            parsed_args.static_inventory)
        # Don't expost limit_hosts. We need this on the whole overcloud.
        limit_hosts = ''
        oooutils.run_update_ansible_action(
            self.log, clients, limit_hosts, inventory,
            constants.FFWD_UPGRADE_PLAYBOOK, constants.FFWD_UPGRADE_QUEUE,
            [], package_update, parsed_args.ssh_user)


class FFWDUpgradeConverge(DeployOvercloud):
    """Converge the fast-forward upgrade on Overcloud Nodes

       This is the last step for completion of a fast forward upgrade.
       There is no heat stack update performed here. The main task is updating
       the plan to unblock future stack updates. For the ffwd upgrade workflow
       we have set and used the config-download Software/Structured Deployment
       for the OS::TripleO and OS::Heat resources. This unsets those back
       to their default values, in the swift stored plan.
    """

    log = logging.getLogger(__name__ + ".FFWDUpgradeConverge")

    def get_parser(self, prog_name):
        parser = super(FFWDUpgradeConverge, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        stack = oooutils.get_stack(clients.orchestration,
                                   parsed_args.stack)
        stack_name = stack.stack_name

        parsed_args.update_plan_only = True
        # Add the converge environment into the args to unset noop etc
        templates_dir = (parsed_args.templates or
                         constants.TRIPLEO_HEAT_TEMPLATES)
        if not parsed_args.environment_files:
            parsed_args.environment_files = []
        parsed_args.environment_files = oooutils.prepend_environment(
            parsed_args.environment_files, templates_dir,
            constants.FFWD_UPGRADE_CONVERGE_ENV)

        super(FFWDUpgradeConverge, self).take_action(parsed_args)
        # Run converge steps
        package_update.ffwd_converge_nodes(
            clients, container=stack_name,
            queue_name=constants.FFWD_UPGRADE_QUEUE)
        print("FFWD Upgrade Converge on stack {0} complete.".format(
              parsed_args.stack))
