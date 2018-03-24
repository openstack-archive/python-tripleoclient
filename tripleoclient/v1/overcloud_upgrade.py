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
import os
import yaml

from osc_lib.i18n import _

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils as oooutils
from tripleoclient.v1.overcloud_deploy import DeployOvercloud
from tripleoclient.workflows import package_update


class UpgradePrepare(DeployOvercloud):
    """Run heat stack update for overcloud nodes to refresh heat stack outputs.

       The heat stack outputs are what we use later on to generate ansible
       playbooks which deliver the major upgrade workflow. This is used as the
       first step for a major upgrade of your overcloud.
    """

    log = logging.getLogger(__name__ + ".MajorUpgradePrepare")

    # enable preservation of all important files (plan env, user env,
    # roles/network data, user files) so that we don't have to pass
    # all env files on update command
    _keep_env_on_update = True

    def get_parser(self, prog_name):
        parser = super(UpgradePrepare, self).get_parser(prog_name)
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
        container_registry = parsed_args.container_registry_file

        # Update the container registry:
        if container_registry:
            with open(os.path.abspath(container_registry)) as content:
                registry = yaml.load(content.read())
        else:
            self.log.warning(
                "You have not provided a container registry file. Note "
                "that none of the containers on your environement will be "
                "updated. If you want to update your container you have "
                "to re-run this command and provide the registry file "
                "with: --container-registry-file option.")
            registry = None
        # Run update
        ceph_ansible_playbook = parsed_args.ceph_ansible_playbook
        # Run Overcloud deploy (stack update)
        # In case of update and upgrade we need to force the
        # update_plan_only. The heat stack update is done by the
        # packag_update mistral action
        parsed_args.update_plan_only = True
        super(UpgradePrepare, self).take_action(parsed_args)
        package_update.update(clients, container=stack_name,
                              container_registry=registry,
                              ceph_ansible_playbook=ceph_ansible_playbook)
        package_update.get_config(clients, container=stack_name)
        print("Update init on stack {0} complete.".format(
              parsed_args.stack))


class UpgradeRun(command.Command):
    """Run major upgrade ansible playbooks on Overcloud nodes"""

    log = logging.getLogger(__name__ + ".MajorUpgradeRun")

    def get_parser(self, prog_name):
        parser = super(UpgradeRun, self).get_parser(prog_name)
        nodes_or_roles = parser.add_mutually_exclusive_group(required=True)
        nodes_or_roles.add_argument(
            '--nodes', action="store", help=_(
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
        nodes_or_roles.add_argument(
            '--roles', action="store", help=_(
                "A string that identifies the role or comma-separated list of"
                "roles to be upgraded in this upgrade run invocation. "
                "NOTE: nodes of specified role(s) are upgraded in parallel. "
                "This is REQUIRED for controlplane roles. For non "
                "controlplane roles (e.g., \"Compute\"), you may consider "
                "instead using the --nodes argument to limit the upgrade to "
                "a specific node or list (comma separated string) of nodes.")
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
                                   "post_upgrade_steps_playbooks.yaml. Set "
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
        # Run ansible:
        roles = parsed_args.roles
        nodes = parsed_args.nodes
        limit_hosts = roles or nodes
        playbook = parsed_args.playbook
        inventory = oooutils.get_tripleo_ansible_inventory(
            parsed_args.static_inventory)
        skip_tags = self._validate_skip_tags(parsed_args.skip_tags)
        oooutils.run_update_ansible_action(self.log, clients, limit_hosts,
                                           inventory, playbook,
                                           constants.UPGRADE_QUEUE,
                                           constants.MAJOR_UPGRADE_PLAYBOOKS,
                                           package_update, skip_tags)


class UpgradeConvergeOvercloud(DeployOvercloud):
    """Converge the upgrade on Overcloud Nodes"""

    log = logging.getLogger(__name__ + ".UpgradeConvergeOvercloud")

    def get_parser(self, prog_name):
        parser = super(UpgradeConvergeOvercloud, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        stack = oooutils.get_stack(clients.orchestration,
                                   parsed_args.stack)
        stack_name = stack.stack_name

        parsed_args.update_plan_only = True
        super(UpgradeConvergeOvercloud, self).take_action(parsed_args)
        # Run converge steps
        package_update.converge_nodes(clients, container=stack_name)
