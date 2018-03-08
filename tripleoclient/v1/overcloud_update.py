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

import logging
import os
import yaml

from osc_lib.i18n import _

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils
from tripleoclient.v1.overcloud_deploy import DeployOvercloud
from tripleoclient.workflows import package_update


class UpdatePrepare(DeployOvercloud):
    """Run heat stack update for overcloud nodes to refresh heat stack outputs.

       The heat stack outputs are what we use later on to generate ansible
       playbooks which deliver the minor update workflow. This is used as the
       first step for a minor update of your overcloud.
    """

    log = logging.getLogger(__name__ + ".MinorUpdatePrepare")

    # enable preservation of all important files (plan env, user env,
    # roles/network data, user files) so that we don't have to pass
    # all env files on update command
    _keep_env_on_update = True

    def get_parser(self, prog_name):
        parser = super(UpdatePrepare, self).get_parser(prog_name)
        parser.add_argument('--container-registry-file',
                            dest='container_registry_file',
                            default=None,
                            help=_("File which contains the container "
                                   "registry data for the update"),
                            )
        parser.add_argument('--ceph-ansible-playbook',
                            action="store",
                            default="/usr/share/ceph-ansible"
                                    "/site-docker.yml.sample",
                            help=_('Path to switch the ceph-ansible playbook '
                                   'used for update. '),
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
        super(UpdatePrepare, self).take_action(parsed_args)
        package_update.update(clients, container=stack_name,
                              container_registry=registry,
                              ceph_ansible_playbook=ceph_ansible_playbook)
        package_update.get_config(clients, container=stack_name)
        print("Update init on stack {0} complete.".format(
              parsed_args.stack))


class UpdateRun(command.Command):
    """Run minor update ansible playbooks on Overcloud nodes"""

    log = logging.getLogger(__name__ + ".MinorUpdateRun")

    def get_parser(self, prog_name):
        parser = super(UpdateRun, self).get_parser(prog_name)
        parser.add_argument('--nodes',
                            action="store",
                            required=True,
                            help=_("Required parameter. This specifies the "
                                   "overcloud nodes to run the minor update "
                                   "playbooks on. You can use the name of "
                                   "a specific node, or the name of the role "
                                   "(e.g. Compute). You may also use the "
                                   "special value 'all' to run the minor "
                                   "on all nodes. In all cases the minor "
                                   "update ansible playbook is executed on "
                                   "one node at a time (with serial 1)")
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
        parser.add_argument('--static-inventory',
                            dest='static_inventory',
                            action="store",
                            default=None,
                            help=_('Path to an existing ansible inventory to '
                                   'use. If not specified, one will be '
                                   'generated in '
                                   '~/tripleo-ansible-inventory.yaml')
                            )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        # Run ansible:
        nodes = parsed_args.nodes
        if nodes == 'all':
            # unset this, the ansible action deals with unset 'limithosts'
            nodes = None
        playbook = parsed_args.playbook
        inventory = oooutils.get_tripleo_ansible_inventory(
            parsed_args.static_inventory)
        oooutils.run_update_ansible_action(self.log, clients, nodes, inventory,
                                           playbook, constants.UPDATE_QUEUE,
                                           constants.MINOR_UPDATE_PLAYBOOKS,
                                           package_update)
