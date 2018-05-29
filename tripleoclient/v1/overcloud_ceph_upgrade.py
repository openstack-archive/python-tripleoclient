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

from osc_lib.i18n import _

from tripleoclient import constants
from tripleoclient import utils as oooutils
from tripleoclient.v1.overcloud_deploy import DeployOvercloud
from tripleoclient.workflows import package_update


class CephUpgrade(DeployOvercloud):
    """Run heat stack update for overcloud nodes to run Ceph upgrade."""

    log = logging.getLogger(__name__ + ".CephUpgrade")

    def get_parser(self, prog_name):
        parser = super(CephUpgrade, self).get_parser(prog_name)
        parser.add_argument('--ceph-ansible-playbook',
                            action="store",
                            default="/usr/share/ceph-ansible"
                                    "/infrastructure-playbooks"
                                    "/rolling_update.yml",
                            help=_('Path to switch the ceph-ansible playbook '
                                   'used for update. '))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        stack = oooutils.get_stack(clients.orchestration,
                                   parsed_args.stack)

        stack_name = stack.stack_name

        # Run update
        ceph_ansible_playbook = parsed_args.ceph_ansible_playbook
        # Run Overcloud deploy (stack update)
        # In case of update and upgrade we need to force the
        # update_plan_only. The heat stack update is done by the
        # package_update mistral action
        parsed_args.update_plan_only = True

        # Add the upgrade-prepare.yaml environment to set noops etc
        templates_dir = (parsed_args.templates or
                         constants.TRIPLEO_HEAT_TEMPLATES)
        parsed_args.environment_files = oooutils.prepend_environment(
            parsed_args.environment_files, templates_dir,
            constants.CEPH_UPGRADE_PREPARE_ENV)

        super(CephUpgrade, self).take_action(parsed_args)
        package_update.update(clients, container=stack_name,
                              ceph_ansible_playbook=ceph_ansible_playbook)
        package_update.get_config(clients, container=stack_name)
        print("Ceph Upgrade on stack {0} complete.".format(
              parsed_args.stack))
