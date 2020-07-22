#   Copyright 2016 Red Hat, Inc.
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
import pwd
import shutil
import sys
import tempfile

from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from osc_lib import utils as osc_utils

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils
from tripleoclient.workflows import plan_management
from tripleoclient.workflows import stack_management

# For ansible.cfg generation
from tripleo_common.actions import ansible


class DeleteOvercloud(command.Command):
    """Delete overcloud stack and plan"""

    log = logging.getLogger(__name__ + ".DeleteOvercloud")

    def get_parser(self, prog_name):
        parser = super(DeleteOvercloud, self).get_parser(prog_name)
        parser.add_argument('stack', nargs='?',
                            help=_('Name or ID of heat stack to delete'
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=osc_utils.env('OVERCLOUD_STACK_NAME'))
        parser.add_argument('-y', '--yes',
                            help=_('Skip yes/no prompt (assume yes).'),
                            default=False,
                            action="store_true")
        parser.add_argument('-s', '--skip-ipa-cleanup',
                            help=_('Skip removing overcloud hosts, services, '
                                   'and DNS records from FreeIPA. This is '
                                   'particularly relevant for deployments '
                                   'using certificates from FreeIPA for TLS. '
                                   'By default, overcloud hosts, services, '
                                   'and DNS records will be removed from '
                                   'FreeIPA before deleting the overcloud. '
                                   'Using this option might require you to '
                                   'manually cleanup FreeIPA later.'),
                            default=False,
                            action="store_true")
        return parser

    def _validate_args(self, parsed_args):
        if parsed_args.stack in (None, ''):
            raise oscexc.CommandError(
                "You must specify a stack name")

    def _plan_undeploy(self, clients, stack_name):
        orchestration_client = clients.orchestration

        print("Undeploying stack {s}...".format(s=stack_name))
        stack = utils.get_stack(orchestration_client, stack_name)
        if stack is None:
            self.log.warning("No stack found ('{s}'), skipping delete".
                             format(s=stack_name))
        else:
            try:
                stack_management.plan_undeploy(
                    clients,
                    plan=stack.stack_name
                )
            except Exception as e:
                raise oscexc.CommandError(
                    "Error occurred during stack delete {}".
                    format(e))

    def _plan_delete(self, clients, stack_name):
        print("Deleting plan {s}...".format(s=stack_name))
        try:
            plan_management.delete_deployment_plan(
                clients,
                container=stack_name)
        except Exception as err:
            raise oscexc.CommandError(
                "Error occurred while deleting plan {}".format(err))

    def _cleanup_ipa(self, stack_name):
        python_interpreter = \
            "/usr/bin/python{}".format(sys.version_info[0])
        playbook = '/usr/share/ansible/tripleo-playbooks/cli-cleanup-ipa.yml'

        if not os.path.exists(playbook):
            self.log.debug(
                "{} doesn't exist on system. "
                "Ignoring IPA cleanup.".format(playbook)
            )
            return

        static_inventory = utils.get_tripleo_ansible_inventory(
            return_inventory_file_path=True)

        # We don't technically need remote_user to generate an ansible.cfg for
        # stack.  The write_default_ansible_cfg() method treats this as an
        # optional parameter even though the method signature requires it.
        remote_user = None
        tmp_tripleoclient_dir = tempfile.mkdtemp(prefix='tripleoclient-')
        self.log.debug(
            "Creating temporary directory for "
            "ansible config in {}".format(tmp_tripleoclient_dir)
        )

        ansible_config = ansible.write_default_ansible_cfg(
            tmp_tripleoclient_dir, remote_user)

        try:
            utils.run_ansible_playbook(
                self.log,
                constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                playbook,
                static_inventory,
                log_path_dir=pwd.getpwuid(os.getuid()).pw_dir,
                ansible_config=ansible_config,
                python_interpreter=python_interpreter
            )
        finally:
            self.log.debug("Removing static tripleo ansible inventory file")
            utils.cleanup_tripleo_ansible_inventory_file(static_inventory)
            self.log.debug(
                "Removing temporary ansible configuration directory"
            )
            shutil.rmtree(tmp_tripleoclient_dir)

    def take_action(self, parsed_args):
        self.log.debug("take_action({args})".format(args=parsed_args))

        self._validate_args(parsed_args)

        if not parsed_args.yes:
            confirm = utils.prompt_user_for_confirmation(
                message=_("Are you sure you want to delete this overcloud "
                          "[y/N]? "),
                logger=self.log)
            if not confirm:
                raise oscexc.CommandError("Action not confirmed, exiting.")

        clients = self.app.client_manager

        if not parsed_args.skip_ipa_cleanup:
            self._cleanup_ipa(parsed_args.stack)
        self._plan_undeploy(clients, parsed_args.stack)
        self._plan_delete(clients, parsed_args.stack)
        print("Success.")
