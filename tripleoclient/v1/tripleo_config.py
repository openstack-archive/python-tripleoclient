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
from __future__ import print_function

import argparse
import logging

from cliff import command
from osc_lib.i18n import _

from tripleoclient import constants
from tripleoclient import utils

# For ansible.cfg generation
from tripleo_common.actions import ansible


class GenerateAnsibleConfig(command.Command):
    """Generate the default ansible.cfg for UC/AIO-standalone deployments."""

    log = logging.getLogger(__name__ + ".GenerateAnsibleConfig")

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False
        )
        # TODO(bogdando): drop that once using oslo.privsep
        parser.add_argument(
            '--deployment-user',
            dest='deployment_user',
            default='stack',
            help=_('User who executes the tripleo config generate command. '
                   'Defaults to stack.')
        )
        # TODO(bogdando): find a better UNDERCLOUD_OUTPUT_DIR constant name
        # Add more params as far as the imported ansible actions support it
        parser.add_argument('--output-dir',
                            dest='output_dir',
                            help=_("Directory to output ansible.cfg and "
                                   "ansible.log files."),
                            default=constants.UNDERCLOUD_OUTPUT_DIR)

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        if utils.get_deployment_user() != parsed_args.deployment_user:
            self.log.warning(
                _('The --deployment-user value %s does not '
                  'match the user name executing this command!') %
                parsed_args.deployment_user)

        # FIXME(bogdando): unhardcode key/transport for future multi-node
        ansible.write_default_ansible_cfg(parsed_args.output_dir,
                                          parsed_args.deployment_user,
                                          ssh_private_key=None,
                                          transport='local')
