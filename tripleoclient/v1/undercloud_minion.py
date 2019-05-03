#   Copyright 2019 Red Hat, Inc.
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

"""Plugin action implementation"""

import argparse
import logging
import subprocess

from openstackclient.i18n import _

from oslo_config import cfg

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils
from tripleoclient.v1 import minion_config

MINION_FAILURE_MESSAGE = """
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

An error has occured while deploying the Undercloud Minion

See the previous output for details about what went wrong.

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
"""

MINION_COMPLETION_MESSAGE = """
##########################################################

The Undercloud Minion has been successfully installed.

##########################################################
"""
MINION_UPGRADE_COMPLETION_MESSAGE = """
##########################################################

The Undercloud Minion has been successfully upgraded.

##########################################################
"""


class InstallUndercloudMinion(command.Command):
    """Install and setup the undercloud minion"""

    auth_required = False
    log = logging.getLogger(__name__ + ".InstallUndercloudMinion")
    osloconfig = cfg.CONF

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False
        )
        parser.add_argument('--force-stack-update',
                            dest='force_stack_update',
                            action='store_true',
                            default=False,
                            help=_("Do a virtual update of the ephemeral "
                                   "heat stack. New or failed deployments "
                                   "always have the stack_action=CREATE. This "
                                   "option enforces stack_action=UPDATE."),
                            )
        parser.add_argument(
            '--no-validations',
            dest='no_validations',
            action='store_true',
            default=False,
            help=_("Do not perform minion configuration validations"),
        )
        parser.add_argument(
            '--dry-run',
            dest='dry_run',
            action='store_true',
            default=False,
            help=_("Print the install command instead of running it"),
        )
        parser.add_argument('-y', '--yes', default=False,
                            action='store_true',
                            help=_("Skip yes/no prompt (assume yes)."))
        return parser

    def take_action(self, parsed_args):
        # Fetch configuration used to add logging to a file
        utils.load_config(self.osloconfig, constants.MINION_CONF_PATH)
        utils.configure_logging(self.log, self.app_args.verbose_level,
                                self.osloconfig['minion_log_file'])
        self.log.debug("take_action(%s)" % parsed_args)

        utils.ensure_run_as_normal_user()
        no_validations = parsed_args.dry_run or parsed_args.no_validations
        cmd = minion_config.prepare_minion_deploy(
            no_validations=no_validations,
            verbose_level=self.app_args.verbose_level,
            force_stack_update=parsed_args.force_stack_update,
            dry_run=parsed_args.dry_run)

        self.log.warning("Running: %s" % ' '.join(cmd))
        if not parsed_args.dry_run:
            try:
                subprocess.check_call(cmd)
                self.log.warning(MINION_COMPLETION_MESSAGE)
            except Exception as e:
                self.log.error(MINION_FAILURE_MESSAGE)
                self.log.error(e)
                raise exceptions.DeploymentError(e)


class UpgradeUndercloudMinion(InstallUndercloudMinion):
    """Upgrade undercloud minion"""

    auth_required = False
    log = logging.getLogger(__name__ + ".UpgradeUndercloudMinion")
    osloconfig = cfg.CONF

    def take_action(self, parsed_args):
        # Fetch configuration used to add logging to a file
        utils.load_config(self.osloconfig, constants.MINION_CONF_PATH)
        utils.configure_logging(self.log, self.app_args.verbose_level,
                                self.osloconfig['minion_log_file'])
        self.log.debug("take action(%s)" % parsed_args)

        utils.ensure_run_as_normal_user()
        cmd = minion_config.\
            prepare_minion_deploy(
                upgrade=True,
                yes=parsed_args.yes,
                no_validations=parsed_args.
                no_validations,
                verbose_level=self.app_args.verbose_level,
                force_stack_update=parsed_args.force_stack_update)
        self.log.warning("Running: %s" % ' '.join(cmd))
        if not parsed_args.dry_run:
            try:
                subprocess.check_call(cmd)
                self.log.warning(MINION_UPGRADE_COMPLETION_MESSAGE)
            except Exception as e:
                self.log.error(MINION_FAILURE_MESSAGE)
                self.log.error(e)
                raise exceptions.DeploymentError(e)
