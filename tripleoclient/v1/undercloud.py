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

"""Plugin action implementation"""

import argparse
import logging
import os
import subprocess
import sys

from openstackclient.i18n import _

from oslo_config import cfg

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils
from tripleoclient.v1 import undercloud_config

UNDERCLOUD_FAILURE_MESSAGE = """
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

An error has occured while deploying the Undercloud.

See the previous output for details about what went wrong.

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
"""

UNDERCLOUD_COMPLETION_MESSAGE = """
##########################################################

The Undercloud has been successfully installed.

Useful files:

Password file is at {0}
The stackrc file is at {1}

Use these files to interact with OpenStack services, and
ensure they are secured.

##########################################################
"""
UNDERCLOUD_UPGRADE_COMPLETION_MESSAGE = """
##########################################################

The Undercloud has been successfully upgraded.

Useful files:

Password file is at {0}
The stackrc file is at {1}

Use these files to interact with OpenStack services, and
ensure they are secured.

##########################################################
"""


class InstallUndercloud(command.Command):
    """Install and setup the undercloud"""

    auth_required = False
    log = logging.getLogger(__name__ + ".InstallUndercloud")
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
            help=_("Do not perform undercloud configuration validations"),
        )
        parser.add_argument(
            '--inflight-validations',
            dest='inflight',
            action='store_true',
            default=False,
            help=_('Activate in-flight validations during the deploy. '
                   'In-flight validations provide a robust way to ensure '
                   'deployed services are running right after their '
                   'activation. Defaults to False.')
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
        parser.add_argument(
            '--disable-container-prepare',
            action='store_true',
            default=False,
            help=_('Disable the container preparation actions to prevent '
                   'container tags from being updated and new containers '
                   'from being fetched. If you skip this but do not have '
                   'the container parameters configured, the deployment '
                   'action may fail.')
        )
        return parser

    def take_action(self, parsed_args):
        # Fetch configuration used to add logging to a file
        utils.load_config(self.osloconfig, constants.UNDERCLOUD_CONF_PATH)
        utils.configure_logging(self.log, self.app_args.verbose_level,
                                self.osloconfig['undercloud_log_file'])
        self.log.debug("take_action(%s)" % parsed_args)

        utils.ensure_run_as_normal_user()
        no_validations = parsed_args.dry_run or parsed_args.no_validations
        inflight = not parsed_args.dry_run and parsed_args.inflight

        cmd = undercloud_config.prepare_undercloud_deploy(
            no_validations=no_validations,
            verbose_level=self.app_args.verbose_level,
            force_stack_update=parsed_args.force_stack_update,
            dry_run=parsed_args.dry_run,
            inflight=inflight,
            disable_container_prepare=parsed_args.disable_container_prepare)

        self.log.warning("Running: %s" % ' '.join(cmd))
        if not parsed_args.dry_run:
            try:
                subprocess.check_call(cmd)
                self.log.warning(UNDERCLOUD_COMPLETION_MESSAGE.format(
                    os.path.join(
                        constants.UNDERCLOUD_OUTPUT_DIR,
                        'undercloud-passwords.conf'
                    ),
                    '~/stackrc'
                    ))
            except Exception as e:
                self.log.error(UNDERCLOUD_FAILURE_MESSAGE)
                self.log.error(e)
                raise exceptions.DeploymentError(e)


class UpgradeUndercloud(InstallUndercloud):
    """Upgrade undercloud"""

    auth_required = False
    log = logging.getLogger(__name__ + ".UpgradeUndercloud")
    osloconfig = cfg.CONF

    def get_parser(self, prog_name):
        parser = super(UpgradeUndercloud, self).get_parser(prog_name)
        parser.add_argument('--skip-package-updates',
                            dest='skip_package_updates',
                            action='store_true',
                            default=False,
                            help=_("Flag to skip the package update when "
                                   "performing upgrades and updates"),
                            )
        return parser

    def _update_extra_packages(self, packages=[], dry_run=False):
        """Necessary packages to be updated before undercloud upgrade."""

        if not packages:
            return

        cmd = ['sudo', 'dnf', 'upgrade', '-y'] + packages

        if not dry_run:
            self.log.warning("Updating necessary packages: {}".format(
                             " ".join(packages)))
            output = utils.run_command(cmd, name="Update extra packages")
            self.log.warning("{}".format(output))
        else:
            self.log.warning("Would update necessary packages: {}".format(
                " ".join(cmd)))

    def _invoke_self(self, parsed_args):
        cmd = ['openstack', 'undercloud', 'upgrade', '--skip-package-updates']
        opts = {'force_stack_update': '--force-stack-update',
                'no_validations': '--no-validations',
                'inflight': '--inflight-validations',
                'dry_run': '--dry-run',
                'yes': '--yes'}
        args = vars(parsed_args)
        for k, v in opts.items():
            if args[k]:
                cmd.append(v)
        # handle --debug
        if self.app_args.verbose_level > 1:
            cmd.append('--debug')
        try:
            subprocess.check_call(cmd)
        except Exception as e:
            self.log.error(e)
            raise exceptions.DeploymentError(e)

    def _run_upgrade(self, parsed_args):
        cmd = undercloud_config.\
            prepare_undercloud_deploy(
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
                self.log.warning(
                    UNDERCLOUD_UPGRADE_COMPLETION_MESSAGE.format(
                        os.path.join(
                            constants.UNDERCLOUD_OUTPUT_DIR,
                            'undercloud-passwords.conf'
                        ),
                        '~/stackrc'))
            except Exception as e:
                self.log.error(UNDERCLOUD_FAILURE_MESSAGE)
                self.log.error(e)
                raise exceptions.DeploymentError(e)

    def take_action(self, parsed_args):
        # Fetch configuration used to add logging to a file
        utils.load_config(self.osloconfig, constants.UNDERCLOUD_CONF_PATH)
        utils.configure_logging(self.log, self.app_args.verbose_level,
                                self.osloconfig['undercloud_log_file'])
        self.log.debug("take action(%s)" % parsed_args)

        if (not parsed_args.yes
                and not utils.prompt_user_for_confirmation(
                    constants.UPGRADE_PROMPT, self.log)):
            raise exceptions.UndercloudUpgradeNotConfirmed(
                    constants.UPGRADE_NO)

        utils.ensure_run_as_normal_user()

        if not parsed_args.skip_package_updates:
            if ('python3' in sys.executable):
                pyver = '3'
            else:
                pyver = '2'
            client_pkgs = [
                "python{}-tripleoclient".format(pyver),
            ]
            pkgs = client_pkgs + constants.UNDERCLOUD_EXTRA_PACKAGES
            self._update_extra_packages(pkgs, parsed_args.dry_run)
            self._invoke_self(parsed_args)
        else:
            self._run_upgrade(parsed_args)
