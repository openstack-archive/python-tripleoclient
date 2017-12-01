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
import subprocess

from openstackclient.i18n import _

from tripleoclient import command
from tripleoclient import utils
from tripleoclient.v1 import undercloud_config


class InstallUndercloud(command.Command):
    """Install and setup the undercloud"""

    auth_required = False
    log = logging.getLogger(__name__ + ".InstallUndercloud")

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False
        )
        parser.add_argument(
            '--use-heat',
            dest='use_heat',
            action='store_true',
            default=False,
            help=_("Perform undercloud deploy using heat"),
        )
        parser.add_argument(
            '--no-validations',
            dest='no_validations',
            action='store_true',
            default=False,
            help=_("Do not perform undercloud configuration validations"),
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        utils.ensure_run_as_normal_user()
        if parsed_args.use_heat:
            cmd = undercloud_config.\
                prepare_undercloud_deploy(no_validations=parsed_args.
                                          no_validations)
            print("Running: %s" % ' '.join(cmd))
            subprocess.check_call(cmd)
        else:
            subprocess.check_call("instack-install-undercloud")


class UpgradeUndercloud(InstallUndercloud):
    """Upgrade undercloud"""

    auth_required = False
    log = logging.getLogger(__name__ + ".UpgradeUndercloud")

    def take_action(self, parsed_args):
        self.log.debug("take action(%s)" % parsed_args)

        utils.ensure_run_as_normal_user()
        if parsed_args.use_heat:
            cmd = undercloud_config.\
                prepare_undercloud_deploy(upgrade=True,
                                          no_validations=parsed_args.
                                          no_validations)
            print("Running: %s" % ' '.join(cmd))
            subprocess.check_call(cmd)
        else:
            subprocess.check_call(['sudo', 'yum', 'update', '-y',
                                  'instack-undercloud'])
            subprocess.check_call("instack-pre-upgrade-undercloud")
            subprocess.check_call("instack-upgrade-undercloud")
            # restart nova-api
            # https://bugzilla.redhat.com/show_bug.cgi?id=1315467
            subprocess.check_call(['sudo', 'systemctl', 'restart',
                                  'openstack-nova-api'])
