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
from __future__ import print_function

import argparse
import getpass
import logging
import os

from cliff import command
from osc_lib.i18n import _

from tripleoclient import exceptions
from tripleoclient import heat_launcher


class LaunchHeat(command.Command):
    """Launch all-in-one Heat process and run in the foreground."""

    log = logging.getLogger(__name__ + ".Deploy")
    auth_required = False
    heat_pid = None

    def _kill_heat(self, parsed_args):
        """Tear down heat installer and temp files

        Kill the heat launcher/installer process.
        Teardown temp files created in the deployment process,
        when cleanup is requested.

        """
        if self.heat_pid:
            self.heat_launch.kill_heat(self.heat_pid)
            pid, ret = os.waitpid(self.heat_pid, 0)
            self.heat_pid = None

        return 0

    def _launch_heat(self, parsed_args):
        # we do this as root to chown config files properly for docker, etc.
        if parsed_args.heat_native is not None and \
                parsed_args.heat_native.lower() == "false":
            self.heat_launch = heat_launcher.HeatContainerLauncher(
                parsed_args.heat_api_port,
                parsed_args.heat_container_image,
                parsed_args.heat_user,
                parsed_args.heat_dir)
        else:
            self.heat_launch = heat_launcher.HeatNativeLauncher(
                parsed_args.heat_api_port,
                parsed_args.heat_container_image,
                parsed_args.heat_user,
                parsed_args.heat_dir)

        self.heat_launch.heat_db_sync()
        self.heat_launch.launch_heat()

        return 0

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False
        )
        parser.add_argument(
            '--heat-api-port', metavar='<HEAT_API_PORT>',
            dest='heat_api_port',
            default='8006',
            help=_('Heat API port to use for the installers private'
                   ' Heat API instance. Optional. Default: 8006.)')
        )
        parser.add_argument(
            '--heat-user', metavar='<HEAT_USER>',
            dest='heat_user',
            default=getpass.getuser(),
            help=_('User to execute the non-privileged heat-all process. '
                   'Defaults to current user. '
                   'If the configuration files /etc/heat/heat.conf or '
                   '/usr/share/heat/heat-dist.conf exist, the user '
                   'must have read access to those files.')
        )
        parser.add_argument(
            '--heat-container-image', metavar='<HEAT_CONTAINER_IMAGE>',
            dest='heat_container_image',
            default='tripleomaster/centos-binary-heat-all:current-tripleo',
            help=_('The container image to use when launching the heat-all '
                   'process. Defaults to: '
                   'tripleomaster/centos-binary-heat-all:current-tripleo')
        )
        parser.add_argument(
            '--heat-native',
            dest='heat_native',
            nargs='?',
            default=None,
            const="true",
            help=_('Execute the heat-all process natively on this host. '
                   'This option requires that the heat-all binaries '
                   'be installed locally on this machine. '
                   'This option is enabled by default which means heat-all is '
                   'executed on the host OS directly.')
        )
        parser.add_argument(
            '--kill', '-k',
            dest='kill',
            action='store_true',
            default=False,
            help=_('Kill the running heat process (if found).')
        )
        parser.add_argument(
            '--heat-dir',
            dest='heat_dir',
            action='store',
            default=os.path.join(os.getcwd(), 'heat-launcher'),
            help=_("Directory to use for file storage and logs of the "
                   "running heat process. Defaults to 'heat-launcher' "
                   "in the current directory.")
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        if parsed_args.kill:
            if self._kill_heat(parsed_args) != 0:
                msg = _('Heat kill failed.')
                self.log.error(msg)
                raise exceptions.DeploymentError(msg)
        else:
            if self._launch_heat(parsed_args) != 0:
                msg = _('Heat launch failed.')
                self.log.error(msg)
                raise exceptions.DeploymentError(msg)
