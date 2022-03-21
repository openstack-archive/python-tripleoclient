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

import argparse
import getpass
import logging
import os

from osc_lib.i18n import _

from tripleoclient import command
from tripleoclient.constants import (DEFAULT_EPHEMERAL_HEAT_CONTAINER,
                                     DEFAULT_EPHEMERAL_HEAT_API_CONTAINER,
                                     DEFAULT_EPHEMERAL_HEAT_ENGINE_CONTAINER)
from tripleoclient import exceptions
from tripleoclient import utils


class LaunchHeat(command.Command):
    """Launch ephemeral Heat process."""

    log = logging.getLogger("tripleoclient")
    auth_required = False
    heat_pid = None

    def _kill_heat(self, parsed_args):
        """Tear down heat installer and temp files

        Kill the heat launcher/installer process.
        Teardown temp files created in the deployment process,
        when cleanup is requested.

        """
        if parsed_args.heat_type == "native":
            self.log.info("Attempting to kill ephemeral heat")
            if self.heat_pid:
                self.log.info("Using heat pid: %s" % self.heat_pid)
                self.heat_launcher.kill_heat(self.heat_pid)
                pid, ret = os.waitpid(self.heat_pid, 0)
                self.heat_pid = None
            else:
                self.log.info("No heat pid set, can't kill.")

        return 0

    def _launch_heat(self, parsed_args):
        self.log.info("Launching Heat %s" % parsed_args.heat_type)
        utils.launch_heat(self.heat_launcher, parsed_args.restore_db)
        return 0

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument(
            '--heat-api-port', metavar='<HEAT_API_PORT>',
            dest='heat_api_port',
            default='8006',
            help=_('Heat API port to use for the installers private'
                   ' Heat API instance. Optional.')
        )
        parser.add_argument(
            '--heat-user', metavar='<HEAT_USER>',
            dest='heat_user',
            default=getpass.getuser(),
            help=_('User to execute the non-privileged heat-all process. '
                   'Defaults to current user. '
                   'If the configuration files /etc/heat/heat.conf or '
                   '/usr/share/heat/heat-dist.conf exist, the user '
                   'must have read access to those files.\n'
                   'This option is ignored when using --heat-type=container '
                   'or --heat-type=pod')
        )
        parser.add_argument(
            '--heat-container-image', metavar='<HEAT_CONTAINER_IMAGE>',
            dest='heat_container_image',
            default=DEFAULT_EPHEMERAL_HEAT_CONTAINER,
            help=_('The container image to use when launching the heat-all '
                   'process. Defaults to: {}'.format(
                                            DEFAULT_EPHEMERAL_HEAT_CONTAINER))
        )
        parser.add_argument(
            '--heat-container-api-image',
            metavar='<HEAT_CONTAINER_API_IMAGE>',
            dest='heat_container_api_image',
            default=DEFAULT_EPHEMERAL_HEAT_API_CONTAINER,
            help=_('The container image to use when launching the heat-api '
                   'process. Only used when --heat-type=pod. '
                   'Defaults to: {}'.format(
                                    DEFAULT_EPHEMERAL_HEAT_API_CONTAINER))
        )
        parser.add_argument(
            '--heat-container-engine-image',
            metavar='<HEAT_CONTAINER_ENGINE_IMAGE>',
            dest='heat_container_engine_image',
            default=DEFAULT_EPHEMERAL_HEAT_ENGINE_CONTAINER,
            help=_('The container image to use when launching the heat-engine '
                   'process. Only used when --heat-type=pod. '
                   'Defaults to: {}'.format(
                                    DEFAULT_EPHEMERAL_HEAT_ENGINE_CONTAINER))
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
            default=os.path.join(
                        utils.get_default_working_dir('overcloud'),
                        'heat-launcher'),
            help=_("Directory to use for file storage and logs of the "
                   "running heat process. in the current directory. Can be "
                   "set to an already existing directory to reuse the "
                   "environment from a previos Heat process.")
        )
        parser.add_argument(
            '--rm-heat',
            action='store_true',
            default=False,
            help=_('If specified and --heat-type is container or pod '
                   'any existing container or pod of a previous '
                   'ephemeral Heat process will be deleted first. '
                   'Ignored if --heat-type is native or --kill.')
        )
        parser.add_argument(
            '--skip-heat-pull',
            action='store_true',
            default=False,
            help=_('When --heat-type is pod or container, assume '
                   'the container image has already been pulled ')
        )
        parser.add_argument(
            '--restore-db',
            action='store_true',
            default=False,
            help=_('Restore a database dump if it exists '
                   'within the directory specified by --heat-dir')
        )
        heat_type_group = parser.add_mutually_exclusive_group()
        heat_type_group.add_argument(
            '--heat-native',
            dest='heat_native',
            action='store_true',
            default=False,
            help=_('(DEPRECATED): Execute the heat-all process natively on '
                   'this host. '
                   'This option requires that the heat-all binaries '
                   'be installed locally on this machine. '
                   'This option is enabled by default which means heat-all is '
                   'executed on the host OS directly.\n'
                   'Conflicts with --heat-type, which deprecates '
                   '--heat-native.')
        )
        heat_type_group.add_argument(
            '--heat-type',
            dest='heat_type',
            default='pod',
            choices=['native', 'container', 'pod'],
            help=_('Type of ephemeral Heat process to launch. One of: '
                   'native: Execute heat-all directly on the host. '
                   'container: Execute heat-all in a container. '
                   'pod: Execute separate heat api and engine processes in '
                   'a podman pod.')
        )
        return parser

    def take_action(self, parsed_args):
        self._configure_logging(parsed_args)
        self.log.debug("take_action(%s)" % parsed_args)

        if parsed_args.heat_native:
            heat_type = "native"
        else:
            heat_type = parsed_args.heat_type

        if parsed_args.kill:
            rm_heat = True
        else:
            rm_heat = parsed_args.rm_heat

        self.heat_launcher = utils.get_heat_launcher(
            heat_type, parsed_args.heat_api_port,
            parsed_args.heat_container_image,
            parsed_args.heat_container_api_image,
            parsed_args.heat_container_engine_image,
            parsed_args.heat_user,
            parsed_args.heat_dir,
            False,
            False,
            rm_heat,
            parsed_args.skip_heat_pull)

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
            else:
                self.log.info("Writing heat clouds.yaml")
                utils.write_ephemeral_heat_clouds_yaml(parsed_args.heat_dir)
