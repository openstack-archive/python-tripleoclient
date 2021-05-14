#   Copyright 2020 Red Hat, Inc.
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

from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from osc_lib import utils

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils


class OvercloudNetworkExtract(command.Command):

    log = logging.getLogger(__name__ + ".OvercloudNetworkExtract")

    def get_parser(self, prog_name):
        parser = super(OvercloudNetworkExtract, self).get_parser(prog_name)
        parser.add_argument('--stack', dest='stack', required=True,
                            help=_('Name or ID of heat stack '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud'))
        parser.add_argument('-o', '--output', required=True,
                            metavar='<network_deployment.yaml>',
                            help=_('The output file path describing the '
                                   'network deployment'))
        parser.add_argument('-y', '--yes', default=False, action='store_true',
                            help=_('Skip yes/no prompt for existing files '
                                   '(assume yes).'))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        output_path = os.path.abspath(parsed_args.output)

        overwrite = parsed_args.yes
        if (os.path.exists(output_path) and not overwrite
                and not oooutils.prompt_user_for_confirmation(
                    'Overwrite existing file %s [y/N]?' % parsed_args.output,
                    self.log)):
            raise oscexc.CommandError("Will not overwrite existing file:"
                                      " %s" % parsed_args.output)
        else:
            overwrite = True

        extra_vars = {
            "stack_name": parsed_args.stack,
            "output": output_path,
            "overwrite": overwrite
        }

        with oooutils.TempDirs() as tmp:
            oooutils.run_ansible_playbook(
                playbook='cli-overcloud-network-extract.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=oooutils.playbook_verbosity(self=self),
                extra_vars=extra_vars,
            )


class OvercloudNetworkProvision(command.Command):

    log = logging.getLogger(__name__ + ".OvercloudNetworkProvision")

    def get_parser(self, prog_name):
        parser = super(OvercloudNetworkProvision, self).get_parser(prog_name)

        parser.add_argument('networks_file',
                            metavar='<network_data.yaml>',
                            help=_('Configuration file describing the network '
                                   'deployment.'))
        parser.add_argument('-o', '--output', required=True,
                            metavar='<network_environment.yaml>',
                            help=_('The output network environment file '
                                   'path.'))
        parser.add_argument('-y', '--yes', default=False, action='store_true',
                            help=_('Skip yes/no prompt for existing files '
                                   '(assume yes).'))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        networks_file_path = os.path.abspath(parsed_args.networks_file)
        output_path = os.path.abspath(parsed_args.output)

        if not os.path.exists(networks_file_path):
            raise oscexc.CommandError(
                "Network configuration file does not exist:"
                " %s" % parsed_args.networks_file)

        overwrite = parsed_args.yes
        if (os.path.exists(output_path) and not overwrite
                and not oooutils.prompt_user_for_confirmation(
                    'Overwrite existing file %s [y/N]?' % parsed_args.output,
                    self.log)):
            raise oscexc.CommandError("Will not overwrite existing file:"
                                      " %s" % parsed_args.output)
        else:
            overwrite = True

        extra_vars = {
            "network_data_path": networks_file_path,
            "network_deployed_path": output_path,
            "overwrite": overwrite
        }

        with oooutils.TempDirs() as tmp:
            oooutils.run_ansible_playbook(
                playbook='cli-overcloud-network-provision.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=oooutils.playbook_verbosity(self=self),
                extra_vars=extra_vars,
            )


class OvercloudVirtualIPsExtract(command.Command):

    log = logging.getLogger(__name__ + ".OvercloudVirtualIPsExtract")

    def get_parser(self, prog_name):
        parser = super(OvercloudVirtualIPsExtract, self).get_parser(prog_name)
        parser.add_argument('--stack', dest='stack', required=True,
                            help=_('Name of heat stack '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud'))
        parser.add_argument('-o', '--output', required=True,
                            metavar='<vip_data.yaml>',
                            help=_('The output file path describing the '
                                   'Virtual IP deployment'))
        parser.add_argument('-y', '--yes', default=False, action='store_true',
                            help=_('Skip yes/no prompt for existing files '
                                   '(assume yes).'))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        output_path = os.path.abspath(parsed_args.output)

        overwrite = parsed_args.yes
        if (os.path.exists(output_path) and not overwrite
                and not oooutils.prompt_user_for_confirmation(
                    'Overwrite existing file %s [y/N]?' % parsed_args.output,
                    self.log)):
            raise oscexc.CommandError("Will not overwrite existing file:"
                                      " %s" % parsed_args.output)
        else:
            overwrite = True

        extra_vars = {
            "stack_name": parsed_args.stack,
            "output": output_path,
            "overwrite": overwrite
        }

        with oooutils.TempDirs() as tmp:
            oooutils.run_ansible_playbook(
                playbook='cli-overcloud-network-vip-extract.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=oooutils.playbook_verbosity(self=self),
                extra_vars=extra_vars,
            )


class OvercloudVirtualIPsProvision(command.Command):

    log = logging.getLogger(__name__ + ".OvercloudVirtualIPsProvision")

    def get_parser(self, prog_name):
        parser = super(OvercloudVirtualIPsProvision, self).get_parser(
            prog_name)

        parser.add_argument('vip_file',
                            metavar='<vip_data.yaml>',
                            help=_('Configuration file describing the network '
                                   'deployment.'))
        parser.add_argument('--stack', dest='stack', required=True,
                            help=_('Name of heat stack '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud'))
        parser.add_argument('-o', '--output', required=True,
                            metavar='<vip_environment.yaml>',
                            help=_('The output Virtual IP environment file '
                                   'path.'))
        parser.add_argument('-y', '--yes', default=False, action='store_true',
                            help=_('Skip yes/no prompt for existing files '
                                   '(assume yes).'))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        vip_file_path = os.path.abspath(parsed_args.vip_file)
        output_path = os.path.abspath(parsed_args.output)

        if not os.path.exists(vip_file_path):
            raise oscexc.CommandError(
                "Virtual IPs configuration file does not exist:"
                " %s" % parsed_args.vip_file)

        overwrite = parsed_args.yes
        if (os.path.exists(output_path) and not overwrite
                and not oooutils.prompt_user_for_confirmation(
                    'Overwrite existing file %s [y/N]?' % parsed_args.output,
                    self.log)):
            raise oscexc.CommandError("Will not overwrite existing file:"
                                      " %s" % parsed_args.output)
        else:
            overwrite = True

        extra_vars = {
            "stack_name": parsed_args.stack,
            "vip_data_path": vip_file_path,
            "vip_deployed_path": output_path,
            "overwrite": overwrite
        }

        with oooutils.TempDirs() as tmp:
            oooutils.run_ansible_playbook(
                playbook='cli-overcloud-network-vip-provision.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=oooutils.playbook_verbosity(self=self),
                extra_vars=extra_vars,
            )
