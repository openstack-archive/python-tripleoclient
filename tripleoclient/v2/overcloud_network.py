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
        parser.add_argument('--templates',
                            help=_("The directory containing the Heat "
                                   "templates to deploy"),
                            default=constants.TRIPLEO_HEAT_TEMPLATES)
        parser.add_argument('--stack', dest='stack',
                            help=_('Name or ID of heat stack, when set the '
                                   'networks file will be copied to the '
                                   'working dir.'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default=None))
        parser.add_argument(
            '--working-dir', action='store',
            help=_('The working directory for the deployment where all '
                   'input, output, and generated files will be stored.\n'
                   'Defaults to "$HOME/overcloud-deploy-<stack>"')
        )

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
            "overwrite": overwrite,
            "templates": parsed_args.templates,
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

        if parsed_args.stack:
            if not parsed_args.working_dir:
                working_dir = oooutils.get_default_working_dir(
                    parsed_args.stack)
            else:
                working_dir = os.path.abspath(parsed_args.working_dir)
            oooutils.makedirs(working_dir)

            oooutils.copy_to_wd(working_dir, networks_file_path,
                                parsed_args.stack, 'networks')


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
                                   'Virtual IPs.'))
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
        parser.add_argument('--templates',
                            help=_("The directory containing the Heat "
                                   "templates to deploy"),
                            default=constants.TRIPLEO_HEAT_TEMPLATES)
        parser.add_argument(
            '--working-dir', action='store',
            help=_('The working directory for the deployment where all '
                   'input, output, and generated files will be stored.\n'
                   'Defaults to "$HOME/overcloud-deploy-<stack>"')
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if not parsed_args.working_dir:
            working_dir = oooutils.get_default_working_dir(
                parsed_args.stack)
        else:
            working_dir = os.path.abspath(parsed_args.working_dir)
        oooutils.makedirs(working_dir)

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
            "overwrite": overwrite,
            "templates": parsed_args.templates,
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

        oooutils.copy_to_wd(working_dir, vip_file_path, parsed_args.stack,
                            'vips')


class OvercloudNetworkUnprovision(command.Command):

    log = logging.getLogger(__name__ + ".OvercloudNetworkUnprovision")

    def get_parser(self, prog_name):
        parser = super(OvercloudNetworkUnprovision, self).get_parser(prog_name)

        parser.add_argument('networks_file',
                            metavar='<network_data.yaml>',
                            help=_('Configuration file describing the network '
                                   'deployment.'))
        parser.add_argument('-y', '--yes',
                            help=_('Skip yes/no prompt (assume yes).'),
                            default=False,
                            action="store_true")

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        networks_file_path = os.path.abspath(parsed_args.networks_file)

        if not parsed_args.yes:
            confirm = oooutils.prompt_user_for_confirmation(
                message=_("Are you sure you want to unprovision the networks "
                          "mentioned in file %s [y/N]? " % networks_file_path),
                logger=self.log)
            if not confirm:
                raise oscexc.CommandError("Action not confirmed, exiting.")

        if not os.path.exists(networks_file_path):
            raise oscexc.CommandError(
                "Network configuration file does not exist:"
                " %s" % parsed_args.networks_file)

        extra_vars = {
            "network_data_path": networks_file_path,
        }

        with oooutils.TempDirs() as tmp:
            oooutils.run_ansible_playbook(
                playbook='cli-overcloud-network-unprovision.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=oooutils.playbook_verbosity(self=self),
                extra_vars=extra_vars,
            )
