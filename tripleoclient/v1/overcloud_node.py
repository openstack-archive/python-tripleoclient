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

import argparse
import logging
import uuid

from osc_lib.command import command
from osc_lib.i18n import _
from osc_lib import utils

from tripleoclient import constants
from tripleoclient.exceptions import InvalidConfiguration
from tripleoclient import utils as oooutils
from tripleoclient.workflows import baremetal
from tripleoclient.workflows import scale


class DeleteNode(command.Command):
    """Delete overcloud nodes."""

    log = logging.getLogger(__name__ + ".DeleteNode")

    def get_parser(self, prog_name):
        parser = super(DeleteNode, self).get_parser(prog_name)
        parser.add_argument('nodes', metavar='<node>', nargs="+",
                            help=_('Node ID(s) to delete'))
        parser.add_argument('--stack', dest='stack',
                            help=_('Name or ID of heat stack to scale '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud'))
        parser.add_argument(
            '--templates', nargs='?', const=constants.TRIPLEO_HEAT_TEMPLATES,
            help=_("The directory containing the Heat templates to deploy. "
                   "This argument is deprecated. The command now utilizes "
                   "a deployment plan, which should be updated prior to "
                   "running this command, should that be required. Otherwise "
                   "this argument will be silently ignored."),
        )
        parser.add_argument(
            '-e', '--environment-file', metavar='<HEAT ENVIRONMENT FILE>',
            action='append', dest='environment_files',
            help=_("Environment files to be passed to the heat stack-create "
                   "or heat stack-update command. (Can be specified more than "
                   "once.) This argument is deprecated. The command now "
                   "utilizes a deployment plan, which should be updated prior "
                   "to running this command, should that be required. "
                   "Otherwise this argument will be silently ignored."),
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager
        orchestration_client = clients.orchestration

        stack = oooutils.get_stack(orchestration_client, parsed_args.stack)

        if not stack:
            raise InvalidConfiguration("stack {} not found".format(
                parsed_args.stack))

        nodes = '\n'.join('- %s' % node for node in parsed_args.nodes)
        print("Deleting the following nodes from stack {stack}:\n{nodes}"
              .format(stack=stack.stack_name, nodes=nodes))

        scale.scale_down(clients, stack.stack_name, parsed_args.nodes)


class ProvideNode(command.Command):
    """Mark nodes as available based on UUIDs or current 'manageable' state."""

    log = logging.getLogger(__name__ + ".ProvideNode")

    def get_parser(self, prog_name):
        parser = super(ProvideNode, self).get_parser(prog_name)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('node_uuids',
                           nargs="*",
                           metavar="<node_uuid>",
                           default=[],
                           help=_('Baremetal Node UUIDs for the node(s) to be '
                                  'provided'))
        group.add_argument("--all-manageable",
                           action='store_true',
                           help=_("Provide all nodes currently in 'manageable'"
                                  " state"))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        queue_name = str(uuid.uuid4())

        if parsed_args.node_uuids:
            baremetal.provide(self.app.client_manager,
                              node_uuids=parsed_args.node_uuids,
                              queue_name=queue_name)
        else:
            baremetal.provide_manageable_nodes(self.app.client_manager,
                                               queue_name=queue_name)


class IntrospectNode(command.Command):
    """Introspect specified nodes or all nodes in 'manageable' state."""

    log = logging.getLogger(__name__ + ".IntrospectNode")

    def get_parser(self, prog_name):
        parser = super(IntrospectNode, self).get_parser(prog_name)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('node_uuids',
                           nargs="*",
                           metavar="<node_uuid>",
                           default=[],
                           help=_('Baremetal Node UUIDs for the node(s) to be '
                                  'introspected'))
        group.add_argument("--all-manageable",
                           action='store_true',
                           help=_("Introspect all nodes currently in "
                                  "'manageable' state"))
        parser.add_argument('--provide',
                            action='store_true',
                            help=_('Provide (make available) the nodes once '
                                   'introspected'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        queue_name = str(uuid.uuid4())
        nodes = parsed_args.node_uuids

        if nodes:
            baremetal.introspect(self.app.client_manager,
                                 node_uuids=nodes,
                                 queue_name=queue_name)
        else:
            baremetal.introspect_manageable_nodes(self.app.client_manager,
                                                  queue_name=queue_name)

        if parsed_args.provide:
            if nodes:
                baremetal.provide(self.app.client_manager,
                                  node_uuids=nodes,
                                  queue_name=queue_name)
            else:
                baremetal.provide_manageable_nodes(self.app.client_manager,
                                                   queue_name=queue_name)


class ImportNode(command.Command):
    """Import baremetal nodes from a JSON, YAML or CSV file.

    The node status will be set to 'manageable' by default.
    """

    log = logging.getLogger(__name__ + ".ImportNode")

    def get_parser(self, prog_name):
        parser = super(ImportNode, self).get_parser(prog_name)
        parser.add_argument('--introspect',
                            action='store_true',
                            help=_('Introspect the imported nodes'))
        parser.add_argument('--provide',
                            action='store_true',
                            help=_('Provide (make available) the nodes'))
        parser.add_argument('--no-deploy-image', action='store_true',
                            help=_('Skip setting the deploy kernel and '
                                   'ramdisk.'))
        parser.add_argument('--instance-boot-option',
                            choices=['local', 'netboot'], default='local',
                            help=_('Whether to set instances for booting from '
                                   'local hard drive (local) or network '
                                   '(netboot).'))
        parser.add_argument('env_file', type=argparse.FileType('r'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        nodes_config = oooutils.parse_env_file(parsed_args.env_file)

        queue_name = str(uuid.uuid4())

        if parsed_args.no_deploy_image:
            deploy_kernel = None
            deploy_ramdisk = None
        else:
            deploy_kernel = 'bm-deploy-kernel'
            deploy_ramdisk = 'bm-deploy-ramdisk'

        nodes = baremetal.register_or_update(
            self.app.client_manager,
            nodes_json=nodes_config,
            queue_name=queue_name,
            kernel_name=deploy_kernel,
            ramdisk_name=deploy_ramdisk,
            instance_boot_option=parsed_args.instance_boot_option
        )

        nodes_uuids = [node['uuid'] for node in nodes]

        if parsed_args.introspect:
            baremetal.introspect(self.app.client_manager,
                                 node_uuids=nodes_uuids,
                                 queue_name=queue_name)

        if parsed_args.provide:
            baremetal.provide(self.app.client_manager,
                              node_uuids=nodes_uuids,
                              queue_name=queue_name)


class ConfigureNode(command.Command):
    """Configure Node boot options."""

    log = logging.getLogger(__name__ + ".ConfigureNode")

    def get_parser(self, prog_name):
        parser = super(ConfigureNode, self).get_parser(prog_name)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('node_uuids',
                           nargs="*",
                           metavar="<node_uuid>",
                           default=[],
                           help=_('Baremetal Node UUIDs for the node(s) to be '
                                  'configured'))
        group.add_argument("--all-manageable",
                           action='store_true',
                           help=_("Configure all nodes currently in "
                                  "'manageable' state"))
        parser.add_argument('--deploy-kernel',
                            default='bm-deploy-kernel',
                            help=_('Image with deploy kernel.'))
        parser.add_argument('--deploy-ramdisk',
                            default='bm-deploy-ramdisk',
                            help=_('Image with deploy ramdisk.'))
        parser.add_argument('--instance-boot-option',
                            choices=['local', 'netboot'],
                            help=_('Whether to set instances for booting from '
                                   'local hard drive (local) or network '
                                   '(netboot).'))
        parser.add_argument('--root-device',
                            help=_('Define the root device for nodes. '
                                   'Can be either a list of device names '
                                   '(without /dev) to choose from or one of '
                                   'two strategies: largest or smallest. For '
                                   'it to work this command should be run '
                                   'after the introspection.'))
        parser.add_argument('--root-device-minimum-size',
                            type=int, default=4,
                            help=_('Minimum size (in GiB) of the detected '
                                   'root device. Used with --root-device.'))
        parser.add_argument('--overwrite-root-device-hints',
                            action='store_true',
                            help=_('Whether to overwrite existing root device '
                                   'hints when --root-device is used.'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        queue_name = str(uuid.uuid4())

        if parsed_args.node_uuids:
            baremetal.configure(
                self.app.client_manager,
                node_uuids=parsed_args.node_uuids,
                queue_name=queue_name,
                kernel_name=parsed_args.deploy_kernel,
                ramdisk_name=parsed_args.deploy_ramdisk,
                instance_boot_option=parsed_args.instance_boot_option,
                root_device=parsed_args.root_device,
                root_device_minimum_size=parsed_args.root_device_minimum_size,
                overwrite_root_device_hints=(
                    parsed_args.overwrite_root_device_hints)
            )
        else:
            baremetal.configure_manageable_nodes(
                self.app.client_manager,
                queue_name=queue_name,
                kernel_name=parsed_args.deploy_kernel,
                ramdisk_name=parsed_args.deploy_ramdisk,
                instance_boot_option=parsed_args.instance_boot_option,
                root_device=parsed_args.root_device,
                root_device_minimum_size=parsed_args.root_device_minimum_size,
                overwrite_root_device_hints=(
                    parsed_args.overwrite_root_device_hints)
            )
