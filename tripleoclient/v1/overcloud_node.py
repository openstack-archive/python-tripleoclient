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

import collections
import logging
import sys

from cliff.formatters import table
from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from osc_lib import utils
import six
import yaml

from tripleoclient import command
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
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('nodes', metavar='<node>', nargs="*",
                           default=[],
                           help=_('Node ID(s) to delete (otherwise specified '
                                  'in the --baremetal-deployment file)'))
        group.add_argument('-b', '--baremetal-deployment',
                           metavar='<BAREMETAL DEPLOYMENT FILE>',
                           help=_('Configuration file describing the '
                                  'baremetal deployment'))

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

        parser.add_argument(
            '--timeout', metavar='<TIMEOUT>',
            type=int, default=constants.STACK_TIMEOUT, dest='timeout',
            help=_("Timeout in minutes to wait for the nodes to be deleted. "
                   "Keep in mind that due to keystone session duration "
                   "that timeout has an upper bound of 4 hours ")
        )
        parser.add_argument('-y', '--yes',
                            help=_('Skip yes/no prompt (assume yes).'),
                            default=False,
                            action="store_true")
        return parser

    def _nodes_to_delete(self, parsed_args, roles):
        # expand for provisioned:False to get a list of nodes
        # to delete
        expanded = baremetal.expand_roles(
            self.app.client_manager,
            roles=roles,
            stackname=parsed_args.stack,
            provisioned=False)
        nodes = expanded.get('instances', [])
        if not nodes:
            print('No nodes to unprovision')
            return
        TableArgs = collections.namedtuple(
            'TableArgs', 'print_empty max_width fit_width')
        args = TableArgs(print_empty=True, max_width=80, fit_width=True)
        nodes_data = [(i.get('hostname', ''),
                       i.get('name', '')) for i in nodes]

        formatter = table.TableFormatter()
        output = six.StringIO()
        formatter.emit_list(
            column_names=['hostname', 'name'],
            data=nodes_data,
            stdout=output,
            parsed_args=args
        )
        return output.getvalue()

    def _translate_nodes_to_resources(self, parsed_args, roles):
        # build a dict of resource type names to role name
        role_types = dict(
            ('OS::TripleO::%sServer' % r['name'], r['name'])
            for r in roles
        )
        expanded = baremetal.expand_roles(
            self.app.client_manager,
            roles=roles,
            stackname=parsed_args.stack,
            provisioned=True)

        parameters = expanded.get(
            'environment', {}).get('parameter_defaults', {})

        # build a dict with the role and
        # a list of indexes of nodes to delete for that role
        removal_indexes = {}
        for role in role_types.values():
            removal_indexes.setdefault(role, [])
            param = '%sRemovalPolicies' % role
            policies = parameters.get(param, [])
            if policies:
                removal_indexes[role] = policies[0].get('resource_list', [])

        nodes = []
        clients = self.app.client_manager

        # iterate every server resource and compare its index with
        # the list of indexes to be deleted
        resources = clients.orchestration.resources.list(
            parsed_args.stack, nested_depth=5)
        for res in resources:
            if res.resource_type not in role_types:
                continue
            role = role_types[res.resource_type]
            removal_list = removal_indexes.get(role, [])

            index = int(res.parent_resource)
            if index in removal_list:
                node = res.physical_resource_id
                nodes.append(node)
        return nodes

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        if parsed_args.baremetal_deployment:
            with open(parsed_args.baremetal_deployment, 'r') as fp:
                roles = yaml.safe_load(fp)

            nodes_text = self._nodes_to_delete(parsed_args, roles)
            if nodes_text:
                nodes = self._translate_nodes_to_resources(
                    parsed_args, roles)
                print(nodes_text)
            else:
                return
        else:
            nodes = parsed_args.nodes
            nodes_text = '\n'.join('- %s' % node for node in nodes)
        if not parsed_args.yes:
            confirm = oooutils.prompt_user_for_confirmation(
                message=_("Are you sure you want to delete these overcloud "
                          "nodes [y/N]? "),
                logger=self.log)
            if not confirm:
                raise oscexc.CommandError("Action not confirmed, exiting.")

        orchestration_client = clients.orchestration

        stack = oooutils.get_stack(orchestration_client, parsed_args.stack)

        if not stack:
            raise InvalidConfiguration("stack {} not found".format(
                parsed_args.stack))

        print("Deleting the following nodes from stack {stack}:\n{nodes}"
              .format(stack=stack.stack_name, nodes=nodes_text))

        scale.scale_down(
            log=self.log,
            clients=clients,
            stack=stack,
            nodes=nodes,
            timeout=parsed_args.timeout
        )

        if parsed_args.baremetal_deployment:
            baremetal.undeploy_roles(
                self.app.client_manager,
                roles=roles,
                plan=parsed_args.stack)


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

        if parsed_args.node_uuids:
            baremetal.provide(self.app.client_manager,
                              node_uuids=parsed_args.node_uuids)
        else:
            baremetal.provide_manageable_nodes(self.app.client_manager)


class CleanNode(command.Command):
    """Run node(s) through cleaning."""

    log = logging.getLogger(__name__ + ".CleanNode")

    def get_parser(self, prog_name):
        parser = super(CleanNode, self).get_parser(prog_name)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('node_uuids',
                           nargs="*",
                           metavar="<node_uuid>",
                           default=[],
                           help=_('Baremetal Node UUIDs for the node(s) to be '
                                  'cleaned'))
        group.add_argument("--all-manageable",
                           action='store_true',
                           help=_("Clean all nodes currently in 'manageable'"
                                  " state"))
        parser.add_argument('--provide',
                            action='store_true',
                            help=_('Provide (make available) the nodes once '
                                   'cleaned'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        nodes = parsed_args.node_uuids

        if nodes:
            baremetal.clean_nodes(self.app.client_manager,
                                  node_uuids=parsed_args.node_uuids)
        else:
            baremetal.clean_manageable_nodes(self.app.client_manager)

        if parsed_args.provide:
            if nodes:
                baremetal.provide(self.app.client_manager,
                                  node_uuids=nodes,
                                  )
            else:
                baremetal.provide_manageable_nodes(self.app.client_manager)


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
        parser.add_argument(
            '--deploy-kernel',
            default='file://%s/agent.kernel' %
            constants.IRONIC_HTTP_BOOT_BIND_MOUNT,
            help=_('Image with deploy kernel.'))
        parser.add_argument(
            '--deploy-ramdisk',
            default='file://%s/agent.ramdisk' %
            constants.IRONIC_HTTP_BOOT_BIND_MOUNT,
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

        if parsed_args.node_uuids:
            baremetal.configure(
                self.app.client_manager,
                node_uuids=parsed_args.node_uuids,
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
                kernel_name=parsed_args.deploy_kernel,
                ramdisk_name=parsed_args.deploy_ramdisk,
                instance_boot_option=parsed_args.instance_boot_option,
                root_device=parsed_args.root_device,
                root_device_minimum_size=parsed_args.root_device_minimum_size,
                overwrite_root_device_hints=(
                    parsed_args.overwrite_root_device_hints)
            )


class DiscoverNode(command.Command):
    """Discover overcloud nodes by polling their BMCs."""

    log = logging.getLogger(__name__ + ".DiscoverNode")

    def get_parser(self, prog_name):
        parser = super(DiscoverNode, self).get_parser(prog_name)
        ip_group = parser.add_mutually_exclusive_group(required=True)
        ip_group.add_argument('--ip', action='append',
                              dest='ip_addresses', metavar='<ips>',
                              help=_('IP address(es) to probe'))
        ip_group.add_argument('--range', dest='ip_addresses',
                              metavar='<range>', help=_('IP range to probe'))
        parser.add_argument('--credentials', metavar='<key:value>',
                            action='append', required=True,
                            help=_('Key/value pairs of possible credentials'))
        parser.add_argument('--port', action='append', metavar='<ports>',
                            type=int, help=_('BMC port(s) to probe'))
        parser.add_argument('--introspect', action='store_true',
                            help=_('Introspect the imported nodes'))
        parser.add_argument('--run-validations', action='store_true',
                            default=False,
                            help=_('Run the pre-deployment validations. These '
                                   'external validations are from the TripleO '
                                   'Validations project.'))
        parser.add_argument('--provide', action='store_true',
                            help=_('Provide (make available) the nodes'))
        parser.add_argument('--no-deploy-image', action='store_true',
                            help=_('Skip setting the deploy kernel and '
                                   'ramdisk.'))
        parser.add_argument('--instance-boot-option',
                            choices=['local', 'netboot'], default='local',
                            help=_('Whether to set instances for booting from '
                                   'local hard drive (local) or network '
                                   '(netboot).'))
        parser.add_argument('--concurrency', type=int,
                            default=20,
                            help=_('Maximum number of nodes to introspect at '
                                   'once.'))
        return parser

    # FIXME(tonyb): This is not multi-arch safe :(
    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if parsed_args.no_deploy_image:
            deploy_kernel = None
            deploy_ramdisk = None
        else:
            deploy_kernel = 'file://{}/agent.kernel'.format(
                    constants.IRONIC_HTTP_BOOT_BIND_MOUNT
            )
            deploy_ramdisk = 'file://{}/agent.ramdisk'.format(
                    constants.IRONIC_HTTP_BOOT_BIND_MOUNT
            )

        credentials = [list(x.split(':', 1)) for x in parsed_args.credentials]
        kwargs = {}
        # Leave it up to the workflow to figure out the defaults
        if parsed_args.port:
            kwargs['ports'] = parsed_args.port

        nodes = baremetal.discover_and_enroll(
            self.app.client_manager,
            ip_addresses=parsed_args.ip_addresses,
            credentials=credentials,
            kernel_name=deploy_kernel,
            ramdisk_name=deploy_ramdisk,
            instance_boot_option=parsed_args.instance_boot_option,
            **kwargs
        )

        nodes_uuids = [node.uuid for node in nodes]

        if parsed_args.introspect:
            baremetal.introspect(self.app.client_manager,
                                 node_uuids=nodes_uuids,
                                 run_validations=parsed_args.run_validations,
                                 concurrency=parsed_args.concurrency
                                 )
        if parsed_args.provide:
            baremetal.provide(self.app.client_manager,
                              node_uuids=nodes_uuids
                              )


class ProvisionNode(command.Command):
    """Provision new nodes using Ironic."""

    log = logging.getLogger(__name__ + ".ProvisionNode")

    def get_parser(self, prog_name):
        parser = super(ProvisionNode, self).get_parser(prog_name)
        parser.add_argument('input',
                            metavar='<baremetal_deployment.yaml>',
                            help=_('Configuration file describing the '
                                   'baremetal deployment'))
        parser.add_argument('-o', '--output',
                            default='baremetal_environment.yaml',
                            help=_('The output environment file path'))
        parser.add_argument('--stack', dest='stack',
                            help=_('Name or ID of heat stack '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud'))

        parser.add_argument('--overcloud-ssh-user',
                            default='heat-admin',
                            help=_('User for SSH access to newly deployed '
                                   'nodes'))
        parser.add_argument('--overcloud-ssh-key',
                            default=None,
                            help=_('Key path for ssh access to'
                                   'overcloud nodes. When undefined the key'
                                   'will be autodetected.'))
        parser.add_argument('--concurrency', type=int,
                            default=20,
                            help=_('Maximum number of nodes to provision at '
                                   'once. (default=20)'))
        parser.add_argument('--timeout', type=int,
                            default=3600,
                            help=_('Number of seconds to wait for the node '
                                   'provision to complete. (default=3600)'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        with open(parsed_args.input, 'r') as fp:
            roles = yaml.safe_load(fp)

        key = self.get_key_pair(parsed_args)
        with open('{}.pub'.format(key), 'rt') as fp:
            ssh_key = fp.read()

        output = baremetal.deploy_roles(
            self.app.client_manager,
            plan=parsed_args.stack,
            roles=roles,
            ssh_keys=[ssh_key],
            ssh_user_name=parsed_args.overcloud_ssh_user,
            concurrency=parsed_args.concurrency,
            timeout=parsed_args.timeout
        )

        with open(parsed_args.output, 'w') as fp:
            yaml.safe_dump(output['environment'], fp, default_flow_style=False)

        print('Nodes deployed successfully, add %s to your deployment '
              'environment' % parsed_args.output)


class UnprovisionNode(command.Command):
    """Unprovisions nodes using Ironic."""

    log = logging.getLogger(__name__ + ".UnprovisionNode")

    def get_parser(self, prog_name):
        parser = super(UnprovisionNode, self).get_parser(prog_name)
        parser.add_argument('--stack', dest='stack',
                            help=_('Name or ID of heat stack '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud'))
        parser.add_argument('--all',
                            help=_('Unprovision every instance in the '
                                   'deployment'),
                            default=False,
                            action="store_true")
        parser.add_argument('-y', '--yes',
                            help=_('Skip yes/no prompt (assume yes)'),
                            default=False,
                            action="store_true")
        parser.add_argument('input',
                            metavar='<baremetal_deployment.yaml>',
                            help=_('Configuration file describing the '
                                   'baremetal deployment'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        with open(parsed_args.input, 'r') as fp:
            roles = yaml.safe_load(fp)

        nodes = []
        expanded = baremetal.expand_roles(
            self.app.client_manager,
            roles=roles,
            stackname=parsed_args.stack,
            provisioned=False)
        nodes.extend(expanded.get('instances', []))

        if parsed_args.all:
            expanded = baremetal.expand_roles(
                self.app.client_manager,
                roles=roles,
                stackname=parsed_args.stack,
                provisioned=True)
            nodes.extend(expanded.get('instances', []))

        if not nodes:
            print('No nodes to unprovision')
            return

        self._print_nodes(nodes)

        if not parsed_args.yes:
            confirm = oooutils.prompt_user_for_confirmation(
                message=_("Are you sure you want to unprovision these %s "
                          "nodes [y/N]? ") % parsed_args.stack,
                logger=self.log)
            if not confirm:
                raise oscexc.CommandError("Action not confirmed, exiting.")
        unprovision_role = self._build_unprovision_role(nodes)
        print('Unprovisioning %d nodes' % len(nodes))
        baremetal.undeploy_roles(
            self.app.client_manager,
            roles=unprovision_role,
            plan=parsed_args.stack)

        print('Unprovision complete')

    def _build_unprovision_role(self, nodes):
        # build a fake role called Unprovisioned which has an instance
        # entry for every node to be unprovisioned
        instances = [{'hostname': n['hostname'], 'provisioned': False}
                     for n in nodes if 'hostname' in n]
        return [{
            'name': 'Unprovisioned',
            'count': 0,
            'instances': instances
        }]

    def _print_nodes(self, nodes):
        TableArgs = collections.namedtuple(
            'TableArgs', 'print_empty max_width fit_width')
        args = TableArgs(print_empty=True, max_width=80, fit_width=True)
        nodes_data = [(i.get('hostname', ''),
                       i.get('name', '')) for i in nodes]

        formatter = table.TableFormatter()
        formatter.emit_list(
            column_names=['hostname', 'name'],
            data=nodes_data,
            stdout=sys.stdout,
            parsed_args=args
        )
