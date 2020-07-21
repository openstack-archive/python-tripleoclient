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
import datetime
import json
import logging
import os
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
        parser.add_argument(
            '--overcloud-ssh-port-timeout',
            help=_('Timeout for the ssh port to become active.'),
            type=int,
            default=constants.ENABLE_SSH_ADMIN_SSH_PORT_TIMEOUT
        )
        parser.add_argument('-y', '--yes',
                            help=_('Skip yes/no prompt (assume yes).'),
                            default=False,
                            action="store_true")
        return parser

    def _nodes_to_delete(self, parsed_args, roles):
        with oooutils.TempDirs() as tmp:
            unprovision_confirm = os.path.join(
                tmp, 'unprovision_confirm.json')

            oooutils.run_ansible_playbook(
                playbook='cli-overcloud-node-unprovision.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=oooutils.playbook_verbosity(self=self),
                extra_vars={
                    "stack_name": parsed_args.stack,
                    "baremetal_deployment": roles,
                    "prompt": True,
                    "unprovision_confirm": unprovision_confirm,
                }
            )
            with open(unprovision_confirm) as f:
                nodes = json.load(f)
        if not nodes:
            print('No nodes to unprovision')
            return None, None
        TableArgs = collections.namedtuple(
            'TableArgs', 'print_empty max_width fit_width')
        args = TableArgs(print_empty=True, max_width=-1, fit_width=True)
        nodes_data = [(i.get('hostname', ''),
                       i.get('name', ''),
                       i.get('id', '')) for i in nodes]

        node_hostnames = [i['hostname'] for i in nodes if 'hostname' in i]

        formatter = table.TableFormatter()
        output = six.StringIO()
        formatter.emit_list(
            column_names=['hostname', 'name', 'id'],
            data=nodes_data,
            stdout=output,
            parsed_args=args
        )
        return output.getvalue(), node_hostnames

    def _check_skiplist_exists(self, env):
        skiplist = env.get('parameter_defaults',
                           {}).get('DeploymentServerBlacklist')
        if skiplist:
            self.log.warning(_('[WARNING] DeploymentServerBlacklist is '
                               'ignored when executing scale down actions. If '
                               'the node(s) being removed should *NOT* have '
                               'any actions executed on them, please shut '
                               'them off prior to their removal.'))

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        if parsed_args.baremetal_deployment:
            with open(parsed_args.baremetal_deployment, 'r') as fp:
                roles = yaml.safe_load(fp)

            nodes_text, nodes = self._nodes_to_delete(parsed_args, roles)
            if nodes_text:
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

        self._check_skiplist_exists(stack.environment())

        scale.scale_down(
            log=self.log,
            clients=clients,
            stack=stack,
            nodes=nodes,
            connection_timeout=parsed_args.overcloud_ssh_port_timeout,
            timeout=parsed_args.timeout,
            verbosity=oooutils.playbook_verbosity(self=self)
        )

        if parsed_args.baremetal_deployment:
            with oooutils.TempDirs() as tmp:
                oooutils.run_ansible_playbook(
                    playbook='cli-overcloud-node-unprovision.yaml',
                    inventory='localhost,',
                    workdir=tmp,
                    playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                    verbosity=oooutils.playbook_verbosity(self=self),
                    extra_vars={
                        "stack_name": parsed_args.stack,
                        "baremetal_deployment": roles,
                        "prompt": False,
                    }
                )


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
            baremetal.clean_nodes(
                node_uuids=parsed_args.node_uuids,
                verbosity=oooutils.playbook_verbosity(self=self)
            )
        else:
            baremetal.clean_manageable_nodes(
                clients=self.app.client_manager,
                verbosity=oooutils.playbook_verbosity(self=self)
            )

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
        parser.add_argument('--node-timeout', type=int,
                            default=1200,
                            help=_('Maximum timeout for node introspection.'))
        parser.add_argument('--max-retries', type=int,
                            default=1,
                            help=_('Maximum introspection retries.'))
        parser.add_argument('--retry-timeout', type=int,
                            default=120,
                            help=_('Maximum timeout between introspection'
                                   'retries'))
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
            baremetal.introspect(
                self.app.client_manager,
                node_uuids=nodes_uuids,
                run_validations=parsed_args.run_validations,
                concurrency=parsed_args.concurrency,
                node_timeout=parsed_args.node_timeout,
                max_retries=parsed_args.max_retries,
                retry_timeout=parsed_args.retry_timeout,
            )

        if parsed_args.provide:
            baremetal.provide(self.app.client_manager,
                              node_uuids=nodes_uuids
                              )


class ExtractProvisionedNode(command.Command):

    log = logging.getLogger(__name__ + ".ExtractProvisionedNode")

    def _setup_clients(self):
        self.clients = self.app.client_manager
        self.orchestration_client = self.clients.orchestration
        self.baremetal_client = self.clients.baremetal

    def get_parser(self, prog_name):
        parser = super(ExtractProvisionedNode, self).get_parser(prog_name)
        parser.add_argument('--stack', dest='stack',
                            help=_('Name or ID of heat stack '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud'))
        parser.add_argument('-o', '--output',
                            metavar='<baremetal_deployment.yaml>',
                            help=_('The output file path describing the '
                                   'baremetal deployment'))
        parser.add_argument('-y', '--yes', default=False, action='store_true',
                            help=_('Skip yes/no prompt for existing files '
                                   '(assume yes).'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        self._setup_clients()
        stack = oooutils.get_stack(self.orchestration_client,
                                   parsed_args.stack)
        host_vars = oooutils.get_stack_output_item(
            stack, 'AnsibleHostVarsMap') or {}
        parameters = stack.to_dict().get('parameters', {})

        # list all baremetal nodes and map hostname to node name
        node_details = self.baremetal_client.node.list(detail=True)
        hostname_node_map = {}
        for node in node_details:
            hostname = node.instance_info.get('display_name')
            if hostname and node.name:
                hostname_node_map[hostname] = node.name

        role_data = six.StringIO()
        role_data.write('# Generated with the following on %s\n#\n' %
                        datetime.datetime.now().isoformat())
        role_data.write('#   openstack %s\n#\n\n' %
                        ' '.join(self.app.command_options))
        for role, entries in host_vars.items():
            role_count = len(entries)

            # skip zero count roles
            if not role_count:
                continue

            role_data.write('- name: %s\n' % role)
            role_data.write('  count: %s\n' % role_count)

            hostname_format = parameters.get('%sHostnameFormat' % role)
            if hostname_format:
                role_data.write('  hostname_format: "%s"\n' % hostname_format)

            role_data.write('  instances:\n')

            for entry in sorted(entries):
                role_data.write('  - hostname: %s\n' % entry)
                if entry in hostname_node_map:
                    role_data.write('    name: %s\n' %
                                    hostname_node_map[entry])

        if parsed_args.output:
            if (os.path.exists(parsed_args.output)
                    and not parsed_args.yes and sys.stdin.isatty()):
                prompt_response = six.moves.input(
                    ('Overwrite existing file %s [y/N]?' % parsed_args.output)
                ).lower()
                if not prompt_response.startswith('y'):
                    raise oscexc.CommandError(
                        "Will not overwrite existing file:"
                        " %s" % parsed_args.output)
            with open(parsed_args.output, 'w+') as fp:
                fp.write(role_data.getvalue())
        self.app.stdout.write(role_data.getvalue())
