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
import collections
import json
import logging
import os
import sys

from cliff.formatters import table
from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from osc_lib import utils
import yaml

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils
from tripleoclient.workflows import baremetal

# NOTE(cloudnull): V1 imports, These classes will be removed as they're
#                  converted from mistral to ansible.
from tripleoclient.v1.overcloud_node import CleanNode  # noqa
from tripleoclient.v1.overcloud_node import ConfigureNode  # noqa
from tripleoclient.v1.overcloud_node import DeleteNode  # noqa
from tripleoclient.v1.overcloud_node import DiscoverNode  # noqa
from tripleoclient.v1.overcloud_node import ProvideNode  # noqa


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
        parser.add_argument('--run-validations', action='store_true',
                            default=False,
                            help=_('Run the pre-deployment validations. These'
                                   ' external validations are from the'
                                   ' TripleO Validations project.'))
        parser.add_argument('--validate-only', action='store_true',
                            default=False,
                            help=_('Validate the env_file and then exit '
                                   'without actually importing the nodes.'))
        parser.add_argument('--provide',
                            action='store_true',
                            help=_('Provide (make available) the nodes'))
        parser.add_argument('--no-deploy-image', action='store_true',
                            help=_('Skip setting the deploy kernel and '
                                   'ramdisk.'))
        parser.add_argument('--instance-boot-option',
                            choices=['local', 'netboot'], default=None,
                            help=_('Whether to set instances for booting from'
                                   ' local hard drive (local) or network '
                                   ' (netboot).'))
        parser.add_argument("--http-boot",
                            default=os.environ.get(
                                'HTTP_BOOT',
                                constants.IRONIC_HTTP_BOOT_BIND_MOUNT),
                            help=_("Root directory for the "
                                   " ironic-python-agent image"))
        parser.add_argument('--concurrency', type=int,
                            default=20,
                            help=_('Maximum number of nodes to introspect at '
                                   'once.'))
        parser.add_argument('env_file', type=argparse.FileType('r'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        nodes_config = oooutils.parse_env_file(parsed_args.env_file)
        parsed_args.env_file.close()

        if parsed_args.validate_only:
            return baremetal.validate_nodes(self.app.client_manager,
                                            nodes_json=nodes_config)

        # Look for *specific* deploy images and update the node data if
        # one is found.
        if not parsed_args.no_deploy_image:
            oooutils.update_nodes_deploy_data(nodes_config,
                                              http_boot=parsed_args.http_boot)
        nodes = baremetal.register_or_update(
            self.app.client_manager,
            nodes_json=nodes_config,
            instance_boot_option=parsed_args.instance_boot_option
        )

        nodes_uuids = [node.uuid for node in nodes]

        if parsed_args.introspect:
            extra_vars = {
                "node_uuids": nodes_uuids,
                "run_validations": parsed_args.run_validations,
                "concurrency": parsed_args.concurrency,
            }

            with oooutils.TempDirs() as tmp:
                oooutils.run_ansible_playbook(
                    playbook='cli-baremetal-introspect.yaml',
                    inventory='localhost,',
                    workdir=tmp,
                    playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                    verbosity=oooutils.playbook_verbosity(self=self),
                    extra_vars=extra_vars
                )

        if parsed_args.provide:
            baremetal.provide(
                verbosity=oooutils.playbook_verbosity(self=self),
                node_uuids=nodes_uuids
            )


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
        parser.add_argument('--run-validations', action='store_true',
                            default=False,
                            help=_('Run the pre-deployment validations. These '
                                   'external validations are from the TripleO '
                                   'Validations project.'))
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

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if parsed_args.all_manageable:
            baremetal.introspect_manageable_nodes(
                self.app.client_manager,
                run_validations=parsed_args.run_validations,
                concurrency=parsed_args.concurrency,
                node_timeout=parsed_args.node_timeout,
                max_retries=parsed_args.max_retries,
                retry_timeout=parsed_args.retry_timeout,
                verbosity=oooutils.playbook_verbosity(self=self)
            )
        else:
            baremetal.introspect(
                self.app.client_manager,
                node_uuids=parsed_args.node_uuids,
                run_validations=parsed_args.run_validations,
                concurrency=parsed_args.concurrency,
                node_timeout=parsed_args.node_timeout,
                max_retries=parsed_args.max_retries,
                retry_timeout=parsed_args.retry_timeout,
                verbosity=oooutils.playbook_verbosity(self=self)
            )

        # NOTE(cloudnull): This is using the old provide function, in a future
        #                  release this may be ported to a standalone playbook
        if parsed_args.provide:
            if parsed_args.node_uuids:
                baremetal.provide(
                    self.app.client_manager,
                    node_uuids=parsed_args.node_uuids,
                )
            else:
                baremetal.provide_manageable_nodes(
                    clients=self.app.client_manager,
                    verbosity=oooutils.playbook_verbosity(self=self)
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

        output_path = os.path.abspath(parsed_args.output)

        extra_vars = {
            "stack_name": parsed_args.stack,
            "baremetal_deployment": roles,
            "baremetal_deployed_path": output_path,
            "ssh_public_keys": ssh_key,
            "ssh_user_name": parsed_args.overcloud_ssh_user,
            "node_timeout": parsed_args.timeout,
            "concurrency": parsed_args.concurrency
        }

        with oooutils.TempDirs() as tmp:
            oooutils.run_ansible_playbook(
                playbook='cli-overcloud-node-provision.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=oooutils.playbook_verbosity(self=self),
                extra_vars=extra_vars,
            )

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

        with oooutils.TempDirs() as tmp:
            unprovision_confirm = os.path.join(tmp, 'unprovision_confirm.json')

            if not parsed_args.yes:
                oooutils.run_ansible_playbook(
                    playbook='cli-overcloud-node-unprovision.yaml',
                    inventory='localhost,',
                    workdir=tmp,
                    playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                    verbosity=oooutils.playbook_verbosity(self=self),
                    extra_vars={
                        "stack_name": parsed_args.stack,
                        "baremetal_deployment": roles,
                        "all": parsed_args.all,
                        "prompt": True,
                        "unprovision_confirm": unprovision_confirm
                    }
                )
                with open(unprovision_confirm) as f:
                    to_unprovision = json.load(f)
                    if not to_unprovision:
                        print('Nothing to unprovision, exiting')
                        return
                    self._print_nodes(to_unprovision)

                confirm = oooutils.prompt_user_for_confirmation(
                    message=_("Are you sure you want to unprovision these %s "
                              "nodes [y/N]? ") % parsed_args.stack,
                    logger=self.log)
                if not confirm:
                    raise oscexc.CommandError("Action not confirmed, exiting.")

            oooutils.run_ansible_playbook(
                playbook='cli-overcloud-node-unprovision.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=oooutils.playbook_verbosity(self=self),
                extra_vars={
                    "stack_name": parsed_args.stack,
                    "baremetal_deployment": roles,
                    "all": parsed_args.all,
                    "prompt": False,
                }
            )

        print('Unprovision complete')

    def _print_nodes(self, nodes):
        TableArgs = collections.namedtuple(
            'TableArgs', 'print_empty max_width fit_width')
        args = TableArgs(print_empty=True, max_width=-1, fit_width=True)
        nodes_data = [(i.get('hostname', ''),
                       i.get('name', ''),
                       i.get('id', '')) for i in nodes]

        sys.stdout.write('\n')
        formatter = table.TableFormatter()
        formatter.emit_list(
            column_names=['hostname', 'name', 'id'],
            data=nodes_data,
            stdout=sys.stdout,
            parsed_args=args
        )
