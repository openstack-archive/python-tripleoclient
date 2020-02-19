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

import logging

from osc_lib.i18n import _

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
from tripleoclient.v1.overcloud_node import ImportNode  # noqa
from tripleoclient.v1.overcloud_node import ProvideNode  # noqa
from tripleoclient.v1.overcloud_node import ProvisionNode  # noqa
from tripleoclient.v1.overcloud_node import UnprovisionNode  # noqa


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
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        extra_vars = {
            "node_uuids": parsed_args.node_uuids,
            "run_validations": parsed_args.run_validations,
            "concurrency": parsed_args.concurrency,
            "all_manageable": parsed_args.all_manageable,
        }

        with oooutils.TempDirs() as tmp:
            oooutils.run_ansible_playbook(
                playbook='cli-baremetal-introspect.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                extra_vars=extra_vars
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
                baremetal.provide_manageable_nodes(self.app.client_manager)
