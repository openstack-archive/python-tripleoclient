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

from __future__ import print_function

from datetime import datetime
import json
import logging
import os.path
import sys
import yaml

from osc_lib.i18n import _
from osc_lib import utils

from tripleoclient import command
from tripleoclient import exceptions
from tripleoclient import utils as oooutils

MISTRAL_VAR = os.environ.get('MISTRAL_VAR',
                             "/var/lib/mistral/")


class ExportCell(command.Command):
    """Export cell information used as import of another cell"""

    log = logging.getLogger(__name__ + ".ExportCell")
    now = datetime.now().strftime('%Y%m%d%H%M%S')

    def get_parser(self, prog_name):
        parser = super(ExportCell, self).get_parser(prog_name)
        parser.add_argument('name', metavar='<cell name>',
                            help=_('Name of the stack used for the additional '
                                   'cell.'))
        parser.add_argument('--control-plane-stack',
                            dest='control_plane_stack',
                            metavar='<control plane stack>',
                            help=_('Name of the environment main Heat stack '
                                   'to export information from. '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud'))
        parser.add_argument('--cell-stack', '-e', metavar='<cell stack>',
                            help=_('Name of the controller cell Heat stack to '
                                   'export information from. Used in case of: '
                                   'control plane stack -> cell controller '
                                   'stack -> multiple compute stacks'))
        parser.add_argument('--output-file', '-o', metavar='<output file>',
                            help=_('Name of the output file for the cell data '
                                   'export. It will default to "<name>.yaml"'))
        parser.add_argument('--force-overwrite', '-f', action='store_true',
                            default=False,
                            help=_('Overwrite output file if it exists.'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        control_plane_stack = parsed_args.control_plane_stack
        cell_stack = parsed_args.cell_stack
        cell_name = parsed_args.name
        output_file = parsed_args.output_file or \
            '%s-cell-input.yaml' % cell_name

        self.log.info('Running at %s with parameters %s',
                      self.now,
                      parsed_args)

        if os.path.exists(output_file) and not parsed_args.force_overwrite:
            raise exceptions.CellExportError(
                "File '%s' already exists, not exporting." % output_file)

        # prepare clients to access the environment
        clients = self.app.client_manager
        swift_client = clients.tripleoclient.object_store

        # data to export
        # parameter: Parameter to be exported
        # file:   IF file specified it is taken as source instead of heat
        #         output.File is relative to MISTRAL_VAR/stack_to_export.
        # filter: in case only specific settings should be
        #         exported from parameter data.
        export_data = {
            "EndpointMap": {
                "parameter": "EndpointMapOverride",
            },
            "HostsEntry": {
                "parameter": "ExtraHostFileEntries",
            },
            "GlobalConfig": {
                "parameter": "GlobalConfigExtraMapData",
            },
            "AllNodesConfig": {
                "file": "/group_vars/overcloud.json",
                "parameter": "GlobalConfigExtraMapData",
                "filter": ["oslo_messaging_notify_short_bootstrap_node_name",
                           "oslo_messaging_notify_node_names",
                           "oslo_messaging_rpc_node_names",
                           "memcached_node_ips",
                           "ovn_dbs_vip",
                           "redis_vip"]},
        }

        # export the data from swift and heat
        data_real = {}

        # Export the passwords from swift
        obj = 'plan-environment.yaml'
        container = control_plane_stack
        try:
            resp_headers, content = swift_client.get_object(container, obj)
        except Exception as e:
            self.log.error("An error happened while exporting the password "
                           "file from swift: %s", str(e))
            sys.exit(1)

        data_real = {'parameter_defaults': yaml.load(content)["passwords"]}

        stack_to_export = control_plane_stack
        if cell_stack:
            stack_to_export = cell_stack

        stack = oooutils.get_stack(clients.orchestration, stack_to_export)

        for export_key, export_param in export_data.items():
            data = None
            if "file" in export_param:
                # get stack data
                file = MISTRAL_VAR + stack_to_export + export_param["file"]
                with open(file, 'r') as ff:
                    try:
                        data = json.load(ff)
                    except Exception:
                        self.log.error(
                            _('Could not read file %s') % file)
            else:
                # get stack data
                data = oooutils.get_stack_output_item(stack,
                                                      export_key)

            param = export_param["parameter"]
            if data:
                # do we just want a subset of entries?
                # When we export information from a cell controller stack
                # we don't want to filter.
                if "filter" in export_param and not cell_stack:
                    for x in export_param["filter"]:
                        element = {x: data[x]}
                        if param not in data_real["parameter_defaults"]:
                            data_real["parameter_defaults"][param] = element
                        else:
                            data_real["parameter_defaults"][param].update(
                                element)
                else:
                    if param not in data_real["parameter_defaults"]:
                        data_real["parameter_defaults"][param] = data
                    else:
                        data_real["parameter_defaults"][param].update(data)
            else:
                raise exceptions.CellExportError(
                    "No data returned to export %s from." % param)

        # write the exported data
        with open(output_file, 'w') as f:
            yaml.safe_dump(data_real, f, default_flow_style=False)

        print("Cell input information exported to %s." % output_file)

        msg = """ \n\n
          Next steps:
          ===========\n
          * Create roles file for cell stack, e.g.:
            openstack overcloud roles generate --roles-path \\
            /usr/share/openstack-tripleo-heat-templates/roles \\
            -o cell_roles_data.yaml Compute CellController
          * Create new flavor used to tag the cell controller
          * Tag cell controller nodes into the new flavor
          * Create cell parameter file as explained in bellow doc link
          * Deploy the cell and make sure to add the following information
           to the deploy command:
            - additional environment files used for overcloud stack
            - --stack <cellname>
            - cell role file created
            - the exported cell input information file {output_file}
            - other specific parameter files for the cell\n
          For more details check https://docs.openstack.org/tripleo-docs/
          latest/install/advanced_deployment/deploy_cellv2.html#
          deploy-the-cell""".format(output_file=output_file)

        print(msg)
