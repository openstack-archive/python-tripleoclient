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
import logging
import os.path
import yaml

from osc_lib.i18n import _
from osc_lib import utils

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import export


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
        parser.add_argument('--config-download-dir',
                            action='store',
                            help=_('Directory to search for config-download '
                                   'export data. Defaults to '
                                   '$HOME/config-download'))
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

        data = export.export_passwords(swift_client, control_plane_stack)

        stack_to_export = control_plane_stack
        should_filter = True
        if cell_stack:
            stack_to_export = cell_stack
            should_filter = False

        if not parsed_args.config_download_dir:
            download_dir = constants.DEFAULT_WORK_DIR
        else:
            download_dir = parsed_args.config_download_dir

        config_download_dir = os.path.join(download_dir, stack_to_export)

        data.update(export.export_stack(
            clients.orchestration, stack_to_export, should_filter,
            config_download_dir))
        data = dict(parameter_defaults=data)

        # write the exported data
        with open(output_file, 'w') as f:
            yaml.safe_dump(data, f, default_flow_style=False)

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
          For more details check https://docs.openstack.org/
          project-deploy-guide/tripleo-docs/latest/features/deploy_cellv2.html
          """.format(output_file=output_file)

        print(msg)
