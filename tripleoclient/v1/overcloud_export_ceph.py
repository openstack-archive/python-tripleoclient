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

from datetime import datetime
import logging
import os.path
import yaml

from osc_lib.i18n import _
from osc_lib import utils

from tripleoclient import command
from tripleoclient import export


class ExportOvercloudCeph(command.Command):
    """Export Ceph information used as import of another stack

    Export Ceph information from one or more stacks to be used
    as input of another stack. Creates a valid YAML file with
    the CephExternalMultiConfig parameter populated.
    """

    log = logging.getLogger(__name__ + ".ExportOvercloudCeph")
    now = datetime.now().strftime('%Y%m%d%H%M%S')

    def get_parser(self, prog_name):
        parser = super(ExportOvercloudCeph, self).get_parser(prog_name)
        parser.add_argument('--stack',
                            dest='stack',
                            metavar='<stack>',
                            help=_('Name of the overcloud stack(s) '
                                   'to export Ceph information from. '
                                   'If a comma delimited list of stacks is '
                                   'passed, Ceph information for all stacks '
                                   'will be exported into a single file. '
                                   '(default=Env: OVERCLOUD_STACK_NAME) '),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud'))
        parser.add_argument('--cephx-key-client-name', '-k',
                            dest='cephx',
                            metavar='<cephx>',
                            help=_('Name of the cephx client key to export. '
                                   '(default=openstack)'),
                            default='openstack')
        parser.add_argument('--output-file', '-o', metavar='<output file>',
                            help=_('Name of the output file for the Ceph '
                                   'data export. Defaults to '
                                   '"ceph-export-<STACK>.yaml" if one '
                                   'stack is provided. Defaults to '
                                   '"ceph-export-<N>-stacks.yaml" '
                                   'if N stacks are provided.'))
        parser.add_argument('--force-overwrite', '-f', action='store_true',
                            default=False,
                            help=_('Overwrite output file if it exists.'))
        parser.add_argument('--config-download-dir',
                            action='store',
                            help=_('Directory to search for config-download '
                                   'export data. Defaults to '
                                   '$HOME/config-download'))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        stacks = parsed_args.stack.split(',')
        stack_count = len(stacks)
        if stack_count == 1:
            name = parsed_args.stack
        else:
            name = str(stack_count) + '-stacks'
        output_file = parsed_args.output_file or \
            'ceph-export-%s.yaml' % name

        self.log.info('Running at %s with parameters %s',
                      self.now,
                      parsed_args)

        if os.path.exists(output_file) and not parsed_args.force_overwrite:
            raise Exception(
                "File '%s' already exists, not exporting." % output_file)

        if not parsed_args.config_download_dir:
            config_download_dir = os.path.join(os.environ.get('HOME'),
                                               'config-download')
        else:
            config_download_dir = parsed_args.config_download_dir

        # extract ceph data for each stack into the cephs list
        cephs = []
        for stack in stacks:
            self.log.info('Exporting Ceph data from stack %s at %s',
                          stack, self.now)
            cephs.append(export.export_ceph(stack,
                                            parsed_args.cephx,
                                            config_download_dir))
        data = {}
        data['parameter_defaults'] = {}
        data['parameter_defaults']['CephExternalMultiConfig'] = cephs
        # write the exported data
        with open(output_file, 'w') as f:
            yaml.safe_dump(data, f, default_flow_style=False)

        print("Ceph information from %s stack(s) exported to %s." %
              (len(cephs), output_file))
