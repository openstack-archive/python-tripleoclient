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

from tripleoclient import command
from tripleoclient import export
from tripleoclient import utils


class ExportOvercloud(command.Command):
    """Export stack information used as import of another stack"""

    log = logging.getLogger(__name__ + ".ExportOvercloud")
    now = datetime.now().strftime('%Y%m%d%H%M%S')

    def get_parser(self, prog_name):
        parser = super(ExportOvercloud, self).get_parser(prog_name)
        parser.add_argument('--stack',
                            dest='stack',
                            metavar='<stack>',
                            help=_('Name of the environment main Heat stack '
                                   'to export information from. '
                                   '(default=overcloud)'),
                            default='overcloud')
        parser.add_argument('--output-file', '-o', metavar='<output file>',
                            help=_('Name of the output file for the stack '
                                   'data export. It will default to '
                                   '"<name>.yaml"'))
        parser.add_argument('--force-overwrite', '-f', action='store_true',
                            default=False,
                            help=_('Overwrite output file if it exists.'))
        parser.add_argument(
            '--working-dir',
            action='store',
            help=_('The working directory for the deployment where all '
                   'input, output, and generated files are stored.\n'
                   'Defaults to "$HOME/overcloud-deploy/<stack>"'))
        parser.add_argument('--config-download-dir',
                            action='store',
                            help=_('Directory to search for config-download '
                                   'export data. Defaults to $HOME/'
                                   'overcloud-deploy/<stack>/config-download'))
        parser.add_argument('--no-password-excludes',
                            action='store_true',
                            dest='no_password_excludes',
                            help=_('Don''t exclude certain passwords from '
                                   'the password export. Defaults to False '
                                   'in that some passwords will be excluded '
                                   'that are not typically necessary.'))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        stack = parsed_args.stack
        self.log.info('Running at %s with parameters %s',
                      self.now,
                      parsed_args)

        if not parsed_args.working_dir:
            working_dir = utils.get_default_working_dir(stack)
        else:
            working_dir = parsed_args.working_dir

        if not parsed_args.config_download_dir:
            config_download_dir = os.path.join(os.environ.get('HOME'),
                                               "overcloud-deploy",
                                               parsed_args.stack,
                                               'config-download')
        else:
            config_download_dir = parsed_args.config_download_dir

        output_file = parsed_args.output_file or os.path.join(
            working_dir,
            '{}-export.yaml'.format(
                parsed_args.stack
            )
        )
        export_file_path = os.path.abspath(
            os.path.expanduser(
                output_file
            )
        )
        if (os.path.exists(export_file_path) and
                not parsed_args.force_overwrite):
            raise Exception(
                "File '%s' already exists, not exporting." % export_file_path)

        data = export.export_overcloud(
            working_dir, stack, excludes=not parsed_args.no_password_excludes,
            should_filter=False, config_download_dir=config_download_dir)
        # write the exported data
        with open(export_file_path, 'w') as f:
            yaml.safe_dump(data, f, default_flow_style=False)

        print("Stack information exported to %s." % export_file_path)
