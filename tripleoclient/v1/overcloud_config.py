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

import logging
import os

from osc_lib.i18n import _
from tripleo_common.utils import config as ooo_config

from tripleoclient import command


class DownloadConfig(command.Command):
    """Download Overcloud Config"""

    log = logging.getLogger(__name__ + ".DownloadConfig")

    def get_parser(self, prog_name):
        parser = super(DownloadConfig, self).get_parser(prog_name)
        parser.add_argument(
            '--name',
            dest='name',
            default='overcloud',
            help=_('The name of the plan, which is used for the object '
                   'storage container, workflow environment and orchestration '
                   'stack names.'),
        )
        parser.add_argument(
            '--config-dir',
            dest='config_dir',
            default=os.path.expanduser("~"),
            help=_('The directory where the configuration files will be '
                   'pushed'),
        )
        parser.add_argument(
            '--config-type',
            dest='config_type',
            type=list,
            default=None,
            help=_('Type of object config to be extract from the deployment, '
                   'defaults to all keys available'),
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        # Get clients
        clients = self.app.client_manager

        name = parsed_args.name
        config_dir = parsed_args.config_dir
        config_type = parsed_args.config_type
        # Get config
        config = ooo_config.Config(clients.orchestration)
        config_path = config.download_config(name, config_dir, config_type)
        print("The TripleO configuration has been successfully generated "
              "into: {0}".format(config_path))
