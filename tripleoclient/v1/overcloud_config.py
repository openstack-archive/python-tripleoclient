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

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils


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
            default=os.path.join(
                constants.CLOUD_HOME_DIR,
                'tripleo-config'
            ),
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
        parser.add_argument(
            '--no-preserve-config',
            dest='preserve_config_dir',
            action='store_false',
            default=True,
            help=('If specified, will delete and recreate the --config-dir '
                  'if it already exists. Default is to use the existing dir '
                  'location and overwrite files. Files in --config-dir not '
                  'from the stack will be preserved by default.')
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        name = parsed_args.name
        config_dir = os.path.abspath(parsed_args.config_dir)
        config_type = parsed_args.config_type
        preserve_config_dir = parsed_args.preserve_config_dir
        extra_vars = {'plan': name,
                      'config_dir': config_dir,
                      'preserve_config': preserve_config_dir}
        if config_type:
            extra_vars['config_type'] = config_type

        with utils.TempDirs() as tmp:
            utils.run_ansible_playbook(
                playbook='cli-config-download-export.yaml',
                inventory='localhost,',
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=utils.playbook_verbosity(self=self),
                extra_vars=extra_vars)

        print("The TripleO configuration has been successfully generated "
              "into: {0}".format(config_dir))
