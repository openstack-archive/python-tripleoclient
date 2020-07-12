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
import shutil
from six.moves.urllib import request

from osc_lib.i18n import _
from oslo_concurrency import processutils

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils
from tripleoclient.workflows import deployment


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

    def create_config_dir(self, config_dir, preserve_config_dir=True):
        # Create config directory
        if os.path.exists(config_dir) and preserve_config_dir is False:
            try:
                self.log.info("Directory %s already exists, removing"
                              % config_dir)
                shutil.rmtree(config_dir)
            except OSError as e:
                message = 'Failed to remove: %s, error: %s' % (config_dir,
                                                               str(e))
                raise OSError(message)

        utils.makedirs(config_dir)

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        name = parsed_args.name
        config_dir = parsed_args.config_dir

        work_dir = os.path.join(config_dir, name)
        config_type = parsed_args.config_type
        preserve_config_dir = parsed_args.preserve_config_dir
        self.create_config_dir(work_dir, preserve_config_dir)

        # Get config
        print("Starting config-download export...")
        tempurl = deployment.config_download_export(
            self.app.client_manager,
            plan=name,
            config_type=config_type
        )
        print("Finished config-download export.")
        self.log.debug("config-download tempurl: %s" % tempurl)
        f = request.urlopen(tempurl)
        tarball_contents = f.read()
        f.close()
        tarball_name = "%s-config.tar.gz" % name
        tarball_path = os.path.join(work_dir, tarball_name)

        with open(tarball_path, 'wb') as f:
            f.write(tarball_contents)

        print("Extracting config-download...")
        cmd = ['/usr/bin/tar', '-C', work_dir, '-xf', tarball_path]
        processutils.execute(*cmd)

        print("The TripleO configuration has been successfully generated "
              "into: {0}".format(work_dir))
