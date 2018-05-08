#   Copyright 2018 Red Hat, Inc.
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

from oslo_config import cfg
from tripleoclient import constants


class BaseConfig(object):

    def sort_opts(self, opts):
        """Sort oslo config options by name

        :param opts: list of olo cfg opts
        :return list - sorted by name
        """
        def sort_cfg(cfg):
            return cfg.name
        return sorted(opts, key=sort_cfg)

    def get_base_opts(self):
        _opts = [
            # TODO(aschultz): rename undercloud_output_dir
            cfg.StrOpt('output_dir',
                       default=constants.UNDERCLOUD_OUTPUT_DIR,
                       help=(
                           'Directory to output state, processed heat '
                           'templates, ansible deployment files.'),
                       ),
            cfg.BoolOpt('cleanup',
                        default=True,
                        help=('Cleanup temporary files. Setting this to '
                              'False will leave the temporary files used '
                              'during deployment in place after the command '
                              'is run. This is useful for debugging the '
                              'generated files or if errors occur.'),
                        ),
        ]
        return self.sort_opts(_opts)
