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
import tempfile
import yaml

from osc_lib.command import command
from osc_lib.i18n import _

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
            default=os.path.expanduser("~"),
            help=_('The directory where the configuration files will be '
                   'pushed'),
        )
        parser.add_argument(
            '--config-type',
            dest='config_type',
            type=list,
            default=['config_settings', 'global_config_settings',
                     'logging_sources', 'monitoring_subscriptions',
                     'service_config_settings', 'service_metadata_settings',
                     'service_names', 'step_config', 'upgrade_batch_tasks',
                     'upgrade_tasks'],
            help=_('Type of object config to be extract from the deployment'),
        )
        return parser

    def _convert_playbook(self, tasks, role):
        playbook = []
        sorted_tasks = sorted(tasks, key=lambda x: x.get('tags', None))
        playbook.append({'name': '%s playbook' % role,
                         'hosts': role,
                         'tasks': sorted_tasks})
        return playbook

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        name = parsed_args.name
        configs = parsed_args.config_type
        config_dir = parsed_args.config_dir
        if not os.path.exists(config_dir):
            try:
                os.mkdir(config_dir)
            except OSError as e:
                message = 'Failed to create: %s, error: %s' % (config_dir,
                                                               str(e))
                raise OSError(message)
        stack = utils.get_stack(clients.orchestration, name)
        tmp_path = tempfile.mkdtemp(prefix='tripleo-',
                                    suffix='-config',
                                    dir=config_dir)
        self.log.info("Generating configuration under the directory: "
                      "%s" % tmp_path)
        role_data = utils.get_role_data(stack)
        for role in role_data:
            for config in configs:
                if 'step_config' in config:
                        with open('%s/%s-%s.pp' % (tmp_path,
                                                   config,
                                                   role), 'w') as step_config:
                            step_config.write('\n'.join(step for step in
                                                        role_data[role][config]
                                                        if step is not None))
                else:
                    if 'upgrade_tasks' in config:
                        data = self._convert_playbook(role_data[role][config],
                                                      role)
                    else:
                        try:
                            data = role_data[role][config]
                        except KeyError as e:
                            message = 'Invalide key: %s, error: %s' % (config,
                                                                       str(e))
                            raise KeyError(message)
                    with open('%s/%s-%s.yaml' % (tmp_path,
                                                 config,
                                                 role), 'w') as conf_file:
                        yaml.safe_dump(data,
                                       conf_file,
                                       default_flow_style=False)
        print("The TripleO configuration has been successfully generated "
              "into: {0}".format(tmp_path))
