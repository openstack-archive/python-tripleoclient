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
import re
import six
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
            help=_('Type of object config to be extract from the deployment, '
                   'defaults to all keys available'),
        )
        return parser

    def _step_tags_to_when(self, sorted_tasks):
        for task in sorted_tasks:
            tag = task.get('tags', '')
            match = re.search('step([0-9]+)', tag)
            if match:
                step = match.group(1)
                whenline = task.get('when', None)
                if whenline:  # how about list of when conditionals
                    when_exists = re.search('step == [0-9]', whenline)
                    if when_exists:  # skip if there is an existing 'step == N'
                        continue
                    task['when'] = "(%s) and (step == %s)" % (whenline, step)
                else:
                    task.update({"when": "step == %s" % step})

    def _write_playbook_get_tasks(self, tasks, role, filepath):
        playbook = []
        sorted_tasks = sorted(tasks, key=lambda x: x.get('tags', None))
        self._step_tags_to_when(sorted_tasks)
        playbook.append({'name': '%s playbook' % role,
                         'hosts': role,
                         'tasks': sorted_tasks})
        with os.fdopen(os.open(filepath, os.O_WRONLY | os.O_CREAT, 0o600),
                       'w') as conf_file:
            yaml.safe_dump(playbook, conf_file, default_flow_style=False)
        return sorted_tasks

    def _mkdir(self, dirname):
        if not os.path.exists(dirname):
            try:
                os.mkdir(dirname, 0o700)
            except OSError as e:
                message = 'Failed to create: %s, error: %s' % (dirname,
                                                               str(e))
                raise OSError(message)

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        name = parsed_args.name
        config_dir = parsed_args.config_dir
        self._mkdir(config_dir)
        stack = utils.get_stack(clients.orchestration, name)
        tmp_path = tempfile.mkdtemp(prefix='tripleo-',
                                    suffix='-config',
                                    dir=config_dir)
        self.log.info("Generating configuration under the directory: "
                      "%s" % tmp_path)
        role_data = utils.get_role_data(stack)
        for role_name, role in six.iteritems(role_data):
            role_path = os.path.join(tmp_path, role_name)
            self._mkdir(role_path)
            for config in parsed_args.config_type or role.keys():
                if config == 'step_config':
                    filepath = os.path.join(role_path, 'step_config.pp')
                    with os.fdopen(os.open(filepath,
                                           os.O_WRONLY | os.O_CREAT, 0o600),
                                   'w') as step_config:
                        step_config.write('\n'.join(step for step in
                                                    role[config]
                                                    if step is not None))
                else:
                    if 'upgrade_tasks' in config:
                        filepath = os.path.join(role_path, '%s_playbook.yaml' %
                                                config)
                        data = self._write_playbook_get_tasks(
                            role[config], role_name, filepath)
                    else:
                        try:
                            data = role[config]
                        except KeyError as e:
                            message = 'Invalid key: %s, error: %s' % (config,
                                                                      str(e))
                            raise KeyError(message)
                    filepath = os.path.join(role_path, '%s.yaml' % config)
                    with os.fdopen(os.open(filepath,
                                           os.O_WRONLY | os.O_CREAT, 0o600),
                                   'w') as conf_file:
                        yaml.safe_dump(data,
                                       conf_file,
                                       default_flow_style=False)
        print("The TripleO configuration has been successfully generated "
              "into: {0}".format(tmp_path))
