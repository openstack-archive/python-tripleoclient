#   Copyright 2017 Red Hat, Inc.
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
from __future__ import print_function

import logging
import os
import signal
import subprocess
import tempfile


log = logging.getLogger(__name__)


class HeatBaseLauncher(object):

    # The init function will need permission to touch these files
    # and chown them accordingly for the heat user
    def __init__(self, api_port, ks_port, container_image, user='heat'):
        self.api_port = api_port
        self.ks_port = ks_port

        self.policy_file = os.path.join(os.path.dirname(__file__),
                                        'noauth_policy.json')
        self.install_tmp = tempfile.mkdtemp(prefix='undercloud_deploy-')
        self.container_image = container_image
        self.user = user
        self.sql_db = os.path.join(self.install_tmp, 'heat.sqlite')
        self.log_file = os.path.join(self.install_tmp, 'heat.log')
        self.config_file = os.path.join(self.install_tmp, 'heat.conf')
        self._write_heat_config(self.config_file,
                                self.sql_db,
                                self.log_file,
                                api_port,
                                ks_port,
                                self.policy_file)
        uid = int(self.get_heat_uid())
        gid = int(self.get_heat_gid())
        os.chown(self.install_tmp, uid, gid)
        os.chown(self.config_file, uid, gid)

    def _write_heat_config(self, config_file, sqlite_db, log_file, api_port,
                           ks_port, policy_file):
        heat_config = '''
[DEFAULT]
log_file = %(log_file)s
rpc_backend = fake
rpc_poll_timeout = 60
rpc_response_timeout = 600
deferred_auth_method = password
num_engine_workers=1
convergence_engine = false
max_json_body_size = 8388608

default_deployment_signal_transport = HEAT_SIGNAL
max_nested_stack_depth = 6

[heat_all]
enabled_services = api,engine

[heat_api]
workers = 1
bind_host = 127.0.0.1
bind_port = %(api_port)s

[database]
connection = sqlite:///%(sqlite_db)s.db

[paste_deploy]
flavor = noauth
api_paste_config = /usr/share/heat/api-paste-dist.ini

[oslo_policy]
policy_file = %(policy_file)s

[clients_keystone]
auth_uri=http://127.0.0.1:%(ks_port)s

[keystone_authtoken]
auth_type = password
auth_url=http://127.0.0.1:%(ks_port)s

[yaql]
memory_quota=900000
limit_iterators=9000
        ''' % {'sqlite_db': sqlite_db, 'log_file': log_file,
               'api_port': api_port, 'ks_port': ks_port,
               'policy_file': policy_file}
        with open(config_file, 'w') as temp_file:
            temp_file.write(heat_config)


class HeatDockerLauncher(HeatBaseLauncher):

    def __init__(self, api_port, ks_port, container_image, user='heat'):
        super(HeatDockerLauncher, self).__init__(api_port, ks_port,
                                                 container_image, user)

    def launch_heat(self):
        cmd = [
            'docker', 'run',
            '--name', 'heat_all',
            '--user', self.user,
            '--net', 'host',
            '--volume', '%(conf)s:/etc/heat/heat.conf:Z' % {'conf':
                                                            self.config_file},
            '--volume', '%(inst_tmp)s:%(inst_tmp)s:Z' % {'inst_tmp':
                                                         self.install_tmp},
            '--volume', '%(pfile)s:%(pfile)s:ro' % {'pfile':
                                                    self.policy_file},
            self.container_image, 'heat-all'
        ]
        log.debug(' '.join(cmd))
        subprocess.check_call(cmd)

    def heat_db_sync(self):

        cmd = [
            'docker', 'run', '--rm',
            '--user', self.user,
            '--volume', '%(conf)s:/etc/heat/heat.conf:Z' % {'conf':
                                                            self.config_file},
            '--volume', '%(inst_tmp)s:%(inst_tmp)s:Z' % {'inst_tmp':
                                                         self.install_tmp},
            self.container_image,
            'heat-manage', 'db_sync']
        log.debug(' '.join(cmd))
        subprocess.check_call(cmd)

    def get_heat_uid(self):
        cmd = [
            'docker', 'run', '--rm',
            self.container_image,
            'getent', 'passwd'
        ]
        log.debug(' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        result = p.communicate()[0]
        for line in result.split("\n"):
            if line.startswith('%s:' % self.user):
                return line.split(':')[2]
        raise Exception('Could not find heat uid')

    def get_heat_gid(self):
        cmd = [
            'docker', 'run', '--rm',
            self.container_image,
            'getent', 'group'
        ]
        log.debug(' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        result = p.communicate()[0]
        for line in result.split("\n"):
            if line.startswith('%s:' % self.user):
                return line.split(':')[2]
        raise Exception('Could not find heat gid')

    def kill_heat(self, pid):
        cmd = ['docker', 'rm', '-f', 'heat_all']
        log.debug(' '.join(cmd))
        subprocess.check_call(cmd)


class HeatNativeLauncher(HeatBaseLauncher):

    def __init__(self, api_port, ks_port, container_image, user='heat'):
        super(HeatNativeLauncher, self).__init__(api_port, ks_port,
                                                 container_image, user)

    def launch_heat(self):
        os.execvp('heat-all', ['heat-all', '--config-file', self.config_file])

    def heat_db_sync(self):
        subprocess.check_call(['heat-manage', '--config-file',
                               self.config_file, 'db_sync'])

    def get_heat_uid(self):
        p = subprocess.Popen(["getent", "passwd", "|", "grep", "heat"],
                             stdout=subprocess.PIPE)
        return p.communicate()[0].rstrip().split(':')[2]

    def get_heat_gid(self):
        p = subprocess.Popen(["getent", "group", "|", "grep", "heat"],
                             stdout=subprocess.PIPE)
        return p.communicate()[0].rstrip().split(':')[2]

    def kill_heat(self, pid):
        os.kill(pid, signal.SIGKILL)
