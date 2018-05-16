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

import datetime
import grp
import json
import logging
import os
import pwd
import signal
import subprocess
import tempfile

from oslo_utils import timeutils

log = logging.getLogger(__name__)

NEXT_DAY = (timeutils.utcnow() + datetime.timedelta(days=2)).isoformat()

FAKE_TOKEN_RESPONSE = {
    "token": {
        "is_domain": False,
        "methods": ["password"],
        "roles": [{
            "id": "4c8de39b96794ab28bf37a0b842b8bc8",
            "name": "admin"
        }],
        "expires_at": NEXT_DAY,
        "project": {
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "admin",
            "name": "admin"
        },
        "catalog": [{
            "endpoints": [{
                "url": "http://127.0.0.1:%(heat_port)s/v1/admin",
                "interface": "public",
                "region": "regionOne",
                "region_id": "regionOne",
                "id": "2809305628004fb391b3d0254fb5b4f7"
            }, {
                "url": "http://127.0.0.1:%(heat_port)s/v1/admin",
                "interface": "internal",
                "region": "regionOne",
                "region_id": "regionOne",
                "id": "2809305628004fb391b3d0254fb5b4f7"
            }, {
                "url": "http://127.0.0.1:%(heat_port)s/v1/admin",
                "interface": "admin",
                "region": "regionOne",
                "region_id": "regionOne",
                "id": "2809305628004fb391b3d0254fb5b4f7"
            }],
            "type": "orchestration",
            "id": "96a549e3961d45cabe883dd17c5835be",
            "name": "heat"
        }, {
            "endpoints": [{
                "url": "http://127.0.0.1/v3",
                "interface": "public",
                "region": "regionOne",
                "region_id": "regionOne",
                "id": "eca215878e404a2d9dcbcc7f6a027165"
            }, {
                "url": "http://127.0.0.1/v3",
                "interface": "internal",
                "region": "regionOne",
                "region_id": "regionOne",
                "id": "eca215878e404a2d9dcbcc7f6a027165"
            }, {
                "url": "http://127.0.0.1/v3",
                "interface": "admin",
                "region": "regionOne",
                "region_id": "regionOne",
                "id": "eca215878e404a2d9dcbcc7f6a027165"
            }],
            "type": "identity",
            "id": "a785f0b7603042d1bf59237c71af2f15",
            "name": "keystone"
        }],
        "user": {
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "8b7b4c094f934e8c83aa7fe12591dc6c",
            "name": "admin"
        },
        "audit_ids": ["F6ONJ8fCT6i_CFTbmC0vBA"],
        "issued_at": datetime.datetime.utcnow().isoformat()
    }
}


class HeatBaseLauncher(object):

    # The init function will need permission to touch these files
    # and chown them accordingly for the heat user
    def __init__(self, api_port, container_image, user='heat'):
        self.api_port = api_port
        heatdir = '/var/log/heat-launcher'

        if os.path.isdir(heatdir):
            # This one may fail but it's just cleanup.
            p = subprocess.Popen(['umount', heatdir],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            cmd_stdout, cmd_stderr = p.communicate()
            retval = p.returncode
            if retval != 0:
                log.info('Cleanup unmount of %s failed (probably because '
                         'it was not mounted): %s' % (heatdir, cmd_stderr))
            else:
                log.info('umount of %s success' % (heatdir))
        else:
            # Create the directory if it doesn't exist.
            try:
                os.makedirs(heatdir, mode=0o700)
            except Exception as e:
                log.error('Creating temp directory "%s" failed: %s' %
                          (heatdir, e))
                raise Exception('Could not create temp directory %s: %s' %
                                (heatdir, e))
        # As an optimization we mount the tmp directory in a tmpfs (in memory)
        # filesystem.  Depending on your system this can cut the heat
        # deployment times by half.
        p = subprocess.Popen(['mount', '-t', 'tmpfs', '-o', 'size=500M',
                              'tmpfs', heatdir],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        cmd_stdout, cmd_stderr = p.communicate()
        retval = p.returncode
        if retval != 0:
            # It's ok if this fails, it will still work.  It just won't
            # be on tmpfs.
            log.warning('Unable to mount tmpfs for logs and database %s: %s' %
                        (heatdir, cmd_stderr))

        self.policy_file = os.path.join(os.path.dirname(__file__),
                                        'noauth_policy.json')
        self.install_tmp = tempfile.mkdtemp(prefix='%s/undercloud_deploy-' %
                                            heatdir)
        self.container_image = container_image
        self.user = user
        self.sql_db = os.path.join(self.install_tmp, 'heat.sqlite')
        self.log_file = os.path.join(self.install_tmp, 'heat.log')
        self.config_file = os.path.join(self.install_tmp, 'heat.conf')
        self.token_file = os.path.join(self.install_tmp, 'token_file.json')
        self._write_fake_keystone_token(api_port, self.token_file)
        self._write_heat_config(self.config_file,
                                self.sql_db,
                                self.log_file,
                                api_port,
                                self.policy_file,
                                self.token_file)
        uid = int(self.get_heat_uid())
        gid = int(self.get_heat_gid())
        os.chown(self.install_tmp, uid, gid)
        os.chown(self.config_file, uid, gid)

    def _write_heat_config(self, config_file, sqlite_db, log_file, api_port,
                           policy_file, token_file):
        heat_config = '''
[DEFAULT]
log_file = %(log_file)s
rpc_backend = fake
rpc_poll_timeout = 60
rpc_response_timeout = 600
deferred_auth_method = password
num_engine_workers=1
convergence_engine = true
max_json_body_size = 8388608
heat_metadata_server_url=http://127.0.0.1:%(api_port)s/
default_deployment_signal_transport = HEAT_SIGNAL
max_nested_stack_depth = 6
keystone_backend = heat.engine.clients.os.keystone.fake_keystoneclient\
.FakeKeystoneClient

[noauth]
token_response = %(token_file)s

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

[yaql]
memory_quota=900000
limit_iterators=9000
        ''' % {'sqlite_db': sqlite_db, 'log_file': log_file,
               'api_port': api_port, 'policy_file': policy_file,
               'token_file': token_file}
        with open(config_file, 'w') as temp_file:
            temp_file.write(heat_config)

    def _write_fake_keystone_token(self, heat_api_port, config_file):
        ks_token = json.dumps(FAKE_TOKEN_RESPONSE) % {'heat_port':
                                                      heat_api_port}
        with open(config_file, 'w') as temp_file:
            temp_file.write(ks_token)


class HeatDockerLauncher(HeatBaseLauncher):

    def __init__(self, api_port, container_image, user='heat'):
        super(HeatDockerLauncher, self).__init__(api_port, container_image,
                                                 user)

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
            'getent', 'passwd', self.user
        ]
        log.debug(' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        result = p.communicate()[0]
        if result:
            return result.split(':')[2]
        raise Exception('Could not find heat uid')

    def get_heat_gid(self):
        cmd = [
            'docker', 'run', '--rm',
            self.container_image,
            'getent', 'group', self.user
        ]
        log.debug(' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        result = p.communicate()[0]
        if result:
            return result.split(':')[2]
        raise Exception('Could not find heat gid')

    def kill_heat(self, pid):
        cmd = ['docker', 'rm', '-f', 'heat_all']
        log.debug(' '.join(cmd))
        # We don't want to hear from this command..
        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class HeatNativeLauncher(HeatBaseLauncher):

    def __init__(self, api_port, container_image, user='heat'):
        super(HeatNativeLauncher, self).__init__(api_port, container_image,
                                                 user)

    def launch_heat(self):
        os.execvp('heat-all', ['heat-all', '--config-file', self.config_file])

    def heat_db_sync(self):
        subprocess.check_call(['heat-manage', '--config-file',
                               self.config_file, 'db_sync'])

    def get_heat_uid(self):
        return pwd.getpwnam('heat').pw_uid

    def get_heat_gid(self):
        return grp.getgrnam('heat').gr_gid

    def kill_heat(self, pid):
        os.kill(pid, signal.SIGKILL)
