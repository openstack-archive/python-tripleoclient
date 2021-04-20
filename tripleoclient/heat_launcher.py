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

import datetime
import glob
import grp
import json
import logging
import multiprocessing
import os
import pwd
import signal
import subprocess
import tempfile

import jinja2
from oslo_utils import timeutils

from tripleoclient.constants import (DEFAULT_HEAT_CONTAINER,
                                     DEFAULT_HEAT_API_CONTAINER,
                                     DEFAULT_HEAT_ENGINE_CONTAINER,
                                     DEFAULT_TEMPLATES_DIR)

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
    def __init__(self, api_port=8006,
                 all_container_image=DEFAULT_HEAT_CONTAINER,
                 api_container_image=DEFAULT_HEAT_API_CONTAINER,
                 engine_container_image=DEFAULT_HEAT_ENGINE_CONTAINER,
                 user='heat',
                 heat_dir='/var/log/heat-launcher',
                 use_tmp_dir=True,
                 use_root=False,
                 rm_heat=False,
                 skip_heat_pull=False):
        self.api_port = api_port
        self.all_container_image = all_container_image
        self.api_container_image = api_container_image
        self.engine_container_image = engine_container_image
        self.heat_dir = os.path.abspath(heat_dir)
        self.host = "127.0.0.1"
        self.db_dump_path = os.path.join(
            self.heat_dir, 'heat-db-dump-{}.sql'.format(
                datetime.datetime.utcnow().isoformat()))
        self.skip_heat_pull = skip_heat_pull

        if rm_heat:
            self.kill_heat(None)
            self.rm_heat()

        if os.path.isdir(self.heat_dir):
            # This one may fail but it's just cleanup.
            p = subprocess.Popen(['umount', self.heat_dir],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 universal_newlines=True)
            cmd_stdout, cmd_stderr = p.communicate()
            retval = p.returncode
            if retval != 0:
                log.info('Cleanup unmount of %s failed (probably because '
                         'it was not mounted): %s' %
                         (self.heat_dir, cmd_stderr))
            else:
                log.info('umount of %s success' % (self.heat_dir))
        else:
            # Create the directory if it doesn't exist.
            try:
                os.makedirs(self.heat_dir, mode=0o700)
            except Exception as e:
                log.error('Creating temp directory "%s" failed: %s' %
                          (self.heat_dir, e))
                raise Exception('Could not create temp directory %s: %s' %
                                (self.heat_dir, e))
        # As an optimization we mount the tmp directory in a tmpfs (in memory)
        # filesystem.  Depending on your system this can cut the heat
        # deployment times by half.
        p = subprocess.Popen(['mount', '-t', 'tmpfs', '-o', 'size=500M',
                              'tmpfs', self.heat_dir],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             universal_newlines=True)
        cmd_stdout, cmd_stderr = p.communicate()
        retval = p.returncode
        if retval != 0:
            # It's ok if this fails, it will still work.  It just won't
            # be on tmpfs.
            log.warning('Unable to mount tmpfs for logs and '
                        'database %s: %s' %
                        (self.heat_dir, cmd_stderr))

        self.policy_file = os.path.join(os.path.dirname(__file__),
                                        'noauth_policy.json')
        if use_tmp_dir:
            self.install_dir = tempfile.mkdtemp(
                prefix='%s/undercloud_deploy-' % self.heat_dir)
        else:
            self.install_dir = self.heat_dir
        self.user = user
        self.sql_db = os.path.join(self.install_dir, 'heat.sqlite')
        self.log_file = os.path.join(self.install_dir, 'heat.log')
        self.config_file = os.path.join(self.install_dir, 'heat.conf')
        self.paste_file = os.path.join(self.install_dir, 'api-paste.ini')
        self.token_file = os.path.join(self.install_dir, 'token_file.json')
        self._write_fake_keystone_token(self.api_port, self.token_file)
        self._write_heat_config()
        self._write_api_paste_config()
        if use_root:
            uid = int(self.get_heat_uid())
            gid = int(self.get_heat_gid())
            os.chown(self.install_dir, uid, gid)
            os.chown(self.config_file, uid, gid)
            os.chown(self.paste_file, uid, gid)

    def _write_heat_config(self):
        # TODO(ksambor) It will be nice to have possibilities to configure heat
        heat_config = '''
[DEFAULT]
log_file = %(log_file)s
transport_url = 'fake://'
rpc_poll_timeout = 60
rpc_response_timeout = 600
deferred_auth_method = password
num_engine_workers=1
convergence_engine = true
max_json_body_size = 8388608
heat_metadata_server_url=http://127.0.0.1:%(api_port)s/
default_deployment_signal_transport = HEAT_SIGNAL
max_nested_stack_depth = 10
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
api_paste_config = api-paste.ini

[oslo_policy]
policy_file = %(policy_file)s

[yaql]
memory_quota=900000
limit_iterators=9000
        ''' % {'sqlite_db': self.sql_db, 'log_file': self.log_file,
               'api_port': self.api_port, 'policy_file': self.policy_file,
               'token_file': self.token_file}

        with open(self.config_file, 'w') as temp_file:
            temp_file.write(heat_config)

    def _write_api_paste_config(self):

        heat_api_paste_config = '''
[pipeline:heat-api-noauth]
pipeline = faultwrap noauth context versionnegotiation apiv1app
[app:apiv1app]
paste.app_factory = heat.common.wsgi:app_factory
heat.app_factory = heat.api.openstack.v1:API
[filter:noauth]
paste.filter_factory = heat.common.noauth:filter_factory
[filter:context]
paste.filter_factory = heat.common.context:ContextMiddleware_filter_factory
[filter:versionnegotiation]
paste.filter_factory = heat.common.wsgi:filter_factory
heat.filter_factory = heat.api.openstack:version_negotiation_filter
[filter:faultwrap]
paste.filter_factory = heat.common.wsgi:filter_factory
heat.filter_factory = heat.api.openstack:faultwrap_filter
'''
        with open(self.paste_file, 'w') as temp_file:
            temp_file.write(heat_api_paste_config)

    def _write_fake_keystone_token(self, heat_api_port, config_file):
        ks_token = json.dumps(FAKE_TOKEN_RESPONSE) % {'heat_port':
                                                      heat_api_port}
        with open(config_file, 'w') as temp_file:
            temp_file.write(ks_token)

    def get_heat_uid(self):
        return pwd.getpwnam(self.user).pw_uid

    def get_heat_gid(self):
        return grp.getgrnam(self.user).gr_gid

    def check_database(self):
        return True

    def check_message_bus(self):
        return True


class HeatContainerLauncher(HeatBaseLauncher):

    heat_type = 'container'

    def __init__(self, *args, **kwargs):
        super(HeatContainerLauncher, self).__init__(*args, **kwargs)
        self._fetch_container_image()
        self.host = "127.0.0.1"

    def _fetch_container_image(self):
        if self.skip_heat_pull:
            log.info("Skipping container image pull.")
            return
        # force pull of latest container image
        cmd = ['podman', 'pull', self.all_container_image]
        log.debug(' '.join(cmd))
        try:
            subprocess.check_output(cmd)
        except subprocess.CalledProcessError as e:
            raise Exception('Unable to fetch container image {}.'
                            'Error: {}'.format(self.all_container_image, e))

    def launch_heat(self):
        # run the heat-all process
        cmd = [
            'podman', 'run', '--rm',
            '--name', 'heat_all',
            '--user', self.user,
            '--net', 'host',
            '--volume', '%(conf)s:/etc/heat/heat.conf:ro' % {'conf':
                                                             self.config_file},
            '--volume', '%(conf)s:/etc/heat/api-paste.ini:ro' % {
                'conf': self.paste_file},
            '--volume', '%(inst_tmp)s:%(inst_tmp)s:Z' % {'inst_tmp':
                                                         self.install_dir},
            '--volume', '%(pfile)s:%(pfile)s:ro' % {'pfile':
                                                    self.policy_file},
            self.all_container_image, 'heat-all'
        ]
        log.debug(' '.join(cmd))
        os.execvp('podman', cmd)

    def heat_db_sync(self):

        cmd = [
            'podman', 'run', '--rm',
            '--user', self.user,
            '--volume', '%(conf)s:/etc/heat/heat.conf:Z' % {'conf':
                                                            self.config_file},
            '--volume', '%(inst_tmp)s:%(inst_tmp)s:Z' % {'inst_tmp':
                                                         self.install_dir},
            self.all_container_image,
            'heat-manage', 'db_sync']
        log.debug(' '.join(cmd))
        subprocess.check_call(cmd)

    def get_heat_uid(self):
        cmd = [
            'podman', 'run', '--rm',
            self.all_container_image,
            'getent', 'passwd', self.user
        ]
        log.debug(' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             universal_newlines=True)
        result = p.communicate()[0]
        if result:
            return result.split(':')[2]
        raise Exception('Could not find heat uid')

    def get_heat_gid(self):
        cmd = [
            'podman', 'run', '--rm',
            self.all_container_image,
            'getent', 'group', self.user
        ]
        log.debug(' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             universal_newlines=True)
        result = p.communicate()[0]
        if result:
            return result.split(':')[2]
        raise Exception('Could not find heat gid')

    def kill_heat(self, pid, backup_db=False):
        cmd = ['podman', 'stop', 'heat_all']
        log.debug(' '.join(cmd))
        # We don't want to hear from this command..
        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def rm_heat(self, pid):
        cmd = ['podman', 'rm', 'heat_all']
        log.debug(' '.join(cmd))
        # We don't want to hear from this command..
        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class HeatNativeLauncher(HeatBaseLauncher):

    heat_type = 'native'

    def __init__(self, *args, **kwargs):
        super(HeatNativeLauncher, self).__init__(*args, **kwargs)
        self.host = "127.0.0.1"

    def launch_heat(self):
        os.execvp('heat-all', ['heat-all', '--config-file', self.config_file])

    def heat_db_sync(self):
        subprocess.check_call(['heat-manage', '--config-file',
                               self.config_file, 'db_sync'])

    def kill_heat(self, pid, backup_db=False):
        os.kill(pid, signal.SIGKILL)


class HeatPodLauncher(HeatContainerLauncher):

    heat_type = 'pod'

    def __init__(self, *args, **kwargs):
        super(HeatPodLauncher, self).__init__(*args, **kwargs)
        log_dir = os.path.join(self.heat_dir, 'log')
        if not os.path.isdir(log_dir):
            os.makedirs(log_dir)
        self.host = self._get_ctlplane_ip()
        self._chcon()

    def _chcon(self):
        subprocess.check_call(
            ['chcon', '-R', '-t', 'container_file_t',
             '-l', 's0', self.heat_dir])

    def _fetch_container_image(self):
        if self.skip_heat_pull:
            log.info("Skipping container image pull.")
            return
        # force pull of latest container image
        for image in self.api_container_image, self.engine_container_image:
            log.info("Pulling conatiner image {}.".format(image))
            cmd = ['sudo', 'podman', 'pull', image]
            log.debug(' '.join(cmd))
            try:
                subprocess.check_output(cmd)
            except subprocess.CalledProcessError as e:
                raise Exception('Unable to fetch container image {}.'
                                'Error: {}'.format(image, e))

    def launch_heat(self):
        inspect = subprocess.run([
            'sudo', 'podman', 'pod', 'inspect', '--format',
            '"{{.State}}"', 'ephemeral-heat'],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        if "Running" in self._decode(inspect.stdout):
            log.info("ephemeral-heat pod already running, skipping launch")
            return
        self._write_heat_pod()
        subprocess.check_call([
            'sudo', 'podman', 'play', 'kube',
            os.path.join(self.heat_dir, 'heat-pod.yaml')
        ])

    def heat_db_sync(self, restore_db=False):
        if not self.database_exists():
            subprocess.check_call([
                'sudo', 'podman', 'exec', '-it', '-u', 'root',
                'mysql', 'mysql', '-e', 'create database heat'
            ])
            subprocess.check_call([
                'sudo', 'podman', 'exec', '-it', '-u', 'root',
                'mysql', 'mysql', '-e',
                'create user if not exists '
                '\'heat\'@\'%\' identified by \'heat\''
            ])
            subprocess.check_call([
                'sudo', 'podman', 'exec', '-it', '-u', 'root',
                'mysql', 'mysql', 'heat', '-e',
                'grant all privileges on heat.* to \'heat\'@\'%\''
            ])
            subprocess.check_call([
                'sudo', 'podman', 'exec', '-it', '-u', 'root',
                'mysql', 'mysql', '-e', 'flush privileges;'
            ])
        cmd = [
            'sudo', 'podman', 'run', '--rm',
            '--user', 'heat',
            '--volume', '%(conf)s:/etc/heat/heat.conf:z' % {'conf':
                                                            self.config_file},
            '--volume', '%(inst_tmp)s:%(inst_tmp)s:z' % {'inst_tmp':
                                                         self.install_dir},
            self.api_container_image,
            'heat-manage', 'db_sync']
        log.debug(' '.join(cmd))
        subprocess.check_call(cmd)
        if restore_db:
            self.do_restore_db()

    def do_restore_db(self, db_dump_path=None):
        if not db_dump_path:
            # Find the latest dump from self.heat_dir
            db_dumps = glob.glob('{}/heat-db-dump*'.format(self.heat_dir))
            if not db_dumps:
                raise Exception('No db backups found to restore in %s' %
                                self.heat_dir)
            db_dump_path = max(db_dumps, key=os.path.getmtime)
            log.info("Restoring db from {}".format(db_dump_path))
        subprocess.run([
            'sudo', 'podman', 'exec', '-i', '-u', 'root',
            'mysql', 'mysql', 'heat'], stdin=open(db_dump_path),
            check=True)

    def do_backup_db(self, db_dump_path=None):
        if not db_dump_path:
            db_dump_path = self.db_dump_path
        if os.path.exists(db_dump_path):
            raise Exception("Won't overwrite existing db dump at %s. "
                            "Remove it first." % db_dump_path)
        with open(db_dump_path, 'w') as out:
            subprocess.run([
                'sudo', 'podman', 'exec', '-it', '-u', 'root',
                'mysql', 'mysqldump', 'heat'], stdout=out,
                check=True)

    def rm_heat(self, backup_db=False):
        if self.database_exists():
            if backup_db:
                self.do_backup_db()
            try:
                subprocess.check_call([
                    'sudo', 'podman', 'exec', '-it', '-u', 'root',
                    'mysql', 'mysql', 'heat', '-e',
                    'drop database heat'])
                subprocess.check_call([
                    'sudo', 'podman', 'exec', '-it', '-u', 'root',
                    'mysql', 'mysql', '-e',
                    'drop user \'heat\'@\'%\''])
            except subprocess.CalledProcessError:
                pass
        subprocess.call([
            'sudo', 'podman', 'pod', 'rm', '-f', 'ephemeral-heat'
        ])

    def stop_heat(self):
        subprocess.check_call([
            'sudo', 'podman', 'pod', 'stop', 'ephemeral-heat'
        ])

    def check_message_bus(self):
        log.info("Checking that message bus (rabbitmq) is up")
        try:
            subprocess.check_call([
                'sudo', 'podman', 'exec', '-u', 'root', 'rabbitmq',
                'rabbitmqctl', 'list_queues'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError as cpe:
            log.error("The message bus (rabbitmq) does not seem "
                      "to be available")
            log.error(cpe)
            raise

    def check_database(self):
        log.info("Checking that database is up")
        try:
            subprocess.check_call([
                'sudo', 'podman', 'exec', '-u', 'root', 'mysql',
                'mysql', '-h', self._get_ctlplane_ip(), '-e',
                'show databases;'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError as cpe:
            log.error("The database does not seem to be available")
            log.error(cpe)
            raise

    def database_exists(self):
        output = subprocess.check_output([
            'sudo', 'podman', 'exec', '-it', '-u', 'root', 'mysql',
            'mysql', '-e', 'show databases like "heat"'
        ])
        return 'heat' in str(output)

    def kill_heat(self, pid, backup_db=False):
        subprocess.call([
            'sudo', 'podman', 'pod', 'kill', 'ephemeral-heat'
        ])

    def _decode(self, encoded):
        if not encoded:
            return ""
        decoded = encoded.decode('utf-8')
        if decoded.endswith('\n'):
            decoded = decoded[:-1]
        return decoded

    def _get_transport_url(self):
        user = self._decode(subprocess.check_output(
            ['sudo', 'hiera', 'rabbitmq::default_user']))
        password = self._decode(subprocess.check_output(
            ['sudo', 'hiera', 'rabbitmq::default_pass']))
        fqdn_ctlplane = self._decode(subprocess.check_output(
            ['sudo', 'hiera', 'fqdn_ctlplane']))
        port = self._decode(subprocess.check_output(
            ['sudo', 'hiera', 'rabbitmq::port']))

        transport_url = "rabbit://%s:%s@%s:%s/?ssl=0" % \
            (user, password, fqdn_ctlplane, port)
        return transport_url

    def _get_db_connection(self):
        return ('mysql+pymysql://'
                'heat:heat@{}/heat?read_default_file='
                '/etc/my.cnf.d/tripleo.cnf&read_default_group=tripleo'.format(
                    self._get_ctlplane_vip()))

    def _get_ctlplane_vip(self):
        return self._decode(subprocess.check_output(
            ['sudo', 'hiera', 'controller_virtual_ip']))

    def _get_ctlplane_ip(self):
        return self._decode(subprocess.check_output(
            ['sudo', 'hiera', 'ctlplane']))

    def _get_num_engine_workers(self):
        return int(multiprocessing.cpu_count() / 2)

    def _write_heat_config(self):
        heat_config_tmpl_path = os.path.join(DEFAULT_TEMPLATES_DIR,
                                             "ephemeral-heat",
                                             "heat.conf.j2")
        with open(heat_config_tmpl_path) as tmpl:
            heat_config_tmpl = jinja2.Template(tmpl.read())

        config_vars = {
            "transport_url": self._get_transport_url(),
            "db_connection": self._get_db_connection(),
            "api_port": self.api_port,
            "num_engine_workers": self._get_num_engine_workers(),
        }
        heat_config = heat_config_tmpl.render(**config_vars)

        with open(self.config_file, 'w') as conf:
            conf.write(heat_config)

    def _write_heat_pod(self):
        heat_pod_tmpl_path = os.path.join(DEFAULT_TEMPLATES_DIR,
                                          "ephemeral-heat",
                                          "heat-pod.yaml.j2")
        with open(heat_pod_tmpl_path) as tmpl:
            heat_pod_tmpl = jinja2.Template(tmpl.read())

        pod_vars = {
            "install_dir": self.install_dir,
            "heat_dir": self.heat_dir,
            "policy_file": self.policy_file,
            "ctlplane_ip": self.host,
            "api_port": self.api_port,
            "api_image": self.api_container_image,
            "engine_image": self.engine_container_image,
        }
        heat_pod = heat_pod_tmpl.render(**pod_vars)

        heat_pod_path = os.path.join(self.heat_dir, "heat-pod.yaml")
        with open(heat_pod_path, 'w') as conf:
            conf.write(heat_pod)
