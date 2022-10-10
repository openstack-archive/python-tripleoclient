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

import configparser
import datetime
import glob
import grp
import json
import logging
import multiprocessing
import os
import pwd
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time

import jinja2
from oslo_utils import timeutils
from tenacity import retry, retry_if_exception_type, retry_if_exception_message
from tenacity.stop import stop_after_attempt, stop_after_delay
from tenacity.wait import wait_fixed

from tripleoclient.constants import (DEFAULT_HEAT_CONTAINER,
                                     DEFAULT_HEAT_API_CONTAINER,
                                     DEFAULT_HEAT_ENGINE_CONTAINER,
                                     DEFAULT_EPHEMERAL_HEAT_API_CONTAINER,
                                     DEFAULT_EPHEMERAL_HEAT_ENGINE_CONTAINER,
                                     DEFAULT_TEMPLATES_DIR,
                                     EPHEMERAL_HEAT_POD_NAME)
from tripleoclient.exceptions import HeatPodMessageQueueException
from tripleoclient import utils as oooutils

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
        self.timestamp = time.time()
        self.db_dump_path = os.path.join(self.heat_dir, 'heat-db.sql')
        self.skip_heat_pull = skip_heat_pull
        self.zipped_db_suffix = '.tar.bzip2'
        self.log_dir = os.path.join(self.heat_dir, 'log')
        self.use_tmp_dir = use_tmp_dir

        if not os.path.isdir(self.heat_dir):
            # Create the directory if it doesn't exist.
            try:
                os.makedirs(self.heat_dir, mode=0o755)
            except Exception as e:
                log.error('Creating temp directory "%s" failed: %s' %
                          (self.heat_dir, e))
                raise Exception('Could not create temp directory %s: %s' %
                                (self.heat_dir, e))

        if self.use_tmp_dir:
            self.install_dir = tempfile.mkdtemp(
                prefix='%s/tripleo_deploy-' % self.heat_dir)
        else:
            self.install_dir = self.heat_dir

        if use_root:
            self.umount_install_dir()

        if use_root and use_tmp_dir:
            # As an optimization we mount the tmp directory in a tmpfs (in
            # memory) filesystem.  Depending on your system this can cut the
            # heat deployment times by half.
            p = subprocess.Popen(['mount', '-t', 'tmpfs', '-o', 'size=500M',
                                  'tmpfs', self.install_dir],
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

        self.log_file = self._get_log_file_path()
        self.sql_db = os.path.join(self.install_dir, 'heat.sqlite')
        self.config_file = os.path.join(self.install_dir, 'heat.conf')
        self.paste_file = os.path.join(self.install_dir, 'api-paste.ini')
        self.token_file = os.path.join(self.install_dir, 'token_file.json')

        self.user = user
        self._write_fake_keystone_token(self.api_port, self.token_file)
        self._write_heat_config()
        self._write_api_paste_config()
        if use_root:
            uid = int(self.get_heat_uid())
            gid = int(self.get_heat_gid())
            os.chown(self.install_dir, uid, gid)
            os.chown(self.config_file, uid, gid)
            os.chown(self.paste_file, uid, gid)

        if rm_heat:
            self.kill_heat(None)
            self.rm_heat()

    def umount_install_dir(self):
        # This one may fail but it's just cleanup.
        p = subprocess.Popen(['umount', self.install_dir],
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

    def _get_log_file_path(self):
        return os.path.join(self.install_dir, 'heat.log')

    def _write_heat_config(self):
        # TODO(ksambor) It will be nice to have possibilities to configure heat
        heat_config = '''
[DEFAULT]
log_file = %(log_file)s
transport_url = 'fake://'
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

[yaql]
memory_quota=900000
limit_iterators=9000
        ''' % {'sqlite_db': self.sql_db, 'log_file': self.log_file,
               'api_port': self.api_port,
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

    def tar_file(self, file_path, cleanup=True):
        tf_name = '{}-{}{}'.format(file_path, self.timestamp,
                                   self.zipped_db_suffix)
        tf = tarfile.open(tf_name, 'w:bz2')
        tf.add(file_path, os.path.basename(file_path))
        tf.close()
        log.info("Created tarfile {}".format(tf_name))
        if cleanup:
            log.info("Deleting {}".format(file_path))
            os.unlink(file_path)

    def untar_file(self, tar_path, extract_dir):
        tf = tarfile.open(tar_path, 'r:bz2')
        tf.extractall(extract_dir)

    def rm_heat(self, backup_db=True):
        pass


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
            self.all_container_image, 'heat-all'
        ]
        log.debug(' '.join(cmd))
        os.execvp('podman', cmd)

    def heat_db_sync(self):

        cmd = [
            'podman', 'run', '--rm',
            '--net', 'host',
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
            '--net', 'host',
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
            '--net', 'host',
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

    def kill_heat(self, pid):
        cmd = ['podman', 'stop', 'heat_all']
        log.debug(' '.join(cmd))
        # We don't want to hear from this command..
        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def rm_heat(self, backup_db=True):
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

    def heat_db_sync(self, restore_db=False):
        subprocess.check_call(['heat-manage', '--config-file',
                               self.config_file, 'db_sync'])

    def kill_heat(self, pid):
        os.kill(pid, signal.SIGKILL)
        if self.use_tmp_dir:
            shutil.copytree(
                self.install_dir,
                os.path.join(self.heat_dir,
                             'tripleo_deploy-%s' % self.timestamp))
        self.umount_install_dir()
        self._remove_install_dir()

    @retry(retry=(retry_if_exception_type(OSError) |
                  retry_if_exception_message('Device or resource busy')),
           reraise=True,
           stop=(stop_after_delay(10) | stop_after_attempt(10)),
           wait=wait_fixed(0.5))
    def _remove_install_dir(self):
        shutil.rmtree(self.install_dir)


class HeatPodLauncher(HeatContainerLauncher):

    heat_type = 'pod'

    def __init__(self, *args, **kwargs):
        super(HeatPodLauncher, self).__init__(*args, **kwargs)
        if not os.path.isdir(self.log_dir):
            os.makedirs(self.log_dir)
        self.host = "127.0.0.1"
        self._chcon()

    def _chcon(self):
        subprocess.check_call(
            ['chcon', '-R', '-t', 'container_file_t',
             '-l', 's0', self.heat_dir])

    def _fetch_container_image(self):
        # Skip trying to pull the images if they are set to the default
        # as they can't be pulled since they are tagged as localhost.
        # If the images are missing for some reason, podman will still pull
        # them by default, and error appropriately if needed.
        if (self.api_container_image ==
                DEFAULT_EPHEMERAL_HEAT_API_CONTAINER or
                self.engine_container_image ==
                DEFAULT_EPHEMERAL_HEAT_ENGINE_CONTAINER):
            skip_heat_pull = True
        else:
            skip_heat_pull = self.skip_heat_pull
        if skip_heat_pull:
            log.info("Skipping container image pull.")
            return
        # force pull of latest container image
        for image in self.api_container_image, self.engine_container_image:
            log.info("Pulling container image {}.".format(image))
            cmd = ['sudo', 'podman', 'pull', image]
            log.debug(' '.join(cmd))
            try:
                subprocess.check_output(cmd)
            except subprocess.CalledProcessError as e:
                raise Exception('Unable to fetch container image {}.'
                                'Error: {}'.format(image, e))

    def get_pod_state(self):
        inspect = subprocess.run([
            'sudo', 'podman', 'pod', 'inspect', '--format',
            '"{{.State}}"', EPHEMERAL_HEAT_POD_NAME],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        return self._decode(inspect.stdout)

    def launch_heat(self):
        if "Running" in self.get_pod_state():
            log.info("%s pod already running, skipping launch",
                     EPHEMERAL_HEAT_POD_NAME)
            return
        self._write_heat_pod()
        subprocess.check_call([
            'sudo', 'podman', 'play', 'kube',
            os.path.join(self.heat_dir, 'heat-pod.yaml')
        ])

    def heat_db_sync(self, restore_db=False):
        if not self.database_exists():
            subprocess.check_call([
                'sudo', 'podman', 'exec', '-u', 'root',
                'mysql', 'mysql', '-e', 'create database heat'
            ])
            subprocess.check_call([
                'sudo', 'podman', 'exec', '-u', 'root',
                'mysql', 'mysql', '-e',
                'create user if not exists '
                '\'heat\'@\'%\' identified by \'heat\''
            ])
            subprocess.check_call([
                'sudo', 'podman', 'exec', '-u', 'root',
                'mysql', 'mysql', 'heat', '-e',
                'grant all privileges on heat.* to \'heat\'@\'%\''
            ])
            subprocess.check_call([
                'sudo', 'podman', 'exec', '-u', 'root',
                'mysql', 'mysql', '-e', 'flush privileges;'
            ])
        cmd = [
            'sudo', 'podman', 'run', '--rm',
            '--user', 'heat',
            '--net', 'host',
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
            db_dump_path = self.db_dump_path
            # Find the latest dump from self.heat_dir
            db_dumps = glob.glob(
                '{}-*{}'.format
                (db_dump_path,
                 self.zipped_db_suffix))
            if not db_dumps:
                raise Exception('No db backups found to restore in %s' %
                                self.heat_dir)
            db_dump = max(db_dumps, key=os.path.getmtime)
            self.untar_file(db_dump, self.heat_dir)
            log.info("Restoring db from {}".format(db_dump))
        try:
            with open(db_dump_path) as f:
                subprocess.run([
                    'sudo', 'podman', 'exec', '-i', '-u', 'root',
                    'mysql', 'mysql', 'heat'], stdin=f,
                    check=True)
        finally:
            os.unlink(db_dump_path)

    def do_backup_db(self, db_dump_path=None):
        if not db_dump_path:
            db_dump_path = self.db_dump_path
        if os.path.exists(db_dump_path):
            raise Exception("Won't overwrite existing db dump at %s. "
                            "Remove it first." % db_dump_path)
        log.info("Starting back up of heat db")
        with open(db_dump_path, 'w') as out:
            subprocess.run([
                'sudo', 'podman', 'exec', '-u', 'root',
                'mysql', 'mysqldump', 'heat'], stdout=out,
                check=True)

        self.tar_file(db_dump_path)

    def pod_exists(self):
        try:
            subprocess.check_call(
                ['sudo', 'podman', 'pod', 'inspect', EPHEMERAL_HEAT_POD_NAME],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False

    def rm_heat(self, backup_db=True):
        if self.database_exists():
            if backup_db:
                self.do_backup_db()
            try:
                subprocess.check_call([
                    'sudo', 'podman', 'exec',  '-u', 'root',
                    'mysql', 'mysql', 'heat', '-e',
                    'drop database heat'])
                subprocess.check_call([
                    'sudo', 'podman', 'exec',  '-u', 'root',
                    'mysql', 'mysql', '-e',
                    'drop user \'heat\'@\'%\''])
            except subprocess.CalledProcessError:
                pass
        if self.pod_exists():
            log.info("Removing pod: %s", EPHEMERAL_HEAT_POD_NAME)
            subprocess.call([
                'sudo', 'podman', 'pod', 'rm', '-f',
                EPHEMERAL_HEAT_POD_NAME
            ])
        config = self._read_heat_config()
        log_file_path = os.path.join(self.log_dir,
                                     config['DEFAULT']['log_file'])
        if os.path.exists(log_file_path):
            self.tar_file(log_file_path)

    def stop_heat(self):
        if self.pod_exists() and self.get_pod_state() != 'Exited':
            log.info("Stopping pod: %s", EPHEMERAL_HEAT_POD_NAME)
            subprocess.check_call([
                'sudo', 'podman', 'pod', 'stop',
                EPHEMERAL_HEAT_POD_NAME
            ])
            log.info("Stopped pod: %s", EPHEMERAL_HEAT_POD_NAME)

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
            'sudo', 'podman', 'exec',  '-u', 'root', 'mysql',
            'mysql', '-e', 'show databases like "heat"'
        ])
        return 'heat' in str(output)

    def kill_heat(self, pid):
        if self.pod_exists():
            log.info("Killing pod: %s", EPHEMERAL_HEAT_POD_NAME)
            subprocess.call([
                'sudo', 'podman', 'pod', 'kill',
                EPHEMERAL_HEAT_POD_NAME
            ])
            log.info("Killed pod: %s", EPHEMERAL_HEAT_POD_NAME)
        else:
            log.info("Pod does not exist: %s", EPHEMERAL_HEAT_POD_NAME)

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
                    oooutils.bracket_ipv6(self._get_ctlplane_vip())))

    def _get_ctlplane_vip(self):
        return self._decode(subprocess.check_output(
            ['sudo', 'hiera', 'controller_virtual_ip']))

    def _get_ctlplane_ip(self):
        return self._decode(subprocess.check_output(
            ['sudo', 'hiera', 'ctlplane']))

    def _get_num_engine_workers(self):
        return int(multiprocessing.cpu_count() / 2)

    @retry(retry=retry_if_exception_type(HeatPodMessageQueueException),
           reraise=True,
           stop=(stop_after_delay(10) | stop_after_attempt(10)),
           wait=wait_fixed(0.5))
    def wait_for_message_queue(self):
        queue_name = 'engine.' + EPHEMERAL_HEAT_POD_NAME
        output = subprocess.check_output([
            'sudo', 'podman', 'exec', 'rabbitmq',
            'rabbitmqctl', 'list_queues'])
        if str(output).count(queue_name) < 1:
            msg = "Message queue for ephemeral heat not created in time."
            raise HeatPodMessageQueueException(msg)

    def _get_log_file_path(self):
        return 'heat-{}.log'.format(self.timestamp)

    def _read_heat_config(self):
        config = configparser.ConfigParser()
        config.read(self.config_file)
        return config

    def _write_heat_config(self):
        heat_config_tmpl_path = os.path.join(DEFAULT_TEMPLATES_DIR,
                                             EPHEMERAL_HEAT_POD_NAME,
                                             "heat.conf.j2")
        with open(heat_config_tmpl_path) as tmpl:
            heat_config_tmpl = jinja2.Template(tmpl.read())

        config_vars = {
            "transport_url": self._get_transport_url(),
            "db_connection": self._get_db_connection(),
            "api_port": self.api_port,
            "num_engine_workers": self._get_num_engine_workers(),
            "log_file": self.log_file,
        }
        heat_config = heat_config_tmpl.render(**config_vars)

        with open(self.config_file, 'w') as conf:
            conf.write(heat_config)

    def _write_heat_pod(self):
        heat_pod_tmpl_path = os.path.join(DEFAULT_TEMPLATES_DIR,
                                          EPHEMERAL_HEAT_POD_NAME,
                                          "heat-pod.yaml.j2")
        with open(heat_pod_tmpl_path) as tmpl:
            heat_pod_tmpl = jinja2.Template(tmpl.read())

        pod_vars = {
            "install_dir": self.install_dir,
            "heat_dir": self.heat_dir,
            "api_image": self.api_container_image,
            "engine_image": self.engine_container_image,
            "heat_pod_name": EPHEMERAL_HEAT_POD_NAME
        }
        heat_pod = heat_pod_tmpl.render(**pod_vars)

        heat_pod_path = os.path.join(self.heat_dir, "heat-pod.yaml")
        with open(heat_pod_path, 'w') as conf:
            conf.write(heat_pod)
