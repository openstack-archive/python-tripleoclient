#   Copyright 2021 Red Hat, Inc.
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

import fixtures
import mock
import os
from pathlib import Path
import shutil
import subprocess
import time

from tripleoclient import constants
from tripleoclient import heat_launcher
from tripleoclient.exceptions import HeatPodMessageQueueException
from tripleoclient.tests import base
from tripleoclient import utils


class TestHeatPodLauncher(base.TestCase):
    def setUp(self):
        super(TestHeatPodLauncher, self).setUp()
        self.run = mock.patch('subprocess.run').start()
        self.call = mock.patch('subprocess.call').start()
        self.check_call = mock.patch('subprocess.check_call').start()
        self.check_output = mock.patch('subprocess.check_output').start()
        self.templates_dir = mock.patch(
            'tripleoclient.heat_launcher.DEFAULT_TEMPLATES_DIR',
            os.path.join(os.path.dirname(__file__),
                         '..', '..', 'templates')).start()
        self.heat_dir = self.useFixture(fixtures.TempDir()).path

        self.addCleanup(mock.patch.stopall)

    def get_launcher(self, **kwargs):
        return heat_launcher.HeatPodLauncher(
                heat_dir=self.heat_dir,
                use_tmp_dir=False,
                **kwargs)

    def check_calls(self, check_call, mock_obj):
        for call in mock_obj.call_args_list:
            call_str = ' '.join(call.args[0])
            if check_call in call_str:
                return True
        return False

    def test_rm_heat_launcher(self):
        self.assertIsInstance(self.get_launcher(rm_heat=True),
                              heat_launcher.HeatPodLauncher)

    def test_chcon(self):
        launcher = self.get_launcher()
        launcher._chcon()
        self.check_calls('chcon', self.check_call)
        self.check_calls(launcher.heat_dir, self.check_call)

    def test_fetch_container_image(self):
        launcher = self.get_launcher(skip_heat_pull=True)
        launcher._fetch_container_image()
        self.assertFalse(self.check_calls('podman pull', self.check_output))

        # With skip_heat_pull=False, this should try and run the command to
        # pull the default images from quay.io
        launcher = self.get_launcher(skip_heat_pull=False)
        launcher._fetch_container_image()
        self.assertTrue(self.check_calls('podman pull', self.check_output))

        # With skip_heat_pull=False, but using the default ephemeral heat
        # container images, this should still skip the command to run the pull
        launcher = self.get_launcher(skip_heat_pull=False)
        launcher.api_container_image = \
            constants.DEFAULT_EPHEMERAL_HEAT_API_CONTAINER
        launcher.engine_container_image = \
            constants.DEFAULT_EPHEMERAL_HEAT_ENGINE_CONTAINER
        self.check_output.reset_mock()
        launcher._fetch_container_image()
        self.check_output.assert_not_called()

    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher._decode')
    def test_get_pod_state(self, mock_decode):
        launcher = self.get_launcher()
        launcher.get_pod_state()
        self.check_calls('podman pod inspect', self.run)
        self.assertTrue(mock_decode.called)

    @mock.patch(
        'tripleoclient.heat_launcher.HeatPodLauncher._write_heat_config')
    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher._write_heat_pod')
    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher.get_pod_state')
    def test_lauch_heat(
            self, mock_get_pod_state, mock_write_heat_pod,
            mock_write_heat_config):

        launcher = self.get_launcher()

        mock_get_pod_state.return_value = 'Running'
        launcher.launch_heat()
        self.assertFalse(mock_write_heat_pod.called)
        self.assertFalse(self.check_calls('podman play kube', self.check_call))

        mock_get_pod_state.return_value = 'Exited'
        launcher.launch_heat()
        self.assertTrue(mock_write_heat_pod.called)
        self.assertTrue(self.check_calls('podman play kube', self.check_call))

        mock_get_pod_state.return_value = ''
        launcher.launch_heat()
        self.assertTrue(mock_write_heat_pod.called)
        self.assertTrue(self.check_calls('podman play kube', self.check_call))

    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher.do_restore_db')
    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher.database_exists')
    def test_heat_db_sync(
            self, mock_db_exists, mock_do_restore_db):

        launcher = self.get_launcher()
        mock_db_exists.return_value = True
        launcher.heat_db_sync(restore_db=False)
        self.assertFalse(self.check_calls('create database', self.check_call))
        self.assertFalse(self.check_calls('create user', self.check_call))
        self.assertFalse(self.check_calls('grant all', self.check_call))
        self.assertFalse(self.check_calls('flush priv', self.check_call))
        self.assertTrue(self.check_calls('heat-manage', self.check_call))
        self.assertFalse(mock_do_restore_db.called)

        self.check_call.reset_mock()

        mock_db_exists.return_value = True
        launcher.heat_db_sync(restore_db=True)
        self.assertFalse(self.check_calls('create database', self.check_call))
        self.assertFalse(self.check_calls('create user', self.check_call))
        self.assertFalse(self.check_calls('grant all', self.check_call))
        self.assertFalse(self.check_calls('flush priv', self.check_call))
        self.assertTrue(self.check_calls('heat-manage', self.check_call))
        self.assertTrue(mock_do_restore_db.called)

        self.check_call.reset_mock()
        mock_db_exists.return_value = False
        launcher.heat_db_sync(restore_db=True)
        self.assertTrue(self.check_calls('create database', self.check_call))
        self.assertTrue(self.check_calls('create user', self.check_call))
        self.assertTrue(self.check_calls('grant all', self.check_call))
        self.assertTrue(self.check_calls('flush priv', self.check_call))
        self.assertTrue(self.check_calls('heat-manage', self.check_call))
        self.assertTrue(mock_do_restore_db.called)

        self.check_call.reset_mock()
        mock_do_restore_db.reset_mock()
        mock_db_exists.return_value = False
        launcher.heat_db_sync(restore_db=False)
        self.assertTrue(self.check_calls('create database', self.check_call))
        self.assertTrue(self.check_calls('create user', self.check_call))
        self.assertTrue(self.check_calls('grant all', self.check_call))
        self.assertTrue(self.check_calls('flush priv', self.check_call))
        self.assertTrue(self.check_calls('heat-manage', self.check_call))
        self.assertFalse(mock_do_restore_db.called)

    @mock.patch('os.unlink')
    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher.untar_file')
    @mock.patch('glob.glob')
    def test_do_restore_db(
            self, mock_glob, mock_untar, mock_unlink):

        launcher = self.get_launcher()

        one = Path(os.path.join(launcher.heat_dir,
                                'heat-db-dump-one.tar.bz2'))
        two = Path(os.path.join(launcher.heat_dir,
                                'heat-db-dump-two.tar.bz2'))
        three = Path(os.path.join(launcher.heat_dir,
                                  'heat-db-dump-three.tar.bz2'))

        now = time.time()
        one.touch()
        two.touch()
        three.touch()
        os.utime(str(one), (now, 1000))
        os.utime(str(two), (now, 2000))
        os.utime(str(three), (now, 3000))
        mock_glob.return_value = [str(one), str(two), str(three)]

        def untar(path, dir):
            p = Path(path.rstrip('.tar.bz2'))
            p.touch()

        mock_untar.side_effect = untar

        mock_open = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open):
            # pylint: disable=bad-str-strip-call
            launcher.do_restore_db()
            self.assertEqual(mock.call(str(three), launcher.heat_dir),
                             mock_untar.call_args)
            self.assertEqual(mock.call(launcher.heat_dir + '/heat-db.sql'),
                             mock_unlink.call_args)
            mock_open.assert_called_with(launcher.heat_dir + '/heat-db.sql') # noqa
            self.assertTrue(self.check_call('mysql heat', self.run))

        mock_unlink.reset_mock()
        self.run.reset_mock()
        two.touch()
        mock_open = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open):
            # pylint: disable=bad-str-strip-call
            launcher.do_restore_db()
            self.assertEqual(mock.call(str(two), launcher.heat_dir),
                             mock_untar.call_args)
            self.assertEqual(mock.call(launcher.heat_dir + '/heat-db.sql'),
                             mock_unlink.call_args)
            mock_open.assert_called_with(launcher.heat_dir + '/heat-db.sql') # noqa
            self.assertTrue(self.check_call('mysql heat', self.run))

    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher.tar_file')
    def test_do_backup_db(self, mock_tar):
        launcher = self.get_launcher()
        p = Path(os.path.join(launcher.heat_dir, 'heat-db.sql'))
        p.touch()
        self.assertRaises(Exception, launcher.do_backup_db, str(p))

        p.unlink()
        launcher.do_backup_db()
        mock_tar.assert_called_with(str(p))
        self.assertTrue(self.check_calls('mysqldump heat', self.run))

    def test_pod_exists(self):
        launcher = self.get_launcher()
        self.assertTrue(launcher.pod_exists())
        self.check_calls('pod inspect', self.check_call)

        self.check_call.reset_mock()
        self.check_call.side_effect = subprocess.CalledProcessError(1, 'test')
        self.assertFalse(launcher.pod_exists())
        self.check_calls('pod inspect', self.check_call)

    @mock.patch('os.path.exists')
    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher.tar_file')
    @mock.patch(
        'tripleoclient.heat_launcher.HeatPodLauncher._read_heat_config')
    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher.pod_exists')
    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher.do_backup_db')
    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher.database_exists')
    def test_rm_heat(self, mock_db_exists, mock_backup_db, mock_pod_exists,
                     mock_read_heat_config, mock_tar, mock_exists):

        launcher = self.get_launcher()
        launcher.log_dir = '/log'

        mock_db_exists.return_value = True
        mock_pod_exists.return_value = True
        mock_exists.return_value = True
        mock_read_heat_config.return_value = {
            'DEFAULT': {
                'log_file': 'heat-log'}}
        launcher.rm_heat()
        mock_backup_db.assert_called()
        self.check_calls('drop database heat', self.check_call)
        self.check_calls('drop user', self.check_call)
        mock_pod_exists.assert_called()
        self.check_calls('podman pod rm -f', self.call)
        mock_read_heat_config.assert_called()
        mock_tar.assert_called_with('/log/heat-log')

        mock_backup_db.reset_mock()
        self.call.reset_mock()
        mock_tar.reset_mock()
        mock_db_exists.return_value = False
        mock_pod_exists.return_value = False
        mock_exists.return_value = False
        launcher.rm_heat()
        mock_backup_db.assert_not_called()
        self.call.assert_not_called()
        mock_tar.assert_not_called()

        mock_backup_db.reset_mock()
        self.call.reset_mock()
        mock_tar.reset_mock()
        mock_exists.reset_mock()
        mock_db_exists.return_value = False
        mock_pod_exists.return_value = True
        mock_exists.return_value = True
        launcher.rm_heat(backup_db=False)
        mock_backup_db.assert_not_called()
        self.check_calls('podman pod rm -f', self.call)

    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher.get_pod_state')
    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher.pod_exists')
    def test_stop_heat(self, mock_pod_exists, mock_pod_state):
        launcher = self.get_launcher()
        mock_pod_exists.return_value = True
        mock_pod_state.return_value = 'Running'
        launcher.stop_heat()
        mock_pod_exists.assert_called()
        mock_pod_state.assert_called()
        self.check_calls('podman pod stop', self.check_call)

        self.check_call.reset_mock()
        mock_pod_exists.reset_mock()
        mock_pod_state.reset_mock()
        mock_pod_state.return_value = 'Exited'
        mock_pod_exists.return_value = True
        launcher.stop_heat()
        mock_pod_exists.assert_called()
        mock_pod_state.assert_called()
        self.check_call.assert_not_called()

        self.check_call.reset_mock()
        mock_pod_exists.reset_mock()
        mock_pod_state.reset_mock()
        mock_pod_state.return_value = 'Exited'
        mock_pod_exists.return_value = False
        launcher.stop_heat()
        mock_pod_exists.assert_called()
        mock_pod_state.assert_not_called()
        self.check_call.assert_not_called()

    def test_check_message_bus(self):
        launcher = self.get_launcher()
        launcher.check_message_bus()
        self.check_calls('rabbitmqctl list_queues', self.check_call)

        self.check_call.reset_mock()
        self.check_call.side_effect = subprocess.CalledProcessError(1, 'test')
        self.assertRaises(subprocess.CalledProcessError,
                          launcher.check_message_bus)

    @mock.patch(
        'tripleoclient.heat_launcher.HeatPodLauncher._get_ctlplane_ip')
    def test_check_database(self, mock_ctlplane_ip):
        launcher = self.get_launcher()

        mock_ctlplane_ip.return_value = '1.1.1.1'
        self.assertTrue(launcher.check_database())
        mock_ctlplane_ip.assert_called()
        self.check_calls('show databases', self.check_call)

        self.check_call.reset_mock()
        mock_ctlplane_ip.reset_mock()
        self.check_call.side_effect = subprocess.CalledProcessError(1, '/test')
        self.assertRaises(subprocess.CalledProcessError,
                          launcher.check_database)

    def test_database_exists(self):
        launcher = self.get_launcher()
        self.check_output.return_value = 'heat'
        self.assertTrue(launcher.database_exists())
        self.check_calls('show databases like "heat"', self.check_output)

        self.check_output.reset_mock()
        self.check_output.return_value = 'nova'
        self.assertFalse(launcher.database_exists())
        self.check_calls('show databases like "heat"', self.check_output)

    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher.pod_exists')
    def test_kill_heat(self, mock_pod_exists):
        launcher = self.get_launcher()
        mock_pod_exists.return_value = True
        launcher.kill_heat(0)
        self.check_calls('podman pod kill', self.call)
        mock_pod_exists.assert_called()

        mock_pod_exists.reset_mock()
        self.call.reset_mock()
        mock_pod_exists.return_value = False
        launcher.kill_heat(0)
        mock_pod_exists.assert_called()
        self.call.assert_not_called()

    def test_decode(self):
        launcher = self.get_launcher()
        mock_encoded = mock.Mock()
        mock_decoded = mock.Mock()
        mock_encoded.decode.return_value = mock_decoded
        mock_decoded.endswith.return_value = False
        launcher._decode(mock_encoded)
        mock_encoded.decode.assert_called_with('utf-8')

        self.assertEqual('test', launcher._decode(b'test\n'))

    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher._decode')
    def test_get_transport_url(self, mock_decode):
        launcher = self.get_launcher()
        mock_decode.side_effect = ['user', 'password', 'fqdn_ctlplane', 'port']
        self.assertEqual("rabbit://user:password@fqdn_ctlplane:port/?ssl=0",
                         launcher._get_transport_url())

    @mock.patch(
        'tripleoclient.heat_launcher.HeatPodLauncher._get_ctlplane_vip')
    def test_get_db_connection(self, mock_ctlplane_vip):
        launcher = self.get_launcher()
        mock_ctlplane_vip.return_value = '1.1.1.1'
        self.assertEqual(
            'mysql+pymysql://'
            'heat:heat@1.1.1.1/heat?read_default_file='
            '/etc/my.cnf.d/tripleo.cnf&read_default_group=tripleo',
            launcher._get_db_connection())

    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher._decode')
    def test_get_ctlplane_vip(self, mock_decode):
        launcher = self.get_launcher()
        self.check_output.return_value = '1.1.1.1'
        launcher._get_ctlplane_vip()
        self.check_calls('sudo hiera controller_virtual_ip', self.check_output)
        mock_decode.assert_called_with('1.1.1.1')

    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher._decode')
    def test_get_ctlplane_ip(self, mock_decode):
        launcher = self.get_launcher()
        self.check_output.return_value = '1.1.1.1'
        launcher._get_ctlplane_ip()
        self.check_calls('sudo hiera ctlplane', self.check_output)
        mock_decode.assert_called_with('1.1.1.1')

    @mock.patch('multiprocessing.cpu_count')
    def test_get_num_engine_workers(self, mock_cpu_count):
        launcher = self.get_launcher()
        mock_cpu_count.return_value = 4
        self.assertEqual(2, launcher._get_num_engine_workers())

    def test_wait_for_message_queue(self):
        launcher = self.get_launcher()
        wait_mq = launcher.wait_for_message_queue.__wrapped__
        self.check_output.return_value = 'engine.ephemeral-heat'
        wait_mq(launcher)

        self.check_output.reset_mock()
        self.check_output.return_value = 'heat-listener'
        self.assertRaises(HeatPodMessageQueueException, wait_mq, launcher)

    def test_get_log_file_path(self):
        launcher = self.get_launcher()
        launcher.timestamp = '1111'
        self.assertEqual('heat-1111.log', launcher._get_log_file_path())

    @mock.patch('configparser.ConfigParser')
    def test_read_heat_config(self, mock_config_parser):
        launcher = self.get_launcher()
        mock_cp = mock.Mock()
        mock_cp.read.return_value = 'test'
        mock_config_parser.return_value = mock_cp
        self.assertEqual(mock_cp, launcher._read_heat_config())
        mock_config_parser.assert_called()
        mock_cp.read.assert_called_with(launcher.config_file)

    @mock.patch('tripleoclient.heat_launcher.'
                'HeatPodLauncher._get_num_engine_workers')
    @mock.patch(
        'tripleoclient.heat_launcher.HeatPodLauncher._get_db_connection')
    @mock.patch(
        'tripleoclient.heat_launcher.HeatPodLauncher._get_transport_url')
    def test_write_heat_config(self, mock_get_transport_url, mock_get_db_conn,
                               mock_num_engine_workers):
        launcher = self.get_launcher()
        launcher.api_port = '1234'
        launcher.log_file = '/log/heat'
        mock_get_transport_url.return_value = 'transport-url'
        mock_get_db_conn.return_value = 'db-connection'
        mock_num_engine_workers.return_value = 'num-engine-workers'
        launcher._write_heat_config()
        with open(launcher.config_file) as f:
            config = f.read()
            self.assertIn('num_engine_workers = num-engine-workers\n', config)
            self.assertIn('connection = db-connection\n', config)
            self.assertIn('transport_url=transport-url\n', config)
            self.assertIn('bind_port = 1234\n', config)
            self.assertIn('log_file = /log/heat\n', config)

    def test_write_heat_pod(self):
        launcher = self.get_launcher()
        launcher.install_dir = 'install-dir'
        launcher.host = '1.1.1.1'
        launcher.api_port = '1234'
        launcher.api_container_image = 'api-image'
        launcher.engine_container_image = 'engine-image'
        launcher._write_heat_pod()
        with open(os.path.join(launcher.heat_dir, 'heat-pod.yaml')) as f:
            pod = f.read()
            self.assertIn('hostPort: 1234', pod)
            self.assertIn('hostIP: 1.1.1.1', pod)
            self.assertIn('image: api-image', pod)
            self.assertIn('image: engine-image', pod)


class TestHeatPodLauncherUtils(base.TestCase):
    def setUp(self):
        super(TestHeatPodLauncherUtils, self).setUp()

    def test_rm_heat(self):
        launcher = mock.Mock()
        utils.rm_heat(launcher)
        launcher.rm_heat.assert_called_once_with(False)
        launcher.reset_mock()
        utils.rm_heat(launcher, True)
        launcher.rm_heat.assert_called_once_with(True)
        launcher.reset_mock()
        utils.rm_heat(launcher, False)
        launcher.rm_heat.assert_called_once_with(False)

    def test_kill_heat(self):
        launcher = mock.Mock()
        utils.kill_heat(launcher)
        launcher.kill_heat.assert_called_once_with(None)
        launcher.reset_mock()
        utils._heat_pid = 111
        utils.kill_heat(launcher)
        launcher.kill_heat.assert_called_once_with(111)
        launcher.reset_mock()
        utils.kill_heat(launcher)
        launcher.kill_heat.assert_called_once_with(111)
        launcher.reset_mock()
        utils.kill_heat(launcher)
        launcher.kill_heat.assert_called_once_with(111)

    @mock.patch('tripleoclient.heat_launcher.HeatPodLauncher')
    @mock.patch('tripleoclient.heat_launcher.HeatNativeLauncher')
    @mock.patch('tripleoclient.heat_launcher.HeatContainerLauncher')
    def test_get_heat_launcher(self, mock_container, mock_native, mock_pod):
        utils.get_heat_launcher('pod', 1, 2, 3, a='a', b='b', c='c')
        mock_pod.assert_called_once_with(1, 2, 3, a='a', b='b', c='c')
        utils.get_heat_launcher('native', 1, 2, 3, a='a', b='b', c='c')
        mock_native.assert_called_once_with(1, 2, 3, a='a', b='b', c='c')
        utils.get_heat_launcher('container', 1, 2, 3, a='a', b='b', c='c')
        mock_container.assert_called_once_with(1, 2, 3, a='a', b='b', c='c')

    def test_heat_api_port(self):
        test_port = utils.test_heat_api_port.__wrapped__
        mock_socket = mock.Mock()
        host = '1.1.1.1'
        port = 1234
        test_port(mock_socket, host, port)
        mock_socket.connect.assert_called_once_with((host, port))

    @mock.patch('tripleoclient.utils.test_heat_api_port')
    @mock.patch('tripleo_common.utils.heat.local_orchestration_client')
    @mock.patch('socket.socket')
    @mock.patch('tripleoclient.utils.get_heat_launcher')
    def test_launch_heat(self, mock_get_heat_launcher, mock_socket,
                         mock_local_client, mock_test_port):
        utils._local_orchestration_client = 'client'
        self.assertEqual('client', utils.launch_heat())
        mock_get_heat_launcher.assert_not_called()

        utils._local_orchestration_client = None
        mock_launcher = mock.Mock()
        mock_launcher.api_port = 1234
        mock_get_heat_launcher.return_value = mock_launcher
        mock_socket.return_value = 'socket'
        utils.launch_heat()
        mock_get_heat_launcher.assert_called_once()
        mock_launcher.check_database.assert_called_once_with()
        mock_launcher.check_message_bus.assert_called_once_with()
        mock_launcher.heat_db_sync.assert_called_once_with(False)
        mock_launcher.launch_heat.assert_called_once_with()
        mock_test_port.assert_called_once_with(
            'socket', mock_launcher.host,
            int(mock_launcher.api_port))
        mock_launcher.wait_for_message_queue.assert_called_once_with()
        mock_local_client.assert_called_once_with(
            mock_launcher.host,
            mock_launcher.api_port)


class TestHeatNativeLauncher(base.TestCase):
    def setUp(self):
        super(TestHeatNativeLauncher, self).setUp()
        self.run = mock.patch('subprocess.run').start()
        self.popen = mock.patch('subprocess.Popen').start()
        self.mock_popen = mock.Mock()
        self.mock_popen.communicate.return_value = ("", "")
        self.popen.return_value = self.mock_popen
        self.getpwnam = mock.patch('pwd.getpwnam').start()
        self.getgrnam = mock.patch('grp.getgrnam').start()
        self.chown = mock.patch('os.chown').start()

        self.templates_dir = mock.patch(
            'tripleoclient.heat_launcher.DEFAULT_TEMPLATES_DIR',
            os.path.join(os.path.dirname(__file__),
                         '..', '..', 'templates')).start()
        self.heat_dir = self.useFixture(fixtures.TempDir()).path
        self.tmp_dir = self.useFixture(fixtures.TempDir()).path

        self.addCleanup(mock.patch.stopall)

    def get_launcher(self, **kwargs):
        return heat_launcher.HeatNativeLauncher(
                heat_dir=self.heat_dir,
                use_tmp_dir=True,
                use_root=True,
                **kwargs)

    def test_heat_dir_no_exist(self):
        shutil.rmtree(self.heat_dir)
        launcher = self.get_launcher()
        self.assertNotEqual(self.heat_dir, launcher.install_dir)

    @mock.patch('tempfile.mkdtemp')
    def test_get_launcher(self, mock_mkdtemp):
        mock_mkdtemp.return_value = self.tmp_dir

        def test_install_dir():
            mock_mkdtemp.assert_not_called()
            return ("", "")

        # Test that tempfile.mkdtemp is *not* called before the tmpfs is setup,
        # otherwise the tmpfs will cause the temp dir to be lost
        self.mock_popen.communicate.side_effect = test_install_dir
        self.get_launcher()
