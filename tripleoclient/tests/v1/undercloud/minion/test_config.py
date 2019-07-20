#   Copyright 2019 Red Hat, Inc.
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
import mock
import sys
import tempfile
import yaml

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture

from tripleo_common.image import kolla_builder

from tripleoclient.tests import base
from tripleoclient.v1 import minion_config


class TestMinionDeploy(base.TestCase):
    def setUp(self):
        super(TestMinionDeploy, self).setUp()
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        self.conf.set_default('output_dir', '/home/stack')
        # set timezone so we don't have to mock it everywhere
        self.conf.set_default('minion_timezone', 'UTC')

    @mock.patch('tripleoclient.v1.minion_config._process_undercloud_passwords')
    @mock.patch('tripleoclient.v1.undercloud_preflight.minion_check')
    @mock.patch('os.makedirs', return_value=None)
    @mock.patch('tripleoclient.v1.minion_config._process_undercloud_output',
                return_value='output.yaml')
    @mock.patch('tripleoclient.v1.minion_config._container_images_config')
    @mock.patch('tripleoclient.utils.write_env_file')
    @mock.patch('tripleoclient.utils.get_deployment_user')
    @mock.patch('tripleoclient.utils.load_config')
    def test_basic_deploy(self, mock_load_config, mock_get_user,
                          mock_write_env, mock_undercloud_output,
                          mock_images_config, mock_isdir,
                          mock_check, mock_pass):
        mock_get_user.return_value = 'foo'
        cmd = minion_config.prepare_minion_deploy()
        expected_cmd = ['sudo', '--preserve-env',
                        'openstack', 'tripleo', 'deploy',
                        '--standalone', '--standalone-role',
                        'UndercloudMinion', '--stack', 'minion',
                        '-r',
                        '/usr/share/openstack-tripleo-heat-templates/roles/'
                        'UndercloudMinion.yaml',
                        '--local-ip=192.168.24.50/24',
                        '--templates='
                        '/usr/share/openstack-tripleo-heat-templates/',
                        '--networks-file=network_data_undercloud.yaml',
                        '-e', 'output.yaml',
                        '--heat-native',
                        '-e', '/usr/share/openstack-tripleo-heat-templates/'
                        'environments/undercloud/undercloud-minion.yaml',
                        '-e', '/usr/share/openstack-tripleo-heat-templates/'
                        'environments/use-dns-for-vips.yaml',
                        '-e', '/usr/share/openstack-tripleo-heat-templates/'
                        'environments/podman.yaml',
                        '-e', '/usr/share/openstack-tripleo-heat-templates/'
                        'environments/services/heat-engine.yaml',
                        '--deployment-user', 'foo',
                        '--output-dir=/home/stack',
                        '-e', '/home/stack/tripleo-config-generated-env-files/'
                        'minion_parameters.yaml',
                        '--log-file=install-minion.log',
                        '-e', '/usr/share/openstack-tripleo-heat-templates/'
                        'minion-stack-vstate-dropin.yaml']
        self.assertEqual(expected_cmd, cmd)
        env_data = {
            'PythonInterpreter': sys.executable,
            'ContainerImagePrepareDebug': True,
            'Debug': True,
            'UndercloudMinionLocalMtu': 1500,
            'ContainerHealthcheckDisabled': False,
            'NeutronPublicInterface': 'eth1',
            'SELinuxMode': 'enforcing',
            'NtpServer': ['0.pool.ntp.org',
                          '1.pool.ntp.org',
                          '2.pool.ntp.org',
                          '3.pool.ntp.org'],
            'TimeZone': 'UTC',
            'DockerInsecureRegistryAddress': ['192.168.24.50:8787'],
            'ContainerCli': 'podman',
            'LocalContainerRegistry': '192.168.24.50',
            'DeploymentUser': 'foo'}
        mock_write_env.assert_called_once_with(
           env_data, '/home/stack/tripleo-config-generated-env-files/'
           'minion_parameters.yaml', {})

    @mock.patch('tripleoclient.v1.minion_config._process_undercloud_passwords')
    @mock.patch('tripleoclient.v1.undercloud_preflight.minion_check')
    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('os.makedirs', return_value=None)
    @mock.patch('tripleoclient.v1.minion_config._process_undercloud_output',
                return_value='output.yaml')
    @mock.patch('tripleoclient.v1.minion_config._container_images_config')
    @mock.patch('tripleoclient.utils.write_env_file')
    @mock.patch('tripleoclient.utils.load_config')
    def test_configured_deploy(self, mock_load_config,
                               mock_write_env, mock_undercloud_output,
                               mock_images_config, mock_isdir, mock_exists,
                               mock_check, mock_pass):
        self.conf.set_default('deployment_user', 'bar')
        self.conf.set_default('enable_heat_engine', False)
        self.conf.set_default('enable_ironic_conductor', True)
        self.conf.set_default('hieradata_override', '/data.yaml')
        self.conf.set_default('minion_debug', False)
        self.conf.set_default('minion_enable_selinux', False)
        self.conf.set_default('minion_local_interface', 'enp0s4')
        self.conf.set_default('minion_local_ip', '1.1.1.1/24')
        self.conf.set_default('minion_local_mtu', '1350')
        self.conf.set_default('minion_ntp_servers', ['pool.ntp.org'])
        self.conf.set_default('networks_file', 'network.yaml')
        self.conf.set_default('output_dir', '/bar')
        self.conf.set_default('templates', '/foo')
        cmd = minion_config.prepare_minion_deploy()
        expected_cmd = ['sudo', '--preserve-env',
                        'openstack', 'tripleo', 'deploy',
                        '--standalone', '--standalone-role',
                        'UndercloudMinion', '--stack', 'minion',
                        '-r', '/foo/roles/UndercloudMinion.yaml',
                        '--local-ip=1.1.1.1/24',
                        '--templates=/foo',
                        '--networks-file=network.yaml',
                        '-e', 'output.yaml',
                        '--heat-native',
                        '-e', '/foo/environments/undercloud/'
                        'undercloud-minion.yaml',
                        '-e', '/foo/environments/use-dns-for-vips.yaml',
                        '-e', '/foo/environments/podman.yaml',
                        '-e', '/foo/environments/services/'
                        'ironic-conductor.yaml',
                        '--deployment-user', 'bar',
                        '--output-dir=/bar',
                        '-e', '/bar/tripleo-config-generated-env-files/'
                        'minion_parameters.yaml',
                        '--hieradata-override=/data.yaml',
                        '--log-file=install-minion.log',
                        '-e', '/foo/minion-stack-vstate-dropin.yaml']
        self.assertEqual(expected_cmd, cmd)
        env_data = {
            'PythonInterpreter': sys.executable,
            'ContainerImagePrepareDebug': False,
            'Debug': False,
            'UndercloudMinionLocalMtu': 1350,
            'ContainerHealthcheckDisabled': False,
            'NeutronPublicInterface': 'enp0s4',
            'SELinuxMode': 'permissive',
            'NtpServer': ['pool.ntp.org'],
            'TimeZone': 'UTC',
            'DockerInsecureRegistryAddress': ['1.1.1.1:8787'],
            'ContainerCli': 'podman',
            'LocalContainerRegistry': '1.1.1.1',
            'DeploymentUser': 'bar'}
        mock_write_env.assert_called_once_with(
           env_data, '/bar/tripleo-config-generated-env-files/'
           'minion_parameters.yaml', {})


class TestMinionContainerImageConfig(base.TestCase):
    def setUp(self):
        super(TestMinionContainerImageConfig, self).setUp()
        conf_keys = (
            'container_images_file',
        )
        self.conf = mock.Mock(**{key: getattr(minion_config.CONF, key)
                                 for key in conf_keys})

    @mock.patch('shutil.copy')
    def test_defaults(self, mock_copy):
        env = {}
        deploy_args = []
        cip_default = getattr(kolla_builder,
                              'CONTAINER_IMAGE_PREPARE_PARAM', None)
        self.addCleanup(setattr, kolla_builder,
                        'CONTAINER_IMAGE_PREPARE_PARAM', cip_default)

        setattr(kolla_builder, 'CONTAINER_IMAGE_PREPARE_PARAM', [{
            'set': {
                'namespace': 'one',
                'name_prefix': 'two',
                'name_suffix': 'three',
                'tag': 'four',
            },
            'tag_from_label': 'five',
        }])

        minion_config._container_images_config(self.conf, deploy_args,
                                               env, None)
        self.assertEqual([], deploy_args)
        cip = env['ContainerImagePrepare'][0]
        set = cip['set']

        self.assertEqual(
            'one', set['namespace'])
        self.assertEqual(
            'two', set['name_prefix'])
        self.assertEqual(
            'three', set['name_suffix'])
        self.assertEqual(
            'four', set['tag'])
        self.assertEqual(
            'five', cip['tag_from_label'])

    @mock.patch('shutil.copy')
    def test_container_images_file(self, mock_copy):
        env = {}
        deploy_args = []
        self.conf.container_images_file = '/tmp/container_images_file.yaml'
        minion_config._container_images_config(self.conf, deploy_args,
                                               env, None)
        self.assertEqual(['-e', '/tmp/container_images_file.yaml'],
                         deploy_args)
        self.assertEqual({}, env)

    @mock.patch('shutil.copy')
    def test_custom(self, mock_copy):
        env = {}
        deploy_args = []
        with tempfile.NamedTemporaryFile(mode='w') as f:
            yaml.dump({
                'parameter_defaults': {'ContainerImagePrepare': [{
                    'set': {
                        'namespace': 'one',
                        'name_prefix': 'two',
                        'name_suffix': 'three',
                        'tag': 'four',
                    },
                    'tag_from_label': 'five',
                }]}
            }, f)
            self.conf.container_images_file = f.name
            cif_name = f.name

            minion_config._container_images_config(
                self.conf, deploy_args, env, None)
        self.assertEqual(['-e', cif_name], deploy_args)
