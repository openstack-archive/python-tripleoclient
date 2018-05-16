#   Copyright 2015 Red Hat, Inc.
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
import os
import tempfile
import yaml

from heatclient import exc as hc_exc
from tripleo_common.image import kolla_builder

from tripleoclient import exceptions
from tripleoclient.tests.v1.test_plugin import TestPluginV1

# Load the plugin init module for the plugin list and show commands
from tripleoclient.v1 import tripleo_deploy

# TODO(sbaker) Remove after a tripleo-common release contains this new function
if not hasattr(kolla_builder, 'container_images_prepare_multi'):
    setattr(kolla_builder, 'container_images_prepare_multi', mock.Mock())


class FakePluginV1Client(object):
    def __init__(self, **kwargs):
        self.auth_token = kwargs['token']
        self.management_url = kwargs['endpoint']


class TestDeployUndercloud(TestPluginV1):

    def setUp(self):
        super(TestDeployUndercloud, self).setUp()

        # Get the command object to test
        self.cmd = tripleo_deploy.Deploy(self.app, None)

        tripleo_deploy.Deploy.heat_pid = mock.MagicMock(
            return_value=False)
        tripleo_deploy.Deploy.tht_render = '/twd/templates'
        tripleo_deploy.Deploy.tmp_env_file_name = 'tmp/foo'
        tripleo_deploy.Deploy.heat_launch = mock.MagicMock(
            side_effect=(lambda *x, **y: None))

        self.tc = self.app.client_manager.tripleoclient = mock.MagicMock()
        self.orc = self.tc.local_orchestration = mock.MagicMock()
        self.orc.stacks.create = mock.MagicMock(
            return_value={'stack': {'id': 'foo'}})

    @mock.patch('os.chmod')
    @mock.patch('os.path.exists')
    @mock.patch('tripleo_common.utils.passwords.generate_passwords')
    @mock.patch('yaml.safe_dump')
    def test_update_passwords_env_init(self, mock_dump, mock_pw,
                                       mock_exists, mock_chmod):
        pw_dict = {"GeneratedPassword": 123}
        pw_conf_path = os.path.join(self.temp_homedir,
                                    'undercloud-passwords.conf')
        t_pw_conf_path = os.path.join(
            self.temp_homedir, 'tripleo-undercloud-passwords.yaml')

        mock_pw.return_value = pw_dict
        mock_exists.return_value = False

        mock_open_context = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open_context):
            self.cmd._update_passwords_env(self.temp_homedir)

        mock_open_handle = mock_open_context()
        mock_dump.assert_called_once_with({'parameter_defaults': pw_dict},
                                          mock_open_handle,
                                          default_flow_style=False)
        chmod_calls = [mock.call(t_pw_conf_path, 0o600),
                       mock.call(pw_conf_path, 0o600)]
        mock_chmod.assert_has_calls(chmod_calls)

    @mock.patch('os.chmod')
    @mock.patch('os.path.exists')
    @mock.patch('tripleo_common.utils.passwords.generate_passwords')
    @mock.patch('yaml.safe_dump')
    def test_update_passwords_env_update(self, mock_dump, mock_pw,
                                         mock_exists, mock_chmod):
        pw_dict = {"GeneratedPassword": 123}
        pw_conf_path = os.path.join(self.temp_homedir,
                                    'undercloud-passwords.conf')
        t_pw_conf_path = os.path.join(
            self.temp_homedir, 'tripleo-undercloud-passwords.yaml')

        mock_pw.return_value = pw_dict
        mock_exists.return_value = True
        with open(t_pw_conf_path, 'w') as t_pw:
            t_pw.write('parameter_defaults: {ExistingKey: xyz}\n')

        with open(pw_conf_path, 'w') as t_pw:
            t_pw.write('[auth]\nundercloud_db_password = abc\n')

        self.cmd._update_passwords_env(self.temp_homedir,
                                       passwords={'ADefault': 456,
                                                  'ExistingKey':
                                                  'dontupdate'})
        expected_dict = {'parameter_defaults': {'GeneratedPassword': 123,
                                                'ExistingKey': 'xyz',
                                                'MysqlRootPassword': 'abc',
                                                'ADefault': 456}}
        mock_dump.assert_called_once_with(expected_dict,
                                          mock.ANY,
                                          default_flow_style=False)
        chmod_calls = [mock.call(t_pw_conf_path, 0o600),
                       mock.call(pw_conf_path, 0o600)]
        mock_chmod.assert_has_calls(chmod_calls)

    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', return_value=({}, {}),
                autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'get_template_contents', return_value=({}, {}),
                autospec=True)
    @mock.patch('heatclient.common.environment_format.'
                'parse', autospec=True, return_value=dict())
    @mock.patch('heatclient.common.template_format.'
                'parse', autospec=True, return_value=dict())
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_setup_heat_environments', autospec=True)
    @mock.patch('tripleo_common.image.kolla_builder.'
                'container_images_prepare_multi')
    def test_deploy_tripleo_heat_templates_redir(self,
                                                 mock_cipm,
                                                 mock_setup_heat_envs,
                                                 mock_hc_templ_parse,
                                                 mock_hc_env_parse,
                                                 mock_hc_get_templ_cont,
                                                 mock_hc_process):

        with tempfile.NamedTemporaryFile(delete=False) as roles_file:
            self.addCleanup(os.unlink, roles_file.name)

        mock_cipm.return_value = {}

        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8',
                                         '--templates', '/tmp/thtroot',
                                         '--roles-file', roles_file.name], [])

        mock_setup_heat_envs.return_value = [
            './inside.yaml', '/tmp/thtroot/abs.yaml',
            '/tmp/thtroot/puppet/foo.yaml',
            '/tmp/thtroot/environments/myenv.yaml',
            '/tmp/thtroot42/notouch.yaml',
            '../outside.yaml']

        self.cmd._deploy_tripleo_heat_templates(self.orc, parsed_args)

        mock_hc_process.assert_has_calls([
            mock.call(env_path='./inside.yaml'),
            mock.call(env_path='/twd/templates/abs.yaml'),
            mock.call(env_path='/twd/templates/puppet/foo.yaml'),
            mock.call(env_path='/twd/templates/environments/myenv.yaml'),
            mock.call(env_path='/tmp/thtroot42/notouch.yaml'),
            mock.call(env_path='../outside.yaml')])

    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', return_value=({}, {}),
                autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'get_template_contents', return_value=({}, {}),
                autospec=True)
    @mock.patch('heatclient.common.environment_format.'
                'parse', autospec=True, return_value=dict())
    @mock.patch('heatclient.common.template_format.'
                'parse', autospec=True, return_value=dict())
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_setup_heat_environments', autospec=True)
    @mock.patch('yaml.safe_dump', autospec=True)
    @mock.patch('yaml.safe_load', autospec=True)
    @mock.patch('six.moves.builtins.open')
    @mock.patch('tempfile.NamedTemporaryFile', autospec=True)
    @mock.patch('tripleo_common.image.kolla_builder.'
                'container_images_prepare_multi')
    def test_deploy_tripleo_heat_templates_rewrite(self,
                                                   mock_cipm,
                                                   mock_temp, mock_open,
                                                   mock_yaml_load,
                                                   mock_yaml_dump,
                                                   mock_setup_heat_envs,
                                                   mock_hc_templ_parse,
                                                   mock_hc_env_parse,
                                                   mock_hc_get_templ_cont,
                                                   mock_hc_process):
        def hc_process(*args, **kwargs):
            if 'abs.yaml' in kwargs['env_path']:
                raise hc_exc.CommandError
            else:
                return ({}, {})

        mock_cipm.return_value = {}

        mock_hc_process.side_effect = hc_process

        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8',
                                         '--templates', '/tmp/thtroot'], [])

        rewritten_env = {'resource_registry': {
            'OS::Foo::Bar': '/twd/outside.yaml',
            'OS::Foo::Baz': '/twd/templates/inside.yaml',
            'OS::Foo::Qux': '/twd/templates/abs.yaml',
            'OS::Foo::Quux': '/tmp/thtroot42/notouch.yaml',
            'OS::Foo::Corge': '/twd/templates/puppet/foo.yaml'
            }
        }
        myenv = {'resource_registry': {
            'OS::Foo::Bar': '../outside.yaml',
            'OS::Foo::Baz': './inside.yaml',
            'OS::Foo::Qux': '/tmp/thtroot/abs.yaml',
            'OS::Foo::Quux': '/tmp/thtroot42/notouch.yaml',
            'OS::Foo::Corge': '/tmp/thtroot/puppet/foo.yaml'
            }
        }
        mock_yaml_load.return_value = myenv

        mock_setup_heat_envs.return_value = [
            './inside.yaml', '/tmp/thtroot/abs.yaml',
            '/tmp/thtroot/puppet/foo.yaml',
            '/tmp/thtroot/environments/myenv.yaml',
            '../outside.yaml']

        self.cmd._deploy_tripleo_heat_templates(self.orc, parsed_args)

        mock_yaml_dump.assert_has_calls([mock.call(rewritten_env,
                                        default_flow_style=False)])

    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', return_value=({}, {}),
                autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'get_template_contents', return_value=({}, {}),
                autospec=True)
    @mock.patch('tripleoclient.utils.'
                'process_multiple_environments', autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_process_hieradata_overrides', return_value='foo.yaml',
                autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_update_passwords_env', autospec=True)
    @mock.patch('tripleoclient.utils.'
                'run_command_and_log', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True, return_value='/twd')
    @mock.patch('shutil.copytree', autospec=True)
    def test_setup_heat_environments(self,
                                     mock_copy,
                                     mock_mktemp,
                                     mock_run,
                                     mock_update_pass_env,
                                     mock_process_hiera,
                                     mock_process_multiple_environments,
                                     mock_hc_get_templ_cont,
                                     mock_hc_process):

        mock_run.return_value = 0

        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8',
                                         '--templates', '/tmp/thtroot',
                                         '--output-dir', '/my',
                                         '--hieradata-override',
                                         'legacy.yaml',
                                         '-e',
                                         '/tmp/thtroot/puppet/foo.yaml',
                                         '-e',
                                         '/tmp/thtroot//docker/bar.yaml',
                                         '-e',
                                         '/tmp/thtroot42/notouch.yaml',
                                         '-e', '~/custom.yaml',
                                         '-e', 'something.yaml',
                                         '-e', '../../../outside.yaml'], [])
        expected_env = [
            '/my/tripleo-heat-installer-templates/'
            'overcloud-resource-registry-puppet.yaml',
            mock.ANY,
            '/my/tripleo-heat-installer-templates/'
            'environments/undercloud.yaml',
            '/my/tripleo-heat-installer-templates/'
            'environments/config-download-environment.yaml',
            '/my/tripleo-heat-installer-templates/'
            'environments/deployed-server-noop-ctlplane.yaml',
            '/tmp/thtroot/puppet/foo.yaml',
            '/tmp/thtroot//docker/bar.yaml',
            '/tmp/thtroot42/notouch.yaml',
            '~/custom.yaml',
            'something.yaml',
            '../../../outside.yaml',
            mock.ANY, 'foo.yaml']

        environment = self.cmd._setup_heat_environments(parsed_args)

        self.assertEqual(environment, expected_env)

    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_create_working_dirs', autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.TripleoInventory',
                autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_launch_heat', autospec=True)
    @mock.patch('tripleo_common.utils.config.Config',
                autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.sys.stdout.flush')
    @mock.patch('os.path.join', return_value='/twd/inventory.yaml')
    def test_download_ansible_playbooks(self, mock_join, mock_flush,
                                        mock_stack_config, mock_launch_heat,
                                        mock_importInv, createdir_mock):

        fake_output_dir = '/twd'
        extra_vars = {'Undercloud': {'ansible_connection': 'local'}}
        mock_inventory = mock.Mock()
        mock_importInv.return_value = mock_inventory
        self.cmd.output_dir = fake_output_dir
        self.cmd._download_ansible_playbooks(mock_launch_heat,
                                             'undercloud')
        self.assertEqual(mock_flush.call_count, 2)
        mock_inventory.write_static_inventory.assert_called_once_with(
            fake_output_dir + '/inventory.yaml', extra_vars)

    @mock.patch('tripleoclient.utils.'
                'run_command_and_log', autospec=True)
    @mock.patch('os.chdir')
    @mock.patch('os.execvp')
    def test_launch_ansible_deploy(self, mock_execvp, mock_chdir, mock_run):

        self.cmd._launch_ansible_deploy('/tmp')
        mock_chdir.assert_called_once()
        mock_run.assert_called_once_with(self.cmd.log, [
            'ansible-playbook', '-i', '/tmp/inventory.yaml',
            'deploy_steps_playbook.yaml', '-e', 'role_name=Undercloud',
            '-e', 'tripleo_role_name=Undercloud',
            '-e', 'deploy_server_id=undercloud', '-e',
            'bootstrap_server_id=undercloud'])

    @mock.patch('tripleo_common.image.kolla_builder.'
                'container_images_prepare_multi')
    def test_prepare_container_images(self, mock_cipm):
        env = {'parameter_defaults': {}}
        mock_cipm.return_value = {'FooImage': 'foo/bar:baz'}

        with tempfile.NamedTemporaryFile(mode='w') as roles_file:
            yaml.dump([{'name': 'Compute'}], roles_file)
            self.cmd._prepare_container_images(env, roles_file.name)

        mock_cipm.assert_called_once_with(
            env,
            [{'name': 'Compute'}]
        )
        self.assertEqual(
            {
                'parameter_defaults': {
                    'FooImage': 'foo/bar:baz'
                }
            },
            env
        )

    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_create_install_artifact', return_value='/tmp/foo.tar.bzip2')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_launch_ansible_deploy', return_value=0)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_cleanup_working_dirs')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_create_working_dirs')
    @mock.patch('tripleoclient.utils.wait_api_port_ready',
                autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_deploy_tripleo_heat_templates', autospec=True,
                return_value='undercloud, 0')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_download_ansible_playbooks', autospec=True,
                return_value='/foo')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_launch_heat')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_kill_heat')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_configure_puppet')
    @mock.patch('os.geteuid', return_value=0)
    @mock.patch('os.environ', return_value='CREATE_COMPLETE')
    @mock.patch('tripleoclient.v1.tripleo_deploy.'
                'event_utils.poll_for_events',
                return_value=('CREATE_COMPLETE', 0))
    def test_take_action_standalone(self, mock_poll, mock_environ,
                                    mock_geteuid, mock_puppet, mock_killheat,
                                    mock_launchheat, mock_download, mock_tht,
                                    mock_wait_for_port, mock_createdirs,
                                    mock_cleanupdirs, mock_launchansible,
                                    mock_tarball):

        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my',
                                         '-e', '/tmp/thtroot/puppet/foo.yaml',
                                         '-e', '/tmp/thtroot//docker/bar.yaml',
                                         '-e', '/tmp/thtroot42/notouch.yaml',
                                         '-e', '~/custom.yaml',
                                         '-e', 'something.yaml',
                                         '-e', '../../../outside.yaml',
                                         '--standalone'], [])

        fake_orchestration = mock_launchheat(parsed_args)
        self.cmd.take_action(parsed_args)
        mock_createdirs.assert_called_once()
        mock_puppet.assert_called_once()
        mock_launchheat.assert_called_with(parsed_args)
        mock_tht.assert_called_once_with(self.cmd, fake_orchestration,
                                         parsed_args)
        mock_download.assert_called_with(self.cmd, fake_orchestration,
                                         'undercloud')
        mock_launchansible.assert_called_once()
        mock_tarball.assert_called_once()
        mock_cleanupdirs.assert_called_once()
        self.assertEqual(mock_killheat.call_count, 2)

    def test_take_action(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my'], [])
        self.assertRaises(exceptions.DeploymentError,
                          self.cmd.take_action, parsed_args)

    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy._standalone_deploy',
                return_value=1)
    def test_take_action_failure(self, mock_deploy):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my',
                                         '--standalone'], [])
        self.assertRaises(exceptions.DeploymentError,
                          self.cmd.take_action, parsed_args)
