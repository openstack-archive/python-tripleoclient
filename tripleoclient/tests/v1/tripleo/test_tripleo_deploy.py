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

import fixtures
import mock
import os
import sys
import tempfile
import yaml

from heatclient import exc as hc_exc
from tripleo_common.image import kolla_builder

from tripleoclient import exceptions
from tripleoclient.tests import fakes
from tripleoclient.tests.v1.test_plugin import TestPluginV1

# Load the plugin init module for the plugin list and show commands
from tripleoclient.v1 import tripleo_deploy

import ansible_runner


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
        self.cmd.ansible_dir = '/tmp'

        tripleo_deploy.Deploy.heat_pid = mock.MagicMock(
            return_value=False)
        tripleo_deploy.Deploy.tht_render = '/twd/templates'
        tripleo_deploy.Deploy.heat_launch = mock.MagicMock(
            side_effect=(lambda *x, **y: None))

        self.tc = self.app.client_manager.tripleoclient = mock.MagicMock()
        self.orc = self.tc.local_orchestration = mock.MagicMock()
        self.orc.stacks.create = mock.MagicMock(
            return_value={'stack': {'id': 'foo'}})

    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy._is_undercloud_deploy')
    @mock.patch('tripleoclient.utils.check_hostname')
    def test_run_preflight_checks(self, mock_check_hostname, mock_uc):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8'], [])

        mock_uc.return_value = False
        self.cmd._run_preflight_checks(parsed_args)
        mock_check_hostname.called_one_with(False)

    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy._is_undercloud_deploy')
    @mock.patch('tripleoclient.utils.check_hostname')
    def test_run_preflight_checks_output_only(self, mock_check_hostname,
                                              mock_uc):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8',
                                         '--output-only'], [])

        mock_uc.return_value = False
        self.cmd._run_preflight_checks(parsed_args)
        mock_check_hostname.assert_not_called()

    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy._is_undercloud_deploy')
    @mock.patch('tripleoclient.utils.check_hostname')
    def test_run_preflight_checks_undercloud(self, mock_check_hostname,
                                             mock_uc):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8'], [])

        mock_uc.return_value = True
        self.cmd._run_preflight_checks(parsed_args)
        mock_check_hostname.assert_not_called()

    def test_get_roles_file_path(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8'], [])

        roles_file = self.cmd._get_roles_file_path(parsed_args)
        self.assertEqual(roles_file,
                         '/usr/share/openstack-tripleo-heat-templates/'
                         'roles_data_undercloud.yaml')

    def test_get_roles_file_path_custom_file(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8',
                                         '--templates', '/tmp/thtroot',
                                         '--roles-file', 'foobar.yaml'], [])

        roles_file = self.cmd._get_roles_file_path(parsed_args)
        self.assertEqual(roles_file, 'foobar.yaml')

    def test_get_roles_file_path_custom_templates(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8',
                                         '--templates', '/tmp/thtroot'], [])

        import pprint
        pprint.pprint(parsed_args)
        roles_file = self.cmd._get_roles_file_path(parsed_args)
        self.assertEqual(roles_file,
                         '/tmp/thtroot/roles_data_undercloud.yaml')

    def test_get_networks_file_path(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8'], [])

        networks_file = self.cmd._get_networks_file_path(parsed_args)
        self.assertEqual('/dev/null', networks_file)

    def test_get_networks_file_path_custom_file(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8',
                                         '--networks-file', 'foobar.yaml'], [])

        networks_file = self.cmd._get_networks_file_path(parsed_args)
        self.assertEqual('foobar.yaml', networks_file)

    def test_get_networks_file_path_custom_templates(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8',
                                         '--templates', '/tmp/thtroot'], [])

        networks_file = self.cmd._get_networks_file_path(parsed_args)
        self.assertEqual('/dev/null', networks_file)

    def test_get_plan_env_file_path(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8'], [])

        plan_env_file = self.cmd._get_plan_env_file_path(parsed_args)
        self.assertEqual(plan_env_file,
                         '/usr/share/openstack-tripleo-heat-templates/'
                         'plan-environment.yaml')

    def test_get_plan_env_file_path_custom_file(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8',
                                         '--templates', '/tmp/thtroot',
                                         '--plan-environment-file',
                                         'foobar.yaml'], [])

        plan_env_file = self.cmd._get_plan_env_file_path(parsed_args)
        self.assertEqual(plan_env_file, 'foobar.yaml')

    def test_get_plan_env_file_path_custom_templates(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8',
                                         '--templates', '/tmp/thtroot'], [])

        plan_env_file = self.cmd._get_plan_env_file_path(parsed_args)
        self.assertEqual(plan_env_file,
                         '/tmp/thtroot/plan-environment.yaml')

    @mock.patch('os.path.exists')
    @mock.patch('tripleoclient.utils.fetch_roles_file')
    def test_get_primary_role_name(self, mock_data, mock_exists):
        parsed_args = mock.Mock()
        mock_data.return_value = [
            {'name': 'Bar'}, {'name': 'Foo', 'tags': ['primary']}
        ]
        self.assertEqual(
            self.cmd._get_primary_role_name(parsed_args.roles_file,
                                            parsed_args.templates),
            'Foo')

    @mock.patch('tripleoclient.utils.fetch_roles_file', return_value=None)
    def test_get_primary_role_name_none_defined(self, mock_data):
        parsed_args = self.check_parser(self.cmd, [], [])
        self.assertEqual(
            self.cmd._get_primary_role_name(parsed_args.roles_file,
                                            parsed_args.templates),
            'Controller')

    @mock.patch('tripleoclient.utils.fetch_roles_file')
    def test_get_primary_role_name_no_primary(self, mock_data):
        parsed_args = mock.Mock()
        mock_data.return_value = [{'name': 'Bar'}, {'name': 'Foo'}]
        self.assertEqual(
            self.cmd._get_primary_role_name(parsed_args.roles_file,
                                            parsed_args.templates),
            'Bar')

    @mock.patch('os.path.exists', side_effect=[True, False])
    @mock.patch('shutil.copytree')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_create_working_dirs')
    def test_populate_templates_dir(self, mock_workingdirs, mock_copy,
                                    mock_exists):
        self.cmd.tht_render = '/foo'
        self.cmd._populate_templates_dir('/bar')
        mock_workingdirs.assert_called_once()
        mock_copy.assert_called_once_with('/bar', '/foo', symlinks=True)

    @mock.patch('os.path.exists', return_value=False)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_create_working_dirs')
    def test_populate_templates_dir_bad_source(self, mock_workingdirs,
                                               mock_exists):
        self.cmd.tht_render = '/foo'
        self.assertRaises(exceptions.NotFound,
                          self.cmd._populate_templates_dir, '/foo')

    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('os.chmod')
    @mock.patch('os.path.exists')
    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleo_common.utils.passwords.generate_passwords')
    @mock.patch('yaml.safe_dump')
    def test_update_passwords_env_init(self, mock_dump, mock_pw, mock_cc,
                                       mock_exists, mock_chmod, mock_user):
        pw_dict = {"GeneratedPassword": 123}

        mock_pw.return_value = pw_dict
        mock_exists.return_value = False

        mock_open_context = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open_context):
            self.cmd._update_passwords_env(self.temp_homedir, 'stack')

        mock_open_handle = mock_open_context()
        mock_dump.assert_called_once_with({'parameter_defaults': pw_dict},
                                          mock_open_handle,
                                          default_flow_style=False)

    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('os.chmod')
    @mock.patch('os.path.exists')
    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleo_common.utils.passwords.generate_passwords')
    @mock.patch('yaml.safe_dump')
    def test_update_passwords_env(self, mock_dump, mock_pw, mock_cc,
                                  mock_exists, mock_chmod, mock_user):
        pw_dict = {"GeneratedPassword": 123, "LegacyPass": "override me"}
        pw_conf_path = os.path.join(self.temp_homedir,
                                    'undercloud-passwords.conf')
        t_pw_conf_path = os.path.join(
            self.temp_homedir, 'tripleo-undercloud-passwords.yaml')

        mock_pw.return_value = pw_dict
        mock_exists.return_value = True
        with open(t_pw_conf_path, 'w') as t_pw:
            t_pw.write('parameter_defaults: {ExistingKey: xyz, '
                       'LegacyPass: pick-me-legacy-tht, '
                       'RpcPassword: pick-me-rpc}\n')

        with open(pw_conf_path, 'w') as t_pw:
            t_pw.write('[auth]\nundercloud_db_password = ignore-me-mysql\n'
                       'undercloud_rabbit_password = ignore-me-rabbit\n'
                       'undercloud_rpc_password = ignore-me-rpc\n'
                       'undercloud_legacy_pass = ignore-me-legacy\n')

        self.cmd._update_passwords_env(self.temp_homedir,
                                       'stack', upgrade=False,
                                       passwords={'ADefault': 456,
                                                  'ExistingKey':
                                                  'dontupdate'})
        expected_dict = {
            'parameter_defaults': {'GeneratedPassword': 123,
                                   'LegacyPass': 'pick-me-legacy-tht',
                                   'RpcPassword': 'pick-me-rpc',
                                   'ExistingKey': 'xyz',
                                   'ADefault': 456}}
        mock_dump.assert_called_once_with(expected_dict,
                                          mock.ANY,
                                          default_flow_style=False)

    # TODO(bogdando) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('os.chmod')
    @mock.patch('os.path.exists')
    # TODO(bogdando) drop once we have proper oslo.privsep
    @mock.patch('subprocess.check_call', autospec=True)
    @mock.patch('tripleo_common.utils.passwords.generate_passwords')
    @mock.patch('yaml.safe_dump')
    def test_update_passwords_env_upgrade(self, mock_dump, mock_pw, mock_cc,
                                          mock_exists, mock_chmod, mock_user):
        pw_dict = {"GeneratedPassword": 123, "LegacyPass": "override me"}
        pw_conf_path = os.path.join(self.temp_homedir,
                                    'undercloud-passwords.conf')
        t_pw_conf_path = os.path.join(
            self.temp_homedir, 'tripleo-undercloud-passwords.yaml')

        mock_pw.return_value = pw_dict

        def mock_file_exists(file_name):
            return not file_name.startswith('/etc/keystone')
        mock_exists.side_effect = mock_file_exists
        with open(t_pw_conf_path, 'w') as t_pw:
            t_pw.write('parameter_defaults: {ExistingKey: xyz, '
                       'LegacyPass: override-me-legacy, '
                       'RpcPassword: override-me-rpc}\n')

        with open(pw_conf_path, 'w') as t_pw:
            t_pw.write('[auth]\nundercloud_db_password = pick-me-mysql\n'
                       'undercloud_rabbit_password = pick-me-rabbit\n'
                       'undercloud_rpc_password = pick-me-rpc\n'
                       'undercloud_legacy_pass = pick-me-legacy-instack\n')

        self.cmd._update_passwords_env(self.temp_homedir,
                                       'stack', upgrade=True,
                                       passwords={'ADefault': 456,
                                                  'ExistingKey':
                                                  'dontupdate'})
        expected_dict = {
            'parameter_defaults': {'GeneratedPassword': 123,
                                   'ExistingKey': 'xyz',
                                   'MysqlRootPassword': 'pick-me-mysql',
                                   'RpcPassword': 'pick-me-rpc',
                                   'RabbitPassword': 'pick-me-rabbit',
                                   'LegacyPass': 'pick-me-legacy-instack',
                                   'ADefault': 456}}
        mock_dump.assert_called_once_with(expected_dict,
                                          mock.ANY,
                                          default_flow_style=False)

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

    @mock.patch('tripleoclient.utils.rel_or_abs_path')
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
                                                   mock_hc_process,
                                                   mock_norm_path):
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

    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_populate_templates_dir')
    @mock.patch('tripleoclient.utils.fetch_roles_file')
    @mock.patch('tripleoclient.utils.rel_or_abs_path')
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
    def test_deploy_tripleo_heat_templates_remove(self,
                                                  mock_cipm,
                                                  mock_temp, mock_open,
                                                  mock_yaml_load,
                                                  mock_yaml_dump,
                                                  mock_setup_heat_envs,
                                                  mock_hc_templ_parse,
                                                  mock_hc_env_parse,
                                                  mock_hc_get_templ_cont,
                                                  mock_hc_process,
                                                  mock_norm_path,
                                                  mock_fetch_roles,
                                                  mock_populate):
        def hc_process(*args, **kwargs):
            if 'myenv.yaml' in kwargs['env_path']:
                env = {
                    'resource_registry': {
                        'OS::TripleO::Services::Foo': 'OS::Heat::None'}}
                return ({}, env)
            else:
                return ({}, {})

        mock_fetch_roles.return_value = [
            {'name': 'Bar', 'ServicesDefault': [
                'OS::TripleO::Services::Foo', 'OS::TripleO::Services::Bar']},
            {'name': 'Foo', 'tags': ['primary']}
        ]

        def set_tht(templates, stack_name):
            self.cmd.tht_render = "tht_from"

        mock_populate.side_effect = set_tht

        mock_cipm.return_value = {}

        mock_hc_process.side_effect = hc_process

        parsed_args = self.check_parser(self.cmd,
                                        ['--templates', '/tmp/thtroot'], [])

        rewritten_role = [
            {'name': 'Bar', 'ServicesDefault': ['OS::TripleO::Services::Bar']},
            {'name': 'Foo', 'tags': ['primary']}
        ]
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

        mock_yaml_dump.assert_has_calls([mock.call(rewritten_role)])

    @mock.patch('shutil.copy')
    @mock.patch('os.path.exists', return_value=False)
    def test_normalize_user_templates(self, mock_exists, mock_copy):
        user_tht_root = '/userroot'
        tht_root = '/thtroot'
        env_files = [
            '/home/basic.yaml',
            '/home/dir/dir.yaml',
            'home/relative.yaml',
            'file.yaml',
            '~/tilde.yaml',
            '../../../dots.yaml',
            '/userroot/template.yaml',
            '/userroot/tht/tht.yaml',
        ]
        expected = [
            '/thtroot/basic.yaml',
            '/thtroot/dir.yaml',
            '/thtroot/relative.yaml',
            '/thtroot/file.yaml',
            '/thtroot/tilde.yaml',
            '/thtroot/dots.yaml',
            '/thtroot/template.yaml',
            '/thtroot/tht/tht.yaml'
        ]
        results = self.cmd._normalize_user_templates(user_tht_root,
                                                     tht_root,
                                                     env_files)

        self.assertEqual(expected, results)
        self.assertEqual(mock_copy.call_count, 6)

    @mock.patch('os.path.exists', return_value=True)
    def test_normalize_user_templates_exists(self, mock_exists):
        user_tht_root = '/userroot'
        tht_root = '/thtroot'
        env_files = ['/home/basic.yaml']
        self.assertRaises(exceptions.DeploymentError,
                          self.cmd._normalize_user_templates,
                          user_tht_root,
                          tht_root,
                          env_files)

    @mock.patch('os.path.exists', return_value=True)
    def test_normalize_user_templates_trailing_slash(self, mock_exists):
        user_tht_root = '/userroot/'
        tht_root = '/thtroot'
        env_files = ['/userroot/basic.yaml']
        expected = ['/thtroot/basic.yaml']
        results = self.cmd._normalize_user_templates(user_tht_root,
                                                     tht_root,
                                                     env_files)
        self.assertEqual(expected, results)

    @mock.patch('time.time', return_value=123)
    @mock.patch('yaml.safe_load', return_value={}, autospec=True)
    @mock.patch('yaml.safe_dump', autospec=True)
    @mock.patch('os.path.isfile', return_value=True)
    @mock.patch('six.moves.builtins.open')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_process_hieradata_overrides', autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_update_passwords_env', autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_normalize_user_templates', return_value=[], autospec=True)
    @mock.patch('tripleoclient.utils.rel_or_abs_path', return_value={},
                autospec=True)
    @mock.patch('tripleoclient.utils.run_command_and_log', return_value=0,
                autospec=True)
    def test_setup_heat_environments_dropin(
            self, mock_run, mock_paths, mock_norm, mock_update_pass_env,
            mock_process_hiera, mock_open, mock_os, mock_yaml_dump,
            mock_yaml_load, mock_time):

        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8',
                                         '--templates', 'tht_from',
                                         '--output-dir', 'tht_to'], [])
        dropin = 'tht_from/standalone-stack-vstate-dropin.yaml'
        self.cmd.output_dir = 'tht_to'
        self.cmd.tht_render = 'tht_from'
        self.cmd.stack_action = 'UPDATE'
        environment = self.cmd._setup_heat_environments(
            parsed_args.roles_file, parsed_args.networks_file, parsed_args)

        self.assertIn(dropin, environment)
        mock_open.assert_has_calls([mock.call(dropin, 'w')])

        # unpack the dump yaml calls to verify if the produced stack update
        # dropin matches our expectations
        found_dropin = False
        found_identifier = False
        for call in mock_yaml_dump.call_args_list:
            args, kwargs = call
            for a in args:
                if isinstance(a, mock.mock.MagicMock):
                    continue
                if a.get('parameter_defaults', {}).get('StackAction', None):
                    self.assertTrue(
                        a['parameter_defaults']['StackAction'] == 'UPDATE')
                    found_dropin = True
                if a.get('parameter_defaults', {}).get('DeployIdentifier',
                                                       None):
                    self.assertTrue(
                        a['parameter_defaults']['DeployIdentifier'] == 123)
                    found_identifier = True
        self.assertTrue(found_dropin)
        self.assertTrue(found_identifier)

    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', return_value=({}, {}),
                autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'get_template_contents', return_value=({}, {}),
                autospec=True)
    @mock.patch('tripleoclient.utils.'
                'process_multiple_environments', autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_process_hieradata_overrides', return_value='hiera_or.yaml',
                autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_update_passwords_env', autospec=True)
    @mock.patch('tripleoclient.utils.'
                'run_command_and_log', autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_get_primary_role_name', autospec=True)
    def test_setup_heat_environments_default_plan_env(
            self, mock_prim, mock_run, mock_update_pass_env,
            mock_process_hiera, mock_process_multiple_environments,
            mock_hc_get_templ_cont, mock_hc_process):

        tmpdir = self.useFixture(fixtures.TempDir()).path
        tht_from = os.path.join(tmpdir, 'tht-from')
        os.mkdir(tht_from)
        plan_env_path = os.path.join(tht_from, 'plan-environment.yaml')
        with open(plan_env_path, mode='w') as plan_file:
            yaml.dump({'environments': [{'path': 'env.yaml'}]}, plan_file)
        self.assertTrue(os.path.exists(plan_env_path))
        self._setup_heat_environments(tmpdir, tht_from, plan_env_path,
                                      mock_update_pass_env, mock_run)

    @mock.patch('heatclient.common.template_utils.'
                'process_environment_and_files', return_value=({}, {}),
                autospec=True)
    @mock.patch('heatclient.common.template_utils.'
                'get_template_contents', return_value=({}, {}),
                autospec=True)
    @mock.patch('tripleoclient.utils.'
                'process_multiple_environments', autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_process_hieradata_overrides', return_value='hiera_or.yaml',
                autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_update_passwords_env', autospec=True)
    @mock.patch('tripleoclient.utils.'
                'run_command_and_log', autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_get_primary_role_name', autospec=True)
    def test_setup_heat_environments_non_default_plan_env(
            self, mock_prim, mock_run, mock_update_pass_env,
            mock_process_hiera, mock_process_multiple_environments,
            mock_hc_get_templ_cont, mock_hc_process):

        tmpdir = self.useFixture(fixtures.TempDir()).path
        tht_from = os.path.join(tmpdir, 'tht-from')
        os.mkdir(tht_from)
        default_plan_env_path = os.path.join(tht_from, 'plan-environment.yaml')
        with open(default_plan_env_path, mode='w') as plan_file:
            yaml.dump({'environments': [{'path': 'env.yaml'}]}, plan_file)
        plan_env_path = os.path.join(tmpdir, 'plan-environment.yaml')
        with open(plan_env_path, mode='w') as plan_file:
            yaml.dump({'environments': [{'path': 'notenv.yaml'}]}, plan_file)
        self.assertTrue(os.path.exists(plan_env_path))
        with open(os.path.join(tht_from, 'notenv.yaml'),
                  mode='w') as env_file:
            yaml.dump({}, env_file)
        cmd_extra = ['-p', plan_env_path]
        self._setup_heat_environments(tmpdir, tht_from, plan_env_path,
                                      mock_update_pass_env, mock_run,
                                      cmd_extra, 'notenv.yaml')

    def _setup_heat_environments(self, tmpdir, tht_from, plan_env_path,
                                 mock_update_pass_env, mock_run,
                                 extra_cmd=None, plan_env_env=None):
        cmd_extra = extra_cmd or []
        plan_env_env_name = plan_env_env or 'env.yaml'

        tht_outside = os.path.join(tmpdir, 'tht-outside')
        os.mkdir(tht_outside)
        tht_to = os.path.join(tmpdir, 'tht-to')
        os.mkdir(tht_to)
        with open(os.path.join(tht_from, 'env.yaml'),
                  mode='w') as env_file:
            yaml.dump({}, env_file)
        with open(os.path.join(tht_from, 'foo.yaml'),
                  mode='w') as env_file:
            yaml.dump({}, env_file)
        with open(os.path.join(tht_outside, 'outside.yaml'),
                  mode='w') as env_file:
            yaml.dump({}, env_file)

        tht_render = os.path.join(tht_to, 'tripleo-heat-installer-templates')
        mock_update_pass_env.return_value = os.path.join(
            tht_render, 'passwords.yaml')
        mock_run.return_value = 0
        original_abs = os.path.abspath

        # Stub abspath for default plan and envs to return the tht_render base
        def abs_path_stub(*args, **kwargs):
            if 'plan-environment.yaml' in args:
                return plan_env_path
            elif 'notenv.yaml' in args:
                return os.path.join(tht_render, 'notenv.yaml')
            elif 'env.yaml' in args:
                return os.path.join(tht_render, 'env.yaml')
            else:
                return original_abs(*args, **kwargs)

        # logic handled in _standalone_deploy
        self.cmd.output_dir = tht_to
        # Note we don't create tht_render as _populate_templates_dir creates it
        self.cmd.tht_render = tht_render
        self.cmd._populate_templates_dir(tht_from)

        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1/8',
                                         '--templates', tht_from,
                                         '--output-dir', tht_to,
                                         '--hieradata-override',
                                         'legacy.yaml',
                                         '-e',
                                         os.path.join(tht_from, 'foo.yaml'),
                                         '-e',
                                         os.path.join(tht_outside,
                                                      'outside.yaml'),
                                         ] + cmd_extra, [])
        expected_env = [
            os.path.join(tht_render, plan_env_env_name),
            os.path.join(tht_render, 'passwords.yaml'),
            os.path.join(tht_render,
                         'environments/deployed-server-noop-ctlplane.yaml'),
            os.path.join(tht_render,
                         'tripleoclient-hosts-portmaps.yaml'),
            'hiera_or.yaml',
            os.path.join(tht_render, 'standalone-stack-vstate-dropin.yaml'),
            os.path.join(tht_render, 'foo.yaml'),
            os.path.join(tht_render, 'outside.yaml')]

        with mock.patch('os.path.abspath', side_effect=abs_path_stub):
            with mock.patch('os.path.isfile'):
                environment = self.cmd._setup_heat_environments(
                    parsed_args.roles_file, parsed_args.networks_file,
                    parsed_args)

                self.assertEqual(expected_env, environment)

    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_create_working_dirs', autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.TripleoInventory',
                autospec=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_launch_heat', autospec=True)
    @mock.patch('tripleo_common.utils.config.Config',
                autospec=True)
    @mock.patch('os.path.join', return_value='/twd/inventory.yaml')
    @mock.patch('shutil.copyfile')
    def test_download_ansible_playbooks(self, mock_shutil, mock_join,
                                        mock_stack_config,
                                        mock_launch_heat, mock_importInv,
                                        createdir_mock):

        fake_output_dir = '/twd'
        extra_vars = {'Undercloud': {
            'ansible_connection': 'local',
            'ansible_python_interpreter': sys.executable}}
        mock_inventory = mock.Mock()
        mock_importInv.return_value = mock_inventory
        with mock.patch('sys.stdout', autospec=True) as mock_stdout:
            self.cmd.output_dir = fake_output_dir
            self.cmd._download_ansible_playbooks(mock_launch_heat,
                                                 'undercloud',
                                                 'Undercloud')
            self.assertEqual(mock_stdout.flush.call_count, 2)
        mock_inventory.write_static_inventory.assert_called_once_with(
            fake_output_dir + '/inventory.yaml', extra_vars)

    @mock.patch('tripleo_common.image.kolla_builder.'
                'container_images_prepare_multi')
    def test_prepare_container_images(self, mock_cipm):
        env = {'parameter_defaults': {}}
        mock_cipm.return_value = {'FooImage': 'foo/bar:baz'}

        self.cmd._prepare_container_images(env, [{'name': 'Compute'}])

        mock_cipm.assert_called_once_with(
            env,
            [{'name': 'Compute'}],
            dry_run=True,
        )
        self.assertEqual(
            {
                'parameter_defaults': {
                    'FooImage': 'foo/bar:baz'
                }
            },
            env
        )

    @mock.patch.object(
        ansible_runner.runner_config,
        'RunnerConfig',
        return_value=fakes.FakeRunnerConfig()
    )
    @mock.patch.object(
        ansible_runner.Runner,
        'run',
        return_value=fakes.fake_ansible_runner_run_return()
    )
    @mock.patch('os.path.exists')
    @mock.patch('os.chdir')
    @mock.patch('tripleoclient.utils.reset_cmdline')
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_download_stack_outputs')
    @mock.patch('tripleo_common.actions.ansible.'
                'write_default_ansible_cfg')
    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('os.chmod')
    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('subprocess.check_call', autospec=True)
    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('os.mkdir')
    @mock.patch('six.moves.builtins.open')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_populate_templates_dir')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_create_install_artifact', return_value='/tmp/foo.tar.bzip2')
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
    @mock.patch('tripleoclient.utils.wait_for_stack_ready', return_value=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_set_default_plan')
    @mock.patch('ansible_runner.utils.dump_artifact', autospec=True,
                return_value="/foo/inventory.yaml")
    def test_take_action_standalone(self, mock_dump_artifact,
                                    mock_def_plan, mock_poll,
                                    mock_environ, mock_geteuid, mock_puppet,
                                    mock_killheat, mock_launchheat,
                                    mock_download, mock_tht,
                                    mock_wait_for_port, mock_createdirs,
                                    mock_cleanupdirs, mock_tarball,
                                    mock_templates_dir, mock_open, mock_os,
                                    mock_user, mock_cc, mock_chmod, mock_ac,
                                    mock_outputs, mock_copy, mock_cmdline,
                                    mock_chdir, mock_file_exists, mock_run,
                                    mock_run_prepare):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my',
                                         '--standalone-role', 'Undercloud',
                                         # TODO(cjeanner) drop once we have
                                         # proper oslo.privsep
                                         '--deployment-user', 'stack',
                                         '-e', '/tmp/thtroot/puppet/foo.yaml',
                                         '-e', '/tmp/thtroot//docker/bar.yaml',
                                         '-e', '/tmp/thtroot42/notouch.yaml',
                                         '-e', '~/custom.yaml',
                                         '-e', 'something.yaml',
                                         '-e', '../../../outside.yaml',
                                         '--standalone'], [])

        mock_file_exists.return_value = True
        fake_orchestration = mock_launchheat(parsed_args)
        self.cmd.take_action(parsed_args)
        mock_createdirs.assert_called_once()
        mock_puppet.assert_called_once()
        mock_launchheat.assert_called_with(parsed_args)
        mock_tht.assert_called_once_with(self.cmd, fake_orchestration,
                                         parsed_args)
        mock_download.assert_called_with(self.cmd, fake_orchestration,
                                         'undercloud', 'Undercloud',
                                         sys.executable)
        mock_tarball.assert_called_once()
        mock_cleanupdirs.assert_called_once()
        self.assertEqual(mock_killheat.call_count, 2)

    @mock.patch.object(
        ansible_runner.runner_config,
        'RunnerConfig',
        return_value=fakes.FakeRunnerConfig()
    )
    @mock.patch.object(
        ansible_runner.Runner,
        'run',
        return_value=fakes.fake_ansible_runner_run_return(1)
    )
    @mock.patch('os.path.exists')
    @mock.patch('os.chdir')
    @mock.patch('tripleoclient.utils.reset_cmdline')
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_download_stack_outputs')
    @mock.patch('tripleo_common.actions.ansible.'
                'write_default_ansible_cfg')
    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('os.chmod')
    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('subprocess.check_call', autospec=True)
    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('os.mkdir')
    @mock.patch('six.moves.builtins.open')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_populate_templates_dir')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_create_install_artifact', return_value='/tmp/foo.tar.bzip2')
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
    @mock.patch('tripleoclient.utils.wait_for_stack_ready', return_value=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_set_default_plan')
    @mock.patch('ansible_runner.utils.dump_artifact', autospec=True,
                return_value="/foo/inventory.yaml")
    def test_take_action_ansible_err(self, mock_dump_artifact,
                                     mock_def_plan, mock_poll,
                                     mock_environ, mock_geteuid, mock_puppet,
                                     mock_killheat, mock_launchheat,
                                     mock_download, mock_tht,
                                     mock_wait_for_port, mock_createdirs,
                                     mock_cleanupdirs, mock_tarball,
                                     mock_templates_dir, mock_open, mock_os,
                                     mock_user, mock_cc, mock_chmod, mock_ac,
                                     mock_outputs, mock_copy, mock_cmdline,
                                     mock_chdir, mock_file_exists, mock_run,
                                     mock_run_prepare):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my',
                                         '--standalone',
                                         '--standalone-role', 'Undercloud',
                                         # TODO(cjeanner) drop once we have
                                         # proper oslo.privsep
                                         '--deployment-user', 'stack',
                                         '-e', '/tmp/thtroot/puppet/foo.yaml',
                                         '-e', '/tmp/thtroot//docker/bar.yaml',
                                         '-e', '/tmp/thtroot42/notouch.yaml',
                                         '-e', '~/custom.yaml',
                                         '-e', 'something.yaml',
                                         '-e', '../../../outside.yaml'], [])

        mock_file_exists.return_value = True
        fake_orchestration = mock_launchheat(parsed_args)
        self.assertRaises(exceptions.DeploymentError,
                          self.cmd.take_action, parsed_args)
        mock_createdirs.assert_called_once()
        mock_puppet.assert_called_once()
        mock_launchheat.assert_called_with(parsed_args)
        mock_tht.assert_called_once_with(self.cmd, fake_orchestration,
                                         parsed_args)
        mock_download.assert_called_with(self.cmd, fake_orchestration,
                                         'undercloud', 'Undercloud',
                                         sys.executable)
        mock_tarball.assert_called_once()
        mock_cleanupdirs.assert_called_once()
        self.assertEqual(mock_killheat.call_count, 2)

    @mock.patch('os.chdir')
    @mock.patch('tripleoclient.utils.reset_cmdline')
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_download_stack_outputs')
    @mock.patch('tripleo_common.actions.ansible.'
                'write_default_ansible_cfg')
    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('os.chmod')
    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('subprocess.check_call', autospec=True)
    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('os.mkdir')
    @mock.patch('six.moves.builtins.open')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_populate_templates_dir')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_create_install_artifact', return_value='/tmp/foo.tar.bzip2')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_cleanup_working_dirs')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_create_working_dirs')
    @mock.patch('tripleoclient.utils.wait_api_port_ready')
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
    @mock.patch('tripleoclient.utils.wait_for_stack_ready', return_value=True)
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy.'
                '_set_default_plan')
    def test_take_action_other_err(self,
                                   mock_def_plan, mock_poll,
                                   mock_environ, mock_geteuid, mock_puppet,
                                   mock_killheat, mock_launchheat,
                                   mock_download, mock_tht,
                                   mock_wait_for_port, mock_createdirs,
                                   mock_cleanupdirs, mock_tarball,
                                   mock_templates_dir, mock_open, mock_os,
                                   mock_user, mock_cc, mock_chmod, mock_ac,
                                   mock_outputs, mock_copy, mock_cmdline,
                                   mock_chdir):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my',
                                         '--standalone',
                                         '--standalone-role', 'Undercloud',
                                         # TODO(cjeanner) drop once we have
                                         # proper oslo.privsep
                                         '--deployment-user', 'stack',
                                         '-e', '/tmp/thtroot/puppet/foo.yaml',
                                         '-e', '/tmp/thtroot//docker/bar.yaml',
                                         '-e', '/tmp/thtroot42/notouch.yaml',
                                         '-e', '~/custom.yaml',
                                         '-e', 'something.yaml',
                                         '-e', '../../../outside.yaml'], [])

        mock_wait_for_port.side_effect = exceptions.DeploymentError
        self.assertRaises(exceptions.DeploymentError,
                          self.cmd.take_action, parsed_args)
        mock_createdirs.assert_called_once()
        mock_puppet.assert_called_once()
        mock_launchheat.assert_called_with(parsed_args)
        mock_tht.assert_not_called()
        mock_download.assert_not_called()
        mock_tarball.assert_called_once()
        mock_cleanupdirs.assert_called_once()
        self.assertEqual(mock_killheat.call_count, 1)

    @mock.patch('tripleoclient.utils.reset_cmdline')
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    def test_take_action(self, mock_copy, mock_cmdline):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--standalone',
                                         '--output-dir', '/my'], [])
        self.assertRaises(exceptions.DeploymentError,
                          self.cmd.take_action, parsed_args)
        mock_copy.assert_called_once()

    @mock.patch('tripleoclient.utils.reset_cmdline')
    @mock.patch('tripleoclient.utils.copy_clouds_yaml')
    @mock.patch('tripleoclient.v1.tripleo_deploy.Deploy._standalone_deploy')
    def test_take_action_failure(self, mock_deploy, mock_copy, mock_cmdline):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my',
                                         '--standalone'], [])
        mock_deploy.side_effect = exceptions.DeploymentError
        self.assertRaises(exceptions.DeploymentError,
                          self.cmd.take_action, parsed_args)
        mock_copy.assert_called_once()

    @mock.patch('os.path.isfile', return_value=False)
    def test_set_stack_action_default_create(self, mock_isfile):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my',
                                         '--standalone'], [])
        self.cmd._set_stack_action(parsed_args)
        self.assertEqual('CREATE', self.cmd.stack_action)

    @mock.patch('os.path.isfile', return_value=True)
    def test_set_stack_action_default_update(self, mock_isfile):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my',
                                         '--standalone'], [])
        self.cmd._set_stack_action(parsed_args)
        self.assertEqual('UPDATE', self.cmd.stack_action)

    @mock.patch('os.path.isfile', return_value=False)
    def test_set_stack_action_force_update(self, mock_isfile):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my',
                                         '--standalone',
                                         '--force-stack-update'], [])
        self.cmd._set_stack_action(parsed_args)
        self.assertEqual('UPDATE', self.cmd.stack_action)

    @mock.patch('os.path.isfile', return_value=True)
    def test_set_stack_action_force_create(self, mock_isfile):
        parsed_args = self.check_parser(self.cmd,
                                        ['--local-ip', '127.0.0.1',
                                         '--templates', '/tmp/thtroot',
                                         '--stack', 'undercloud',
                                         '--output-dir', '/my',
                                         '--standalone',
                                         '--force-stack-create'], [])
        self.cmd._set_stack_action(parsed_args)
        self.assertEqual('CREATE', self.cmd.stack_action)

    @mock.patch('os.path.isfile', return_value=True)
    def test_set_stack_action_mutually_exclusive(self, mock_isfile):
        self.assertRaises(
            SystemExit,
            self.check_parser,
            self.cmd,
            ['--local-ip', '127.0.0.1',
             '--templates', '/tmp/thtroot',
             '--stack', 'undercloud',
             '--output-dir', '/my',
             '--standalone',
             '--force-stack-create',
             '--force-stack-update'], [])
