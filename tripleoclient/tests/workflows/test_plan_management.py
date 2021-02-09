# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import mock

from osc_lib.tests import utils
from swiftclient import exceptions as swift_exc

from tripleoclient import constants
from tripleoclient.tests import base
from tripleoclient.workflows import plan_management


class TestPlanCreationWorkflows(utils.TestCommand):

    def setUp(self):
        super(TestPlanCreationWorkflows, self).setUp()
        self.tripleoclient = mock.Mock()
        self.app.client_manager.tripleoclient = self.tripleoclient
        self.tripleoclient.object_store.get_account = mock.MagicMock()

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_create_plan_from_templates_success(self, mock_tmp, mock_cd,
                                                mock_tarball,
                                                mock_run_playbook):
        plan_management.create_plan_from_templates(
            self.app.client_manager,
            'test-overcloud',
            '/tht-root/',
            validate_stack=False)

        mock_run_playbook.assert_called_once_with(
            'cli-create-deployment-plan.yaml',
            'undercloud,',
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "container": "test-overcloud",
                "generate_passwords": True,
                "validate": False,
                "disable_image_params_prepare": False,
            },
            verbosity=0,
        )

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch('tripleoclient.utils.rel_or_abs_path')
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_create_plan_from_templates_roles_data(self, mock_tmp, mock_cd,
                                                   mock_tarball,
                                                   mock_norm_path,
                                                   mock_run_playbook):
        mock_open_context = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open_context):
            plan_management.create_plan_from_templates(
                self.app.client_manager,
                'test-overcloud',
                '/tht-root/',
                'the_roles_file.yaml',
                validate_stack=False)

        mock_run_playbook.assert_called_once_with(
            'cli-create-deployment-plan.yaml',
            'undercloud,',
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "container": "test-overcloud",
                "generate_passwords": True,
                "validate": False,
                "disable_image_params_prepare": False,
            },
            verbosity=0,
        )

        self.assertIn(mock.call('the_roles_file.yaml', '/tht-root/'),
                      mock_norm_path.call_args_list)

        self.tripleoclient.object_store.put_object.assert_called_once_with(
            'test-overcloud', 'roles_data.yaml', mock_open_context())

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_create_plan_from_templates_plan_env_data(self, mock_tmp, mock_cd,
                                                      mock_tarball,
                                                      mock_run_playbook):
        mock_open_context = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open_context):
            plan_management.create_plan_from_templates(
                self.app.client_manager,
                'test-overcloud',
                '/tht-root/',
                plan_env_file='the-plan-environment.yaml',
                validate_stack=False)

        mock_run_playbook.assert_called_once_with(
            'cli-create-deployment-plan.yaml',
            'undercloud,',
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "container": "test-overcloud",
                "generate_passwords": True,
                "plan_environment": "the-plan-environment.yaml",
                "validate": False,
                "disable_image_params_prepare": False,
            },
            verbosity=0,
        )
        mock_open_context.assert_has_calls(
            [mock.call('the-plan-environment.yaml', 'rb')])

        self.tripleoclient.object_store.put_object.assert_called_once_with(
            'test-overcloud', 'plan-environment.yaml', mock_open_context())

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_create_plan_from_templates_networks_data(self, mock_tmp, mock_cd,
                                                      mock_tarball,
                                                      mock_run_playbook):
        mock_open_context = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open_context):
            plan_management.create_plan_from_templates(
                self.app.client_manager,
                'test-overcloud',
                '/tht-root/',
                networks_file='the-network-data.yaml',
                validate_stack=False)

        mock_run_playbook.assert_called_once_with(
            'cli-create-deployment-plan.yaml',
            'undercloud,',
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "container": "test-overcloud",
                "generate_passwords": True,
                "validate": False,
                "disable_image_params_prepare": False,
            },
            verbosity=0,
        )
        mock_open_context.assert_has_calls(
            [mock.call('the-network-data.yaml', 'rb')])

        self.tripleoclient.object_store.put_object.assert_called_once_with(
            'test-overcloud', 'network_data.yaml', mock_open_context())

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_create_plan_with_password_gen_disabled(self, mock_tmp, mock_cd,
                                                    mock_tarball,
                                                    mock_run_playbook):
        plan_management.create_plan_from_templates(
            self.app.client_manager,
            'test-overcloud',
            '/tht-root/',
            generate_passwords=False,
            validate_stack=False,
            disable_image_params_prepare=True)

        mock_run_playbook.assert_called_once_with(
            'cli-create-deployment-plan.yaml',
            'undercloud,',
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "container": "test-overcloud",
                "generate_passwords": False,
                "validate": False,
                "disable_image_params_prepare": True,
            },
            verbosity=0,
        )


class TestPlanUpdateWorkflows(base.TestCommand):

    def setUp(self):
        super(TestPlanUpdateWorkflows, self).setUp()
        self.app.client_manager.tripleoclient = self.tripleoclient = \
            mock.Mock()
        self.tripleoclient.object_store = self.object_store = mock.Mock()

        self.object_store.get_container.return_value = (
            {},
            [
                {'name': 'plan-environment.yaml'},
                {'name': 'user-environment.yaml'},
                {'name': 'roles_data.yaml'},
                {'name': 'network_data.yaml'},
                {'name': 'user-files/somecustomfile.yaml'},
                {'name': 'user-files/othercustomfile.yaml'},
                {'name': 'this-should-not-be-persisted.yaml'},
            ]
        )

        def get_object(*args, **kwargs):
            if args[0] != 'test-overcloud':
                raise RuntimeError('Unexpected container')
            if args[1] == 'plan-environment.yaml':
                return {}, ('passwords: somepasswords\n'
                            'plan-environment.yaml: mock content\n')
            # Generic return valuebased on param,
            # e.g. 'plan-environment.yaml: mock content'
            return {}, '{0}: mock content\n'.format(args[1])
        self.object_store.get_object.side_effect = get_object

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleo_common.utils.swift.empty_container',
                autospec=True)
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_update_plan_from_templates_keep_env(
            self, mock_tmp, mock_cd, mock_empty_container, mock_tarball,
            mock_run_playbook):

        plan_management.update_plan_from_templates(
            self.app.client_manager,
            'test-overcloud',
            '/tht-root/',
            keep_env=True,
            validate_stack=False)

        mock_empty_container.assert_called_once_with(
            self.object_store, 'test-overcloud')

        # make sure we're pushing the saved files back to plan
        self.object_store.put_object.assert_has_calls(
            [
                mock.call('test-overcloud', 'plan-environment.yaml',
                          'passwords: somepasswords\n'
                          'plan-environment.yaml: mock content\n'),
                mock.call('test-overcloud', 'user-environment.yaml',
                          'user-environment.yaml: mock content\n'),
                mock.call('test-overcloud', 'roles_data.yaml',
                          'roles_data.yaml: mock content\n'),
                mock.call('test-overcloud', 'network_data.yaml',
                          'network_data.yaml: mock content\n'),
                mock.call('test-overcloud', 'user-files/somecustomfile.yaml',
                          'user-files/somecustomfile.yaml: mock content\n'),
                mock.call('test-overcloud', 'user-files/othercustomfile.yaml',
                          'user-files/othercustomfile.yaml: mock content\n'),
            ],
            any_order=True,
        )
        mock_run_playbook.assert_called_once_with(
            'cli-update-deployment-plan.yaml',
            'undercloud,',
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "container": "test-overcloud",
                "generate_passwords": True,
                "validate": False,
                "disable_image_params_prepare": False,
            },
            verbosity=1,
        )

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleo_common.utils.swift.empty_container',
                autospec=True)
    def test_update_plan_from_templates_recreate_env(
            self, mock_empty_container, mock_tarball, mock_run_playbook):

        plan_management.update_plan_from_templates(
            self.app.client_manager,
            'test-overcloud',
            '/tht-root/',
            validate_stack=False)

        mock_empty_container.assert_called_once_with(
            self.object_store, 'test-overcloud')

        # make sure passwords got persisted
        self.object_store.put_object.assert_called_with(
            'test-overcloud', 'plan-environment.yaml',
            'passwords: somepasswords\n'
            'plan-environment.yaml: mock content\n'
        )

        mock_run_playbook.assert_called_once_with(
            'cli-update-deployment-plan.yaml',
            'undercloud,',
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "container": "test-overcloud",
                "generate_passwords": True,
                "validate": False,
                "disable_image_params_prepare": False,
            },
            verbosity=1,
        )

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management._update_passwords',
                autospec=True)
    @mock.patch('yaml.safe_load',
                autospec=True)
    @mock.patch('tripleoclient.workflows.plan_management.tarball',
                autospec=True)
    @mock.patch('tripleo_common.utils.swift.empty_container',
                autospec=True)
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_update_plan_from_templates_recreate_env_missing_passwords(
            self, mock_tmp, mock_cd, mock_empty_container, mock_tarball,
            mock_yaml_safe_load, mock_update_passwords, mock_run_playbook):
        plan_management.update_plan_from_templates(
            self.app.client_manager,
            'test-overcloud',
            '/tht-root/',
            validate_stack=False,
            disable_image_params_prepare=True)
        # A dictionary without the "passwords" key is provided in
        # the _load_passwords method.
        mock_yaml_safe_load.return_value = {}
        # Ensure that the passwords variable is passed with a value of None.
        mock_update_passwords.assert_called_with(
            mock.ANY, 'test-overcloud', None)
        mock_run_playbook.assert_called_once_with(
            'cli-update-deployment-plan.yaml',
            'undercloud,',
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "container": "test-overcloud",
                "generate_passwords": True,
                "validate": False,
                "disable_image_params_prepare": True,
            },
            verbosity=1,
        )


class TestUpdatePasswords(base.TestCase):

    YAML_CONTENTS = """version: 1.0
name: overcloud
template: overcloud.yaml
parameter_defaults:
  ControllerCount: 7
"""

    def setUp(self):
        super(TestUpdatePasswords, self).setUp()
        self.swift_client = mock.MagicMock()
        self.swift_client.get_object.return_value = ({}, self.YAML_CONTENTS)

        self.plan_name = "overcast"

    def test_update_passwords(self):
        plan_management._update_passwords(self.swift_client,
                                          self.plan_name,
                                          {'AdminPassword': "1234"})

        self.swift_client.put_object.assert_called_once()
        result = self.swift_client.put_object.call_args_list[0][0][2]

        # Check new data is in
        self.assertIn("passwords:\n", result)
        self.assertIn("\n  AdminPassword: '1234'", result)
        # Check previous data still is too
        self.assertIn("name: overcloud", result)

    def test_no_passwords(self):
        plan_management._update_passwords(self.swift_client,
                                          self.plan_name,
                                          [])

        self.swift_client.put_object.assert_not_called()

    def test_no_plan_environment(self):
        self.swift_client.get_object.side_effect = (
            swift_exc.ClientException("404"))

        plan_management._update_passwords(self.swift_client,
                                          self.plan_name,
                                          {'SecretPassword': 'abcd'})

        self.swift_client.put_object.assert_not_called()
