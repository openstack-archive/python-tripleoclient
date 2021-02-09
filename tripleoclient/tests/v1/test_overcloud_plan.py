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
import mock

from osc_lib.tests import utils

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import plugin
from tripleoclient.tests import fakes
from tripleoclient.v1 import overcloud_plan


class TestStringCapture(object):
    def __init__(self):
        self.capture_string = ''

    def write(self, msg):
        self.capture_string = self.capture_string + msg

    def getvalue(self):
        return self.capture_string

    def flush(self):
        return


class TestOvercloudPlanList(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudPlanList, self).setUp()
        self.app.client_manager.tripleoclient = plugin.ClientWrapper(
            instance=fakes.FakeInstanceData
        )
        self.cmd = overcloud_plan.ListPlans(self.app, None)

    @mock.patch("tripleoclient.workflows.plan_management."
                "list_deployment_plans",
                autospec=True)
    def test_list_empty(self, mock_list_plans):
        mock_list_plans.return_value = []

        result = self.cmd.take_action(None)

        self.assertEqual(0, len(result[1]))

    @mock.patch("tripleoclient.workflows.plan_management."
                "list_deployment_plans",
                autospec=True)
    def test_list(self, mock_list_plans):
        mock_list_plans.return_value = (['test-plan-1', 'test-plan-2'])

        result = self.cmd.take_action(None)

        self.assertEqual(1, len(result[0]))
        self.assertEqual([('test-plan-1',), ('test-plan-2',)], result[1])


class TestOvercloudDeletePlan(fakes.FakePlaybookExecution):

    def setUp(self):
        super(TestOvercloudDeletePlan, self).setUp()

        self.cmd = overcloud_plan.DeletePlan(self.app, None)

    @mock.patch("tripleo_common.actions.plan.DeletePlanAction.run",
                return_value=None)
    def test_delete_plan(self, mock_run):
        parsed_args = self.check_parser(self.cmd, ['test-plan'],
                                        [('plans', ['test-plan'])])

        self.cmd.take_action(parsed_args)

    @mock.patch("tripleo_common.actions.plan.DeletePlanAction.run",
                return_value=None)
    def test_delete_multiple_plans(self, mock_run):
        argslist = ['test-plan1', 'test-plan2']
        verifylist = [('plans', ['test-plan1', 'test-plan2'])]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.cmd.take_action(parsed_args)


class TestOvercloudCreatePlan(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudCreatePlan, self).setUp()

        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.options = fakes.FakeOptions()
        self.cmd = overcloud_plan.CreatePlan(self.app, app_args)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.tripleoclient = mock.Mock()
        self.app.client_manager.tripleoclient = self.tripleoclient

        self.swift = self.app.client_manager.tripleoclient.object_store
        self.swift.get_account = mock.MagicMock()

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_create_default_plan(self, mock_tmp, mock_cd, mock_run_playbook):

        # Setup
        arglist = ['overcast']
        verifylist = [
            ('name', 'overcast'),
            ('templates', None)
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # Run
        self.cmd.take_action(parsed_args)

        # Verify
        mock_run_playbook.assert_called_once_with(
            'cli-create-deployment-plan.yaml',
            'undercloud,',
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "container": "overcast",
                "generate_passwords": True,
                "validate": False,
                "disable_image_params_prepare": False,
            },
            verbosity=3,
        )

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch("tripleoclient.workflows.plan_management.tarball")
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_create_custom_plan(self, mock_tmp, mock_cd, mock_tarball,
                                mock_run_playbook):

        # Setup
        arglist = ['overcast', '--templates', '/fake/path']
        verifylist = [
            ('name', 'overcast'),
            ('templates', '/fake/path')
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # Run
        self.cmd.take_action(parsed_args)

        # Verify
        mock_run_playbook.assert_called_once_with(
            'cli-create-deployment-plan.yaml',
            'undercloud,',
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "container": "overcast",
                "generate_passwords": True,
                "validate": False,
                "disable_image_params_prepare": False,
            },
            verbosity=3,
        )
        self.swift.get_account.assert_called_once()

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch("tripleoclient.workflows.plan_management.tarball")
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_create_custom_plan_plan_environment_file(
            self, mock_tmp, mock_cd, mock_tarball, mock_run_playbook):
        # Setup
        arglist = ['overcast', '--templates', '/fake/path',
                   '-p', 'the_plan_environment.yaml']
        verifylist = [
            ('name', 'overcast'),
            ('templates', '/fake/path'),
            ('plan_environment_file', 'the_plan_environment.yaml')
        ]
        self.app.options = fakes.FakeOptions()
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        mock_open = mock.mock_open()
        # Run
        with mock.patch('six.moves.builtins.open', mock_open):
            self.cmd.take_action(parsed_args)

        mock_open.assert_has_calls(
            [mock.call('the_plan_environment.yaml', 'rb')])

        # Verify
        mock_run_playbook.assert_called_once_with(
            'cli-create-deployment-plan.yaml',
            'undercloud,',
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "container": "overcast",
                "generate_passwords": True,
                "plan_environment": "the_plan_environment.yaml",
                "validate": False,
                "disable_image_params_prepare": False,
            },
            verbosity=3,
        )
        self.swift.get_account.assert_called_once()

    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_create_default_plan_with_password_gen_disabled(
            self, mock_tmp, mock_cd, mock_run_playbook):

        # Setup
        arglist = ['overcast', '--disable-password-generation',
                   '--disable-container-prepare']
        verifylist = [
            ('name', 'overcast'),
            ('templates', None),
            ('disable_password_generation', True),
            ('disable_container_prepare', True)
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # Run
        self.app.options = fakes.FakeOptions()
        self.cmd.take_action(parsed_args)
        # Verify
        mock_run_playbook.assert_called_once_with(
            'cli-create-deployment-plan.yaml',
            'undercloud,',
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "container": "overcast",
                "generate_passwords": False,
                "validate": False,
                "disable_image_params_prepare": True,
            },
            verbosity=3,
        )


class TestOvercloudDeployPlan(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudDeployPlan, self).setUp()

        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.options = fakes.FakeOptions()
        self.cmd = overcloud_plan.DeployPlan(self.app, app_args)

        sleep_patch = mock.patch('time.sleep')
        self.addCleanup(sleep_patch.stop)
        sleep_patch.start()

    @mock.patch("tripleoclient.utils.update_deployment_status", autospec=True)
    @mock.patch("tripleoclient.utils.run_ansible_playbook", autospec=True)
    @mock.patch('tripleoclient.utils.wait_for_stack_ready', autospec=True)
    @mock.patch('os.chdir', autospec=True)
    @mock.patch('tempfile.mkdtemp', autospec=True)
    def test_overcloud_deploy_plan(self, mock_tmp, mock_cd,
                                   mock_for_stack_ready,
                                   mock_run_playbook,
                                   mock_update_status):

        # Setup
        arglist = ['--run-validations', 'overcast']
        verifylist = [
            ('name', 'overcast'),
            ('run_validations', True),
            ('timeout', 240)
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.orch = self.app.client_manager.orchestration = mock.Mock()
        # No existing stack, this is a new deploy.
        self.orch.stacks.get.return_value = None

        mock_for_stack_ready.return_value = True

        # Run
        self.cmd.take_action(parsed_args)

        mock_run_playbook.assert_called_once_with(
            'cli-deploy-deployment-plan.yaml',
            'undercloud,',
            mock.ANY,
            constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            timeout=240,
            extra_vars={
                "container": "overcast",
                "run_validations": True,
                "skip_deploy_identifier": False,
            },
            verbosity=3,
        )
        mock_update_status.assert_called()


class TestOvercloudExportPlan(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudExportPlan, self).setUp()
        self.cmd = overcloud_plan.ExportPlan(self.app, None)
        self.app.client_manager = mock.Mock()
        self.clients = self.app.client_manager

        # Mock urlopen
        f = mock.Mock()
        f.read.return_value = 'tarball contents'
        urlopen_patcher = mock.patch('six.moves.urllib.request.urlopen',
                                     return_value=f)
        self.mock_urlopen = urlopen_patcher.start()
        self.addCleanup(self.mock_urlopen.stop)

    @mock.patch(
        'tripleoclient.workflows.plan_management.export_deployment_plan',
        autospec=True)
    def test_export_plan(self, export_deployment_plan_mock):
        parsed_args = self.check_parser(self.cmd, ['test-plan'],
                                        [('plan', 'test-plan')])

        export_deployment_plan_mock.return_value = 'http://fake-url.com'

        with mock.patch('six.moves.builtins.open', mock.mock_open()):
            self.cmd.take_action(parsed_args)

        export_deployment_plan_mock.assert_called_once_with(
            self.clients, 'test-plan')

    @mock.patch('os.path.exists')
    def test_export_plan_outfile_exists(self, exists_mock):
        parsed_args = self.check_parser(self.cmd, ['test-plan'],
                                        [('plan', 'test-plan')])

        exists_mock.return_value = True

        self.assertRaises(exceptions.PlanExportError,
                          self.cmd.take_action, parsed_args)

    @mock.patch(
        'tripleoclient.workflows.plan_management.export_deployment_plan',
        autospec=True)
    @mock.patch('os.path.exists')
    def test_export_plan_outfile_exists_with_overwrite(
            self, exists_mock, export_deployment_plan_mock):
        arglist = ['-f', 'test-plan']
        verifylist = [
            ('plan', 'test-plan'),
            ('force_overwrite', True)
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        exists_mock.return_value = True
        export_deployment_plan_mock.return_value = 'http://fake-url.com'

        with mock.patch('six.moves.builtins.open', mock.mock_open()):
            self.cmd.take_action(parsed_args)

        export_deployment_plan_mock.assert_called_once_with(
            self.clients, 'test-plan')
