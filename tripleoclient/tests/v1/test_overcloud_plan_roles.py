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

from osc_lib import exceptions
from osc_lib.tests import utils

from tripleoclient.v1 import overcloud_plan_roles


class TestOvercloudListCurrentRoles(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudListCurrentRoles, self).setUp()

        self.cmd = overcloud_plan_roles.ListRoles(self.app, None)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine

    def test_list_empty_on_non_default_plan(self):
        self.workflow.action_executions.create.return_value = (
            mock.Mock(output='{"result": []}'))

        arglist = ['--name', 'overcast', '--current']
        verifylist = [('name', 'overcast'), ('current', True)]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.role.list',
            {'container': 'overcast', 'detail': False},
            run_sync=True, save_result=True
        )
        self.assertEqual(0, len(result[1]))

    def test_list(self):
        self.workflow.action_executions.create.return_value = (
            mock.MagicMock(
                output='{"result": ["ObjectStorage", "Controller"]}'))

        arglist = ['--current']
        verifylist = [('name', 'overcloud'), ('current', True)]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.role.list',
            {'container': 'overcloud', 'detail': False},
            run_sync=True, save_result=True
        )

        self.assertEqual(2, len(result[1]))
        self.assertEqual([('Controller',), ('ObjectStorage',)], result[1])

    def test_list_with_details(self):
        self.workflow.action_executions.create.return_value = (
            mock.MagicMock(output=(
                '{"result": [{"name":"Controller","description":"Test desc",'
                '"random": "abcd"},{"name":"Test"}]}')))

        parsed_args = self.check_parser(self.cmd,
                                        ['--current', '--detail'],
                                        [])
        result = self.cmd.take_action(parsed_args)

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.role.list',
            {'container': 'overcloud', 'detail': True},
            run_sync=True, save_result=True
        )

        data = result[1]
        self.assertEqual(2, len(data))

        self.assertEqual(data[0][0], "Controller")
        self.assertEqual(data[0][3], "random: abcd")
        self.assertEqual(data[1][0], "Test")
        self.assertEqual(data[1][3], "")

    def test_list_with_details_empty(self):
        self.workflow.action_executions.create.return_value = (
            mock.Mock(output='{"result": []}'))

        parsed_args = self.check_parser(self.cmd,
                                        ['--current', '--detail'],
                                        [])
        result = self.cmd.take_action(parsed_args)

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.role.list',
            {'container': 'overcloud', 'detail': True},
            run_sync=True, save_result=True
        )
        self.assertEqual(0, len(result[1]))

    def test_list_with_details_sorted(self):
        self.workflow.action_executions.create.return_value = (
            mock.MagicMock(output=(
                '{"result": [{"name":"Compute"},{"name":"Random"},'
                '{"name": "BlockStorage","ServicesDefault":["c","b","a"]}]}')))

        parsed_args = self.check_parser(self.cmd,
                                        ['--current', '--detail'],
                                        [])
        result = self.cmd.take_action(parsed_args)

        self.workflow.action_executions.create.assert_called_once_with(
            'tripleo.role.list',
            {'container': 'overcloud', 'detail': True},
            run_sync=True, save_result=True
        )

        self.assertEqual(3, len(result[1]))

        # Test main list sorted
        self.assertEqual(result[1][0][0], "BlockStorage")
        self.assertEqual(result[1][1][0], "Compute")
        self.assertEqual(result[1][2][0], "Random")

        # Test service sublist sorted
        self.assertEqual(result[1][0][2], "a\nb\nc")


class TestOvercloudListRole(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudListRole, self).setUp()

        self.cmd = overcloud_plan_roles.ListRoles(self.app, None)

        self.workflow = self.app.client_manager.workflow_engine = mock.Mock()
        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient = mock.Mock()
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient

    def test_list_empty(self):
        self.websocket.wait_for_messages.return_value = [{
            'execution': {'id': 'IDID'},
            'status': 'SUCCESS',
            'available_roles': []
        }]

        arglist = ['--name', 'overcast']
        verifylist = [('name', 'overcast')]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.list_available_roles',
            workflow_input={'container': 'overcast'},
        )
        self.assertEqual(0, len(result[1]))

    def test_list(self):
        self.websocket.wait_for_messages.return_value = [{
            'execution': {'id': 'IDID'},
            'status': 'SUCCESS',
            'available_roles': [{'name': 'ObjectStorage'},
                                {'name': 'Compute'}]
        }]

        parsed_args = self.check_parser(self.cmd, [], [('name', 'overcloud')])
        result = self.cmd.take_action(parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.list_available_roles',
            workflow_input={'container': 'overcloud'},
        )

        self.assertEqual(2, len(result[1]))
        self.assertEqual([('Compute',), ('ObjectStorage',)], result[1])

    def test_list_with_details(self):
        self.websocket.wait_for_messages.return_value = [{
            'execution': {'id': 'IDID'},
            'status': 'SUCCESS',
            'available_roles': [
                {'name': 'Controller', 'description': 'Test description',
                 'random': 'abcd'},
                {'name': 'Test'}]
        }]

        parsed_args = self.check_parser(self.cmd, ['--detail'], [])
        result = self.cmd.take_action(parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.list_available_roles',
            workflow_input={'container': 'overcloud'},
        )

        data = result[1]
        self.assertEqual(2, len(data))

        self.assertEqual(data[0][0], "Controller")
        self.assertEqual(data[0][3], "random: abcd")
        self.assertEqual(data[1][0], "Test")
        self.assertEqual(data[1][3], "")


class TestOvercloudShowRole(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudShowRole, self).setUp()

        self.cmd = overcloud_plan_roles.ShowRole(self.app, None)

        self.workflow = self.app.client_manager.workflow_engine = mock.Mock()
        self.websocket = mock.Mock()
        self.websocket.__enter__ = lambda s: self.websocket
        self.websocket.__exit__ = lambda s, *exc: None
        self.tripleoclient = mock.Mock()
        self.tripleoclient.messaging_websocket.return_value = self.websocket
        self.app.client_manager.tripleoclient = self.tripleoclient

    def test_role_not_found(self):
        self.websocket.wait_for_messages.return_value = [{
            'execution': {'id': 'IDID'},
            'status': 'SUCCESS',
            'available_roles': []
        }]

        arglist = ['--name', 'overcast', 'doesntexist']
        verifylist = [('name', 'overcast'), ('role', 'doesntexist')]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaises(exceptions.CommandError,
                          self.cmd.take_action,
                          parsed_args)

    def test_role(self):
        self.websocket.wait_for_messages.return_value = [{
            'execution': {'id': 'IDID'},
            'status': 'SUCCESS',
            'available_roles': [
                {"name": "Test", "a": "b"},
                {"name": "Controller", "description": "Test desc",
                 "random": "abcd", "efg": "123",
                 "ServicesDefault": ["b", "c", "a"]}]}]

        arglist = ['Controller']
        verifylist = [('name', 'overcloud'), ('role', 'Controller')]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)

        self.workflow.executions.create.assert_called_once_with(
            'tripleo.plan_management.v1.list_available_roles',
            workflow_input={'container': 'overcloud'},
        )

        self.assertEqual(len(result), 2)

        # Check that all the columns are picked up correctly
        expected = ['Name', 'Description', 'Services Default', 'efg', 'random']
        actual = result[0]
        self.assertEqual(expected, actual)

        # Check the content
        expected = ['Controller', 'Test desc', "a\nb\nc", '123', 'abcd']
        actual = result[1]
        self.assertEqual(expected, actual)
