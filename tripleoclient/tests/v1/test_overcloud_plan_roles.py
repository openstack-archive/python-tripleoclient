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


class BaseTestCommand(utils.TestCommand):
    def setUp(self):
        super(BaseTestCommand, self).setUp()

        tc = self.app.client_manager.tripleoclient = mock.Mock()
        tc.object_store.get_object.return_value = (
            {},
            '{"result": [{"name":"Controller","description":"Test desc",'
            '"random": "abcd"},{"name":"Test"}]}'
        )
        tc.object_store.get_container.return_value = (
            'container',
            [
                {
                    "name": "Controller",
                    "description": "Test desc",
                    "random": "abcd",
                    "efg": "123",
                    "ServicesDefault": [
                        "b",
                        "c",
                        "a"
                    ]
                }
            ]
        )
        self.tripleoclient = tc


class TestOvercloudListCurrentRoles(BaseTestCommand):

    def setUp(self):
        super(TestOvercloudListCurrentRoles, self).setUp()

        self.cmd = overcloud_plan_roles.ListRoles(self.app, None)

    @mock.patch(
        'tripleo_common.actions.plan.ListRolesAction.run',
        autospec=True,
        return_value=[]
    )
    def test_list_empty_on_non_default_plan(self, mock_list):
        arglist = ['--name', 'overcast', '--current']
        verifylist = [('name', 'overcast'), ('current', True)]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)
        self.assertEqual(0, len(result[1]))

    @mock.patch(
        'tripleo_common.actions.plan.ListRolesAction.run',
        autospec=True,
        return_value=["ObjectStorage", "Controller"]
    )
    def test_list(self, mock_list):
        arglist = ['--current']
        verifylist = [('name', 'overcloud'), ('current', True)]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)
        self.assertEqual(2, len(result[1]))
        self.assertEqual([('Controller',), ('ObjectStorage',)], result[1])

    @mock.patch(
        'tripleo_common.actions.plan.ListRolesAction.run',
        autospec=True,
        return_value=[
            {
                "name": "Controller",
                "description": "Test desc",
                "random": "abcd"
            },
            {"name": "Test"}
        ]
    )
    def test_list_with_details(self, mock_list):
        parsed_args = self.check_parser(self.cmd,
                                        ['--current', '--detail'],
                                        [])
        result = self.cmd.take_action(parsed_args)

        data = result[1]
        self.assertEqual(2, len(data))

        self.assertEqual(data[0][0], "Controller")
        self.assertEqual(data[0][3], "random: abcd")
        self.assertEqual(data[1][0], "Test")
        self.assertEqual(data[1][3], "")

    @mock.patch(
        'tripleo_common.actions.plan.ListRolesAction.run',
        autospec=True,
        return_value=[]
    )
    def test_list_with_details_empty(self, mock_list):
        parsed_args = self.check_parser(self.cmd,
                                        ['--current', '--detail'],
                                        [])
        result = self.cmd.take_action(parsed_args)

        self.assertEqual(0, len(result[1]))

    @mock.patch(
        'tripleo_common.actions.plan.ListRolesAction.run',
        autospec=True,
        return_value=[
            {"name": "Compute"},
            {"name": "Random"},
            {"name": "BlockStorage", "ServicesDefault": ["c", "b", "a"]}
        ]
    )
    def test_list_with_details_sorted(self, mock_list):

        parsed_args = self.check_parser(self.cmd,
                                        ['--current', '--detail'],
                                        [])
        result = self.cmd.take_action(parsed_args)

        self.assertEqual(3, len(result[1]))

        # Test main list sorted
        self.assertEqual(result[1][0][0], "BlockStorage")
        self.assertEqual(result[1][1][0], "Compute")
        self.assertEqual(result[1][2][0], "Random")

        # Test service sublist sorted
        self.assertEqual(result[1][0][2], "a\nb\nc")


class TestOvercloudShowRole(BaseTestCommand):

    def setUp(self):
        super(TestOvercloudShowRole, self).setUp()

        self.cmd = overcloud_plan_roles.ShowRole(self.app, None)

        self.app.client_manager.tripleoclient = self.tripleoclient

    @mock.patch(
        'tripleo_common.actions.plan.ListRolesAction.run',
        autospec=True,
        return_value=[]
    )
    def test_role_not_found(self, mock_list):
        arglist = ['--name', 'overcast', 'doesntexist']
        verifylist = [('name', 'overcast'), ('role', 'doesntexist')]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaises(exceptions.CommandError,
                          self.cmd.take_action,
                          parsed_args)
