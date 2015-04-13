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

import tempfile

import json
import mock
import os

from rdomanager_oscplugin.tests.v1.baremetal import fakes
from rdomanager_oscplugin.v1 import baremetal


class TestImport(fakes.TestBaremetal):

    def setUp(self):
        super(TestImport, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.ImportPlugin(self.app, None)

        self.csv_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.json_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.instack_json = tempfile.NamedTemporaryFile(mode='w', delete=False)

        self.csv_file.write("""\
pxe_ssh,192.168.122.1,root,"KEY1",00:d0:28:4c:e8:e8
pxe_ssh,192.168.122.1,root,"KEY2",00:7c:ef:3d:eb:60""")

        json.dump([{
            "pm_user": "stack",
            "pm_addr": "192.168.122.1",
            "pm_password": "KEY1",
            "pm_type": "pxe_ssh",
            "mac": [
                "00:0b:d0:69:7e:59"
            ],
        }, {
            "arch": "x86_64",
            "pm_user": "stack",
            "pm_addr": "192.168.122.2",
            "pm_password": "KEY2",
            "pm_type": "pxe_ssh",
            "mac": [
                "00:0b:d0:69:7e:58"
            ]
        }], self.json_file)

        json.dump({
            "nodes": [{
                "pm_user": "stack",
                "pm_addr": "192.168.122.1",
                "pm_password": "KEY1",
                "pm_type": "pxe_ssh",
                "mac": [
                    "00:0b:d0:69:7e:59"
                ],
            }, {
                "arch": "x86_64",
                "pm_user": "stack",
                "pm_addr": "192.168.122.2",
                "pm_password": "KEY2",
                "pm_type": "pxe_ssh",
                "mac": [
                    "00:0b:d0:69:7e:58"
                ]
            }]
        }, self.instack_json)

        self.csv_file.close()
        self.json_file.close()
        self.instack_json.close()

    def tearDown(self):

        super(TestImport, self).tearDown()
        os.unlink(self.csv_file.name)
        os.unlink(self.json_file.name)
        os.unlink(self.instack_json.name)

    @mock.patch('os_cloud_config.nodes.register_all_nodes')
    def test_json_import(self, mock_register_nodes):

        arglist = [self.json_file.name, '--json', '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', True),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_register_nodes.assert_called_with(
            'http://localhost',
            [
                {
                    'pm_password': 'KEY1',
                    'pm_type': 'pxe_ssh',
                    'pm_user': 'stack',
                    'pm_addr': '192.168.122.1',
                    'mac': ['00:0b:d0:69:7e:59']
                }, {
                    'pm_user': 'stack',
                    'pm_password': 'KEY2',
                    'pm_addr': '192.168.122.2',
                    'arch': 'x86_64',
                    'pm_type': 'pxe_ssh',
                    'mac': ['00:0b:d0:69:7e:58']
                }
            ],
            client=self.app.client_manager.rdomanager_oscplugin.baremetal(),
            keystone_client=None)

    @mock.patch('os_cloud_config.nodes.register_all_nodes')
    def test_instack_json_import(self, mock_register_nodes):

        arglist = [self.instack_json.name, '--json', '-s', 'http://localhost']

        verifylist = [
            ('csv', False),
            ('json', True),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_register_nodes.assert_called_with(
            'http://localhost',
            [
                {
                    'pm_password': 'KEY1',
                    'pm_type': 'pxe_ssh',
                    'pm_user': 'stack',
                    'pm_addr': '192.168.122.1',
                    'mac': ['00:0b:d0:69:7e:59']
                }, {
                    'pm_user': 'stack',
                    'pm_password': 'KEY2',
                    'pm_addr': '192.168.122.2',
                    'arch': 'x86_64',
                    'pm_type': 'pxe_ssh',
                    'mac': ['00:0b:d0:69:7e:58']
                }
            ],
            client=self.app.client_manager.rdomanager_oscplugin.baremetal(),
            keystone_client=None)

    @mock.patch('os_cloud_config.nodes.register_all_nodes')
    def test_csv_import(self, mock_register_nodes):

        arglist = [self.csv_file.name, '--csv', '-s', 'http://localhost']

        verifylist = [
            ('csv', True),
            ('json', False),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_register_nodes.assert_called_with(
            'http://localhost',
            [
                {
                    'pm_password': 'KEY1',
                    'pm_user': 'root',
                    'pm_type': 'pxe_ssh',
                    'pm_addr': '192.168.122.1',
                    'mac': ['00:d0:28:4c:e8:e8']
                }, {
                    'pm_password': 'KEY2',
                    'pm_user': 'root',
                    'pm_type': 'pxe_ssh',
                    'pm_addr': '192.168.122.1',
                    'mac': ['00:7c:ef:3d:eb:60']
                }
            ],
            client=self.app.client_manager.rdomanager_oscplugin.baremetal(),
            keystone_client=None)


class TestIntrospectionAll(fakes.TestBaremetal):

    def setUp(self):
        super(TestIntrospectionAll, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.IntrospectionAllPlugin(self.app, None)

    @mock.patch('ironic_discoverd.client.introspect')
    def test_introspect_all_one(self, discoverd_mock):

        client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH")
        ]

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        discoverd_mock.assert_called_once_with(
            'ABCDEFGH', base_url=None, auth_token='TOKEN')

    @mock.patch('ironic_discoverd.client.introspect')
    def test_introspect_all(self, discoverd_mock):

        client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH"),
            mock.Mock(uuid="IJKLMNOP"),
            mock.Mock(uuid="QRSTUVWX"),
        ]

        parsed_args = self.check_parser(self.cmd, [], [])
        self.cmd.take_action(parsed_args)

        discoverd_mock.assert_has_calls([
            mock.call('ABCDEFGH', base_url=None, auth_token='TOKEN'),
            mock.call('IJKLMNOP', base_url=None, auth_token='TOKEN'),
            mock.call('QRSTUVWX', base_url=None, auth_token='TOKEN'),
        ])


class TestStatusAll(fakes.TestBaremetal):

    def setUp(self):
        super(TestStatusAll, self).setUp()

        # Get the command object to test
        self.cmd = baremetal.StatusAllPlugin(self.app, None)

    @mock.patch('ironic_discoverd.client.get_status')
    def test_introspect_all_one(self, discoverd_mock):

        client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH")
        ]

        discoverd_mock.return_value = {
            'finished': False, 'error': None
        }

        parsed_args = self.check_parser(self.cmd, [], [])
        result = self.cmd.take_action(parsed_args)

        discoverd_mock.assert_called_once_with(
            'ABCDEFGH', base_url=None, auth_token='TOKEN')

        self.assertEqual(result, (
            ('Node UUID', 'Finished', 'Error'),
            [('ABCDEFGH', False, None)]))

    @mock.patch('ironic_discoverd.client.get_status')
    def test_introspect_all(self, discoverd_mock):

        client = self.app.client_manager.rdomanager_oscplugin.baremetal()
        client.node.list.return_value = [
            mock.Mock(uuid="ABCDEFGH"),
            mock.Mock(uuid="IJKLMNOP"),
            mock.Mock(uuid="QRSTUVWX"),
        ]

        discoverd_mock.return_value = {
            'finished': False, 'error': None
        }

        parsed_args = self.check_parser(self.cmd, [], [])
        result = self.cmd.take_action(parsed_args)

        discoverd_mock.assert_has_calls([
            mock.call('ABCDEFGH', base_url=None, auth_token='TOKEN'),
            mock.call('IJKLMNOP', base_url=None, auth_token='TOKEN'),
            mock.call('QRSTUVWX', base_url=None, auth_token='TOKEN'),
        ])

        self.assertEqual(result, (
            ('Node UUID', 'Finished', 'Error'),
            [
                ('ABCDEFGH', False, None),
                ('IJKLMNOP', False, None),
                ('QRSTUVWX', False, None)
            ]
        ))
