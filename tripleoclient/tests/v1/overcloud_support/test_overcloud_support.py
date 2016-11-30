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

import mock


from tripleoclient.tests.v1.overcloud_deploy import fakes
from tripleoclient.v1 import overcloud_support


class TestOvercloudSupportReport(fakes.TestDeployOvercloud):

    def setUp(self):
        super(TestOvercloudSupportReport, self).setUp()

        self.cmd = overcloud_support.ReportExecute(self.app, None)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.app.client_manager.tripleoclient = mock.Mock()
        self.app.client_manager.object_store = mock.Mock()
        self.workflow = self.app.client_manager.workflow_engine
        self.swift = self.app.client_manager.object_store

    @mock.patch('tripleoclient.workflows.support.download_files')
    @mock.patch('tripleoclient.workflows.support.delete_container')
    @mock.patch('tripleoclient.workflows.support.fetch_logs')
    def test_action(self, fetch_logs_mock, delete_container_mock,
                    download_files_mock):
        arglist = ['-c', 'mycontainer', '-t', '60', 'control']
        verifylist = [
            ('server_name', 'control'),
            ('container', 'mycontainer'),
            ('timeout', 60)
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        fetch_logs_mock.assert_called_once_with(self.app.client_manager,
                                                parsed_args.container,
                                                parsed_args.server_name,
                                                timeout=60,
                                                concurrency=None)

        download_files_mock.assert_called_once_with(
            self.app.client_manager, parsed_args.container,
            parsed_args.destination)

        delete_container_mock.assert_called_once_with(self.app.client_manager,
                                                      parsed_args.container,
                                                      timeout=60,
                                                      concurrency=None)

    @mock.patch('tripleoclient.workflows.support.download_files')
    @mock.patch('tripleoclient.workflows.support.delete_container')
    @mock.patch('tripleoclient.workflows.support.fetch_logs')
    def test_action_skip_container_delete(self, fetch_logs_mock,
                                          delete_container_mock,
                                          download_files_mock):
        arglist = ['-c', 'mycontainer', '--skip-container-delete', 'control']
        verifylist = [
            ('server_name', 'control'),
            ('container', 'mycontainer')
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        fetch_logs_mock.assert_called_once_with(self.app.client_manager,
                                                parsed_args.container,
                                                parsed_args.server_name,
                                                timeout=None,
                                                concurrency=None)

        download_files_mock.assert_called_once_with(
            self.app.client_manager, parsed_args.container,
            parsed_args.destination)

        delete_container_mock.assert_not_called()

    @mock.patch('tripleoclient.workflows.support.delete_container')
    @mock.patch('tripleoclient.workflows.support.fetch_logs')
    def test_action_collect_logs_only(self, fetch_logs_mock,
                                      delete_container_mock):
        arglist = ['--collect-only', '-t', '60', '-n', '10', 'control']
        verifylist = [
            ('server_name', 'control'),
            ('collect_only', True),
            ('timeout', 60),
            ('concurrency', 10)
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        fetch_logs_mock.assert_called_once_with(self.app.client_manager,
                                                parsed_args.container,
                                                parsed_args.server_name,
                                                timeout=60,
                                                concurrency=10)
        delete_container_mock.assert_not_called()

    @mock.patch('tripleoclient.workflows.support.download_files')
    @mock.patch('tripleoclient.workflows.support.delete_container')
    @mock.patch('tripleoclient.workflows.support.fetch_logs')
    def test_action_download_logs_only(self, fetch_logs_mock,
                                       delete_container_mock,
                                       download_files_mock):
        arglist = ['--download-only', 'control']
        verifylist = [
            ('server_name', 'control'),
            ('download_only', True),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        fetch_logs_mock.assert_not_called()
        delete_container_mock.assert_not_called()
        download_files_mock.assert_called_once_with(
            self.app.client_manager, parsed_args.container,
            parsed_args.destination)
