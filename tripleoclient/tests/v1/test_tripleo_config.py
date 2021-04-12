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
#
"""Tests for the tripleoclient.v1.tripleo_config

Tests basic parser behavior, with both default and user supplied
values of arguments.
Further assertions are placed on results of the parser.
"""
from unittest import mock

from tripleoclient.tests import base

from tripleoclient.constants import UNDERCLOUD_OUTPUT_DIR
from tripleoclient.v1 import tripleo_config


class TestGenerateAnsibleConfig(base.TestCommand):

    def setUp(self):
        super(TestGenerateAnsibleConfig, self).setUp()
        self.config = tripleo_config
        self.cmd = tripleo_config.GenerateAnsibleConfig(self.app, None)

    @mock.patch('tripleo_common.utils.ansible.write_default_ansible_cfg')
    @mock.patch(
        'tripleoclient.utils.get_deployment_user',
        return_value='stack')
    @mock.patch('tripleoclient.v1.tripleo_config.logging')
    def test_all_defaults(self, mock_log, mock_deploy_user, mock_ansible):
        defaults = [
            ('deployment_user', 'stack'),
            ('output_dir', UNDERCLOUD_OUTPUT_DIR)]

        parsed_args = self.check_parser(self.cmd, [], defaults)
        self.cmd.take_action(parsed_args)

        mock_ansible.assert_called_once_with(
            UNDERCLOUD_OUTPUT_DIR,
            'stack',
            ssh_private_key=None)

    @mock.patch('tripleo_common.utils.ansible.write_default_ansible_cfg')
    @mock.patch(
        'tripleoclient.utils.get_deployment_user',
        return_value='notastack')
    @mock.patch('tripleoclient.v1.tripleo_config.logging')
    def test_all_defaults_not_matching_deploy_user(self, mock_log,
                                                   mock_deploy_user,
                                                   mock_ansible):
        defaults = [
            ('deployment_user', 'stack'),
            ('output_dir', UNDERCLOUD_OUTPUT_DIR)]

        parsed_args = self.check_parser(self.cmd, [], defaults)
        self.cmd.take_action(parsed_args)

        mock_ansible.assert_called_once_with(
            UNDERCLOUD_OUTPUT_DIR,
            'stack',
            ssh_private_key=None)

    @mock.patch('tripleo_common.utils.ansible.write_default_ansible_cfg')
    @mock.patch(
        'tripleoclient.utils.get_deployment_user',
        return_value='foo')
    @mock.patch('tripleoclient.v1.tripleo_config.logging')
    def test_all_alternate(self, mock_log, mock_deploy_user, mock_ansible):
        defaults = [
            ('deployment_user', 'foo'),
            ('output_dir', '/fizz/buzz')]

        args = ['--deployment-user', 'foo', '--output-dir', '/fizz/buzz']

        parsed_args = self.check_parser(self.cmd, args, defaults)
        self.cmd.take_action(parsed_args)

        mock_ansible.assert_called_once_with(
            '/fizz/buzz',
            'foo',
            ssh_private_key=None)
