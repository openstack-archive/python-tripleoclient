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

from tripleoclient.tests.v1.test_plugin import TestPluginV1
from tripleoclient.v1 import container_image


class TestContainerImageUpload(TestPluginV1):

    def setUp(self):
        super(TestContainerImageUpload, self).setUp()

        # Get the command object to test
        self.cmd = container_image.UploadImage(self.app, None)

    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager',
                autospec=True)
    def test_container_image_upload_noargs(self, mock_manager):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_manager.assert_called_once_with([])
        mock_manager.return_value.upload.assert_called_once_with()

    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager',
                autospec=True)
    def test_container_image_upload_conf_files(self, mock_manager):
        arglist = [
            '--config-file',
            '/tmp/foo.yaml',
            '--config-file',
            '/tmp/bar.yaml'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_manager.assert_called_once_with(
            ['/tmp/foo.yaml', '/tmp/bar.yaml'])
        mock_manager.return_value.upload.assert_called_once_with()


class TestContainerImageBuild(TestPluginV1):

    def setUp(self):
        super(TestContainerImageBuild, self).setUp()

        # Get the command object to test
        self.cmd = container_image.BuildImage(self.app, None)

    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder',
                autospec=True)
    def test_container_image_build_noargs(self, mock_builder):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_builder.assert_called_once_with([])
        mock_builder.return_value.build_images.assert_called_once_with([])

    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder',
                autospec=True)
    def test_container_image_build(self, mock_builder):
        arglist = [
            '--config-file',
            '/tmp/foo.yaml',
            '--config-file',
            '/tmp/bar.yaml',
            '--kolla-config-file',
            '/tmp/kolla.conf'
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_builder.assert_called_once_with([
            '/tmp/foo.yaml', '/tmp/bar.yaml'])
        mock_builder.return_value.build_images.assert_called_once_with([
            '/tmp/kolla.conf'
        ])
