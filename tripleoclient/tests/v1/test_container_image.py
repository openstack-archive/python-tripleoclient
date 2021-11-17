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

from io import StringIO
import os
import shutil
import tempfile
from urllib import parse
import yaml
from unittest import mock

from osc_lib import exceptions as oscexc
from tripleo_common.image import kolla_builder
from tripleoclient.tests.v1.test_plugin import TestPluginV1
from tripleoclient.v1 import container_image


class TestContainerImagePush(TestPluginV1):
    def setUp(self):
        super(TestContainerImagePush, self).setUp()

        lock = mock.patch('tripleo_common.utils.locks.processlock.ProcessLock')
        self.mock_lock = lock.start()
        self.addCleanup(lock.stop)

        self.cmd = container_image.TripleOContainerImagePush(self.app, None)

    @mock.patch('tripleo_common.image.image_uploader.get_undercloud_registry',
                return_value='uc.ctlplane.somedomain')
    @mock.patch('tripleo_common.image.image_uploader.UploadTask')
    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager')
    def test_take_action(self, mock_manager, mock_task, mock_get_uc_registry):
        arglist = ['docker.io/namespace/foo']
        verifylist = [('image_to_push', 'docker.io/namespace/foo')]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # mock manager object
        mock_mgr = mock.Mock()
        mock_manager.return_value = mock_mgr

        # mock uploader object
        mock_uploader = mock.Mock()
        mock_mgr.uploader.return_value = mock_uploader

        # mock return session object from uploader.authenticate
        mock_session = mock.Mock()
        mock_uploader.authenticate.return_value = mock_session

        # mock upload task
        mock_uploadtask = mock.Mock()
        mock_task.return_value = mock_uploadtask

        # mock add upload task action
        mock_add_upload = mock.Mock()
        data = []
        mock_add_upload.return_value = data
        mock_uploader.add_upload_task = mock_add_upload

        # mock run tasks action
        mock_run_tasks = mock.Mock()
        mock_uploader.run_tasks = mock_run_tasks

        self.cmd.take_action(parsed_args)

        mock_task.assert_called_once_with(
                image_name='namespace/foo',
                pull_source='docker.io',
                push_destination='uc.ctlplane.somedomain',
                append_tag=parsed_args.append_tag,
                modify_role=None,
                modify_vars=None,
                cleanup=False,
                multi_arch=parsed_args.multi_arch)

        mock_add_upload.assert_called_once_with(mock_uploadtask)
        mock_run_tasks.assert_called_once()

    @mock.patch('tripleo_common.image.image_uploader.get_undercloud_registry',
                return_value='uc.ctlplane.somedomain')
    @mock.patch('tripleo_common.image.image_uploader.UploadTask')
    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager')
    def test_take_action_local(self, mock_manager, mock_task,
                               mock_get_uc_registry):
        arglist = ['docker.io/namespace/foo', '--local']
        verifylist = [('image_to_push', 'docker.io/namespace/foo'),
                      ('local', True)]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # mock manager object
        mock_mgr = mock.Mock()
        mock_manager.return_value = mock_mgr

        # mock uploader object
        mock_uploader = mock.Mock()
        mock_mgr.uploader.return_value = mock_uploader

        # mock return session object from uploader.authenticate
        mock_session = mock.Mock()
        mock_uploader.authenticate.return_value = mock_session

        # mock upload task
        mock_uploadtask = mock.Mock()
        mock_task.return_value = mock_uploadtask

        # mock add upload task action
        mock_add_upload = mock.Mock()
        data = []
        mock_add_upload.return_value = data
        mock_uploader.add_upload_task = mock_add_upload

        # mock run tasks action
        mock_run_tasks = mock.Mock()
        mock_uploader.run_tasks = mock_run_tasks

        self.cmd.take_action(parsed_args)

        mock_task.assert_called_once_with(
                image_name='containers-storage:docker.io/namespace/foo',
                pull_source=None,
                push_destination='uc.ctlplane.somedomain',
                append_tag=parsed_args.append_tag,
                modify_role=None,
                modify_vars=None,
                cleanup=False,
                multi_arch=parsed_args.multi_arch)

        mock_add_upload.assert_called_once_with(mock_uploadtask)
        mock_run_tasks.assert_called_once()

    @mock.patch('tripleo_common.image.image_uploader.get_undercloud_registry',
                return_value='uc.ctlplane.somedomain')
    @mock.patch('tripleo_common.image.image_uploader.UploadTask')
    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager')
    def test_take_action_local_path(self, mock_manager, mock_task,
                                    mock_get_uc_registry):
        arglist = ['containers-storage:docker.io/namespace/foo']
        verifylist = [('image_to_push',
                       'containers-storage:docker.io/namespace/foo')]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # mock manager object
        mock_mgr = mock.Mock()
        mock_manager.return_value = mock_mgr

        # mock uploader object
        mock_uploader = mock.Mock()
        mock_mgr.uploader.return_value = mock_uploader

        # mock return session object from uploader.authenticate
        mock_session = mock.Mock()
        mock_uploader.authenticate.return_value = mock_session

        # mock upload task
        mock_uploadtask = mock.Mock()
        mock_task.return_value = mock_uploadtask

        # mock add upload task action
        mock_add_upload = mock.Mock()
        data = []
        mock_add_upload.return_value = data
        mock_uploader.add_upload_task = mock_add_upload

        # mock run tasks action
        mock_run_tasks = mock.Mock()
        mock_uploader.run_tasks = mock_run_tasks

        self.cmd.take_action(parsed_args)

        mock_task.assert_called_once_with(
                image_name='containers-storage:docker.io/namespace/foo',
                pull_source=None,
                push_destination='uc.ctlplane.somedomain',
                append_tag=parsed_args.append_tag,
                modify_role=None,
                modify_vars=None,
                cleanup=False,
                multi_arch=parsed_args.multi_arch)

        mock_add_upload.assert_called_once_with(mock_uploadtask)
        mock_run_tasks.assert_called_once()

    @mock.patch('tripleo_common.image.image_uploader.get_undercloud_registry',
                return_value='uc.ctlplane.somedomain')
    @mock.patch('tripleo_common.image.image_uploader.UploadTask')
    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager')
    def test_take_action_oserror(self, mock_manager, mock_task,
                                 mock_get_uc_registry):
        arglist = ['docker.io/namespace/foo']
        verifylist = [('image_to_push', 'docker.io/namespace/foo')]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # mock manager object
        mock_mgr = mock.Mock()
        mock_manager.return_value = mock_mgr

        # mock uploader object
        mock_uploader = mock.Mock()
        mock_mgr.uploader.return_value = mock_uploader

        # mock return session object from uploader.authenticate
        mock_session = mock.Mock()
        mock_uploader.authenticate.return_value = mock_session

        # mock upload task
        mock_uploadtask = mock.Mock()
        mock_task.return_value = mock_uploadtask

        # mock add upload task action
        mock_add_upload = mock.Mock()
        data = []
        mock_add_upload.return_value = data
        mock_uploader.add_upload_task = mock_add_upload

        # mock run tasks action
        mock_run_tasks = mock.Mock()
        mock_run_tasks.side_effect = OSError('Fail')
        mock_uploader.run_tasks = mock_run_tasks

        self.assertRaises(oscexc.CommandError,
                          self.cmd.take_action,
                          parsed_args)

    @mock.patch('tripleo_common.image.image_uploader.get_undercloud_registry',
                return_value='uc.ctlplane.somedomain')
    @mock.patch('tripleo_common.image.image_uploader.UploadTask')
    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager')
    def test_take_action_all_options(self, mock_manager, mock_task,
                                     mock_get_uc_registry):
        arglist = ['--registry-url', '127.0.0.1:8787',
                   '--append-tag', 'test',
                   '--source-username', 'sourceuser',
                   '--source-password', 'sourcepassword',
                   '--username', 'user',
                   '--password', 'password',
                   '--dry-run',
                   '--multi-arch',
                   '--cleanup',
                   'docker.io/namespace/foo:tag']
        verifylist = [('registry_url', '127.0.0.1:8787'),
                      ('append_tag', 'test'),
                      ('username', 'user'),
                      ('password', 'password'),
                      ('dry_run', True),
                      ('multi_arch', True),
                      ('cleanup', True),
                      ('image_to_push', 'docker.io/namespace/foo:tag')]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # mock manager object
        mock_mgr = mock.Mock()
        mock_manager.return_value = mock_mgr

        # mock uploader object
        mock_uploader = mock.Mock()
        mock_mgr.uploader.return_value = mock_uploader

        # mock return session object from uploader.authenticate
        mock_session = mock.Mock()
        mock_uploader.authenticate.return_value = mock_session

        # mock upload task
        mock_uploadtask = mock.Mock()
        mock_task.return_value = mock_uploadtask

        # mock add upload task action
        mock_add_upload = mock.Mock()
        data = []
        mock_add_upload.return_value = data
        mock_uploader.add_upload_task = mock_add_upload

        # mock run tasks action
        mock_run_tasks = mock.Mock()
        mock_uploader.run_tasks = mock_run_tasks

        self.cmd.take_action(parsed_args)

        source_url = parse.urlparse("docker://docker.io/namespace/foo:tag")
        registry_url = parse.urlparse("docker://127.0.0.1:8787")
        auth_calls = [mock.call(source_url,
                                parsed_args.source_username,
                                parsed_args.source_password),
                      mock.call(registry_url,
                                parsed_args.username,
                                parsed_args.password)]
        mock_uploader.authenticate.assert_has_calls(auth_calls)

        mock_task.assert_not_called()
        mock_add_upload.assert_not_called()
        mock_run_tasks.assert_not_called()


class TestContainerImageDelete(TestPluginV1):

    def setUp(self):
        super(TestContainerImageDelete, self).setUp()

        lock = mock.patch('tripleo_common.utils.locks.processlock.ProcessLock')
        self.mock_lock = lock.start()
        self.addCleanup(lock.stop)

        self.cmd = container_image.TripleOContainerImageDelete(self.app, None)

    @mock.patch('tripleo_common.image.image_uploader.get_undercloud_registry',
                return_value='uc.ctlplane.somedomain')
    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager')
    def test_oserror(self, mock_manager, mock_get_uc_registry):

        arglist = ['-y', 'foo']
        verifylist = [('yes', True),
                      ('image_to_delete', 'foo')]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # mock manager object
        mock_mgr = mock.Mock()
        mock_manager.return_value = mock_mgr

        # mock uploader object
        mock_uploader = mock.Mock()
        mock_mgr.uploader.return_value = mock_uploader

        # mock return url object from uploader._image_to_url
        mock_url = mock.Mock()
        mock_url.geturl.return_value = 'munged-reg-url'

        mock_uploader._image_to_url.return_value = mock_url

        # mock return session object from uploader.authenticate
        mock_session = mock.Mock()
        mock_uploader.authenticate.return_value = mock_session

        mock_uploader.delete.side_effect = OSError('Errno 13')
        self.assertRaises(oscexc.CommandError,
                          self.cmd.take_action,
                          parsed_args)
        mock_uploader.delete.assert_called_once_with('foo',
                                                     session=mock_session)


class TestContainerImageList(TestPluginV1):

    def setUp(self):
        super(TestContainerImageList, self).setUp()

        lock = mock.patch('tripleo_common.utils.locks.processlock.ProcessLock')
        self.mock_lock = lock.start()
        self.addCleanup(lock.stop)

        self.cmd = container_image.TripleOContainerImageList(self.app, None)

    @mock.patch('tripleo_common.image.image_uploader.get_undercloud_registry',
                return_value='uc.ctlplane.somedomain')
    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager')
    def test_take_action(self, mock_manager, mock_get_uc_registry):
        arglist = []
        verifylist = []

        mock_manager.return_value.uploader.return_value.list.return_value = \
            ['a', 'b']
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        rv = self.cmd.take_action(parsed_args)
        actual = (('Image Name',), [('a',), ('b',)])
        self.assertEqual(actual, rv)

    @mock.patch('tripleo_common.image.image_uploader.get_undercloud_registry',
                return_value='uc.ctlplane.somedomain')
    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager')
    def test_take_action_auth(self, mock_manager, mock_get_uc_registry):
        # check arg parsing items
        arglist = ['--registry-url', 'reg-url',
                   '--username', 'foo',
                   '--password', 'bar']
        verifylist = [('registry_url', 'reg-url'),
                      ('username', 'foo'),
                      ('password', 'bar')]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # mock manager object
        mock_mgr = mock.Mock()
        mock_manager.return_value = mock_mgr

        # mock uploader object
        mock_uploader = mock.Mock()
        mock_mgr.uploader.return_value = mock_uploader

        # mock return url object from uploader._image_to_url
        mock_url = mock.Mock()
        mock_url.geturl.return_value = 'munged-reg-url'

        mock_uploader._image_to_url.return_value = mock_url

        # mock return session object from uploader.authenticate
        mock_session = mock.Mock()
        mock_uploader.authenticate.return_value = mock_session

        # mock image list function
        mock_uploader.list.return_value = ['a', 'b']

        rv = self.cmd.take_action(parsed_args)

        # check various functions are called with expected inputs
        mock_mgr.uploader.assert_called_with('python')
        mock_uploader._image_to_url.assert_called_with('reg-url')
        mock_uploader.authenticate.assert_called_with(mock_url, 'foo', 'bar')
        mock_uploader.list.assert_called_with('munged-reg-url',
                                              session=mock_session)

        # check data format for lister
        actual = (('Image Name',), [('a',), ('b',)])
        self.assertEqual(actual, rv)


class TestContainerImageShow(TestPluginV1):

    def setUp(self):
        super(TestContainerImageShow, self).setUp()

        lock = mock.patch('tripleo_common.utils.locks.processlock.ProcessLock')
        self.mock_lock = lock.start()
        self.addCleanup(lock.stop)

        self.cmd = container_image.TripleOContainerImageShow(self.app, None)

    @mock.patch('tripleoclient.v1.container_image.TripleOContainerImageShow.'
                'format_image_inspect')
    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager')
    def test_take_action(self, mock_manager, mock_formatter):

        arglist = ['foo']
        verifylist = [('image_to_inspect', 'foo')]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # mock manager object
        mock_mgr = mock.Mock()
        mock_manager.return_value = mock_mgr

        # mock uploader object
        mock_uploader = mock.Mock()
        mock_mgr.uploader.return_value = mock_uploader

        # mock return url object from uploader._image_to_url
        mock_url = mock.Mock()
        mock_url.geturl.return_value = 'munged-reg-url'

        mock_uploader._image_to_url.return_value = mock_url

        # mock return session object from uploader.authenticate
        mock_session = mock.Mock()
        mock_uploader.authenticate.return_value = mock_session
        mock_inspect = mock.Mock()
        data = {'Name': 'a', 'Layers': 'b'}
        mock_inspect.return_value = data
        mock_uploader.inspect = mock_inspect

        # mock format image inspect
        formatted_data = (['Name', 'Layers'], ['a', 'b'])
        mock_formatter.return_value = formatted_data

        rv = self.cmd.take_action(parsed_args)

        mock_formatter.assert_called_once_with(data)
        self.assertEqual(formatted_data, rv)

    def test_format_image_inspect(self):
        test_data = {'Name': 'foo', 'Layers': 'bar'}
        self.assertEqual(self.cmd.format_image_inspect(test_data),
                         (['Name', 'Layers'], ['foo', 'bar']))


class TestTripleoImagePrepareDefault(TestPluginV1):

    def setUp(self):
        super(TestTripleoImagePrepareDefault, self).setUp()
        # Get the command object to test
        self.cmd = container_image.TripleOImagePrepareDefault(self.app, None)

    def test_prepare_default(self):
        arglist = []
        verifylist = []

        self.app.command_options = [
            'tripleo', 'container', 'image', 'prepare', 'default'
        ] + arglist
        self.cmd.app.stdout = StringIO()
        cmd = container_image.TripleOImagePrepareDefault(self.app, None)

        parsed_args = self.check_parser(cmd, arglist, verifylist)
        cmd.take_action(parsed_args)

        result = self.app.stdout.getvalue()
        expected_param = kolla_builder.CONTAINER_IMAGE_PREPARE_PARAM
        expected = {
            'parameter_defaults': {
                'ContainerImagePrepare': expected_param
            }
        }
        self.assertEqual(expected, yaml.safe_load(result))

    def test_prepare_default_local_registry(self):
        temp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp)
        env_file = os.path.join(temp, 'containers_env.yaml')

        arglist = ['--local-push-destination', '--output-env-file', env_file]
        verifylist = []

        self.app.command_options = [
            'tripleo', 'container', 'image', 'prepare', 'default'
        ] + arglist
        cmd = container_image.TripleOImagePrepareDefault(self.app, None)
        parsed_args = self.check_parser(cmd, arglist, verifylist)

        cmd.take_action(parsed_args)

        with open(env_file) as f:
            result = yaml.safe_load(f)
        self.assertEqual(
            True,
            result['parameter_defaults']['ContainerImagePrepare']
            [0]['push_destination']
        )

    def test_prepare_default_registyr_login(self):
        temp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp)
        env_file = os.path.join(temp, 'containers_env.yaml')

        arglist = ['--enable-registry-login', '--output-env-file', env_file]
        verifylist = []

        self.app.command_options = [
            'tripleo', 'container', 'image', 'prepare', 'default'
        ] + arglist
        cmd = container_image.TripleOImagePrepareDefault(self.app, None)
        parsed_args = self.check_parser(cmd, arglist, verifylist)

        cmd.take_action(parsed_args)

        with open(env_file) as f:
            result = yaml.safe_load(f)
        self.assertEqual(
            True,
            result['parameter_defaults']['ContainerImageRegistryLogin']
        )
