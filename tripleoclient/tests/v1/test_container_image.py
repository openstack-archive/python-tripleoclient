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
import requests
import shutil
import six
import sys
import tempfile
import uuid
import yaml

from osc_lib import exceptions as oscexc
from six.moves.urllib import parse
from tripleo_common.image import image_uploader
from tripleo_common.image import kolla_builder
from tripleoclient.tests.v1.test_plugin import TestPluginV1
from tripleoclient.v1 import container_image

# TODO(sbaker) Remove after a tripleo-common release contains this attribute
CLEANUP = (
    CLEANUP_FULL, CLEANUP_PARTIAL, CLEANUP_NONE
) = (
    'full', 'partial', 'none'
)
if not hasattr(image_uploader, 'CLEANUP'):
    setattr(image_uploader, 'CLEANUP', CLEANUP)
    setattr(image_uploader, 'CLEANUP_FULL', CLEANUP_FULL)
    setattr(image_uploader, 'CLEANUP_PARTIAL', CLEANUP_PARTIAL)
    setattr(image_uploader, 'CLEANUP_NONE', CLEANUP_NONE)


class TestContainerImageUpload(TestPluginV1):

    def setUp(self):
        super(TestContainerImageUpload, self).setUp()

        # Get the command object to test
        self.cmd = container_image.UploadImage(self.app, None)

    @mock.patch('tripleo_common.utils.locks.processlock.'
                'ProcessLock')
    @mock.patch('sys.exit')
    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager')
    def test_container_image_upload_noargs(self, mock_manager, exit_mock,
                                           mock_lock):
        arglist = []
        verifylist = []

        mock_lockobj = mock.MagicMock()
        mock_lock.return_value = mock_lockobj

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        # argparse will complain that --config-file is missing and exit with 2
        exit_mock.assert_called_with(2)

    @mock.patch('tripleo_common.utils.locks.processlock.'
                'ProcessLock')
    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager')
    def test_container_image_upload_conf_files(self, mock_manager, mock_lock):
        arglist = [
            '--config-file',
            '/tmp/foo.yaml',
            '--config-file',
            '/tmp/bar.yaml'
        ]
        verifylist = []

        mock_lockobj = mock.MagicMock()
        mock_lock.return_value = mock_lockobj

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_manager.assert_called_once_with(
            ['/tmp/foo.yaml', '/tmp/bar.yaml'], cleanup='full',
            lock=mock_lockobj)
        mock_manager.return_value.upload.assert_called_once_with()


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


class TestContainerImagePrepare(TestPluginV1):

    def setUp(self):
        super(TestContainerImagePrepare, self).setUp()

        # Get the command object to test
        self.cmd = container_image.PrepareImageFiles(self.app, None)
        kolla_builder.DEFAULT_TEMPLATE_FILE = os.path.join(
            '/tmp/overcloud_containers.yaml.j2'
        )
        self.roles_yaml = '''
        - name: EnabledRole
          CountDefault: 1
          ServicesDefault:
            - OS::TripleO::Services::AodhEvaluator
        - name: RoleDisabledViaRolesData
          CountDefault: 0
          ServicesDefault:
            - OS::TripleO::Services::AodhApi
        - name: RoleDisabledViaEnvironment
          CountDefault: 1
          ServicesDefault:
            - OS::TripleO::Services::Disabled
        - name: RoleOverwrittenViaEnvironment
          CountDefault: 1
          ServicesDefault:
            - OS::TripleO::Services::Overwritten
        '''

    @mock.patch('tripleo_common.image.kolla_builder.'
                'container_images_prepare_defaults', create=True)
    @mock.patch('tripleo_common.image.kolla_builder.'
                'container_images_prepare', create=True)
    @mock.patch('requests.get')
    @mock.patch('tripleo_common.image.kolla_builder.'
                'build_service_filter')
    def test_container_image_prepare_noargs(self, mock_bsf, mock_get, mock_cip,
                                            mock_cipd):
        mock_bsf.return_value = None
        mock_cipd.return_value = {
            'neutron_driver': 'ovn',
            'name_suffix': '',
            'tag': 'latest',
            'namespace': 'docker.io/tripleou',
            'name_prefix':
            'centos-binary-'
        }
        arglist = []
        verifylist = []

        mock_cip.return_value = {'container_images.yaml': {}}

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_cip.assert_called_with(
            excludes=[],
            includes=[],
            mapping_args={
                'neutron_driver': 'ovn',
                'name_suffix': '',
                'tag': 'latest',
                'namespace': 'docker.io/tripleou',
                'name_prefix':
                'centos-binary-'
            },
            output_env_file=None,
            output_images_file='container_images.yaml',
            push_destination=None,
            service_filter=None,
            tag_from_label=None,
            modify_role=None,
            modify_vars=None,
            append_tag=None,
            template_file=kolla_builder.DEFAULT_TEMPLATE_FILE
        )

    @mock.patch('tripleoclient.utils.fetch_roles_file')
    @mock.patch('tripleo_common.image.kolla_builder.'
                'container_images_prepare_defaults', create=True)
    @mock.patch('tripleo_common.image.kolla_builder.'
                'container_images_prepare', create=True)
    @mock.patch('heatclient.common.template_utils.'
                'process_multiple_environments_and_files')
    @mock.patch('tripleo_common.image.kolla_builder.'
                'build_service_filter')
    @mock.patch('requests.get')
    def test_container_image_prepare(self, mock_get, mock_bsf, pmef, mock_cip,
                                     mock_cipd, mock_roles):

        temp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp)
        images_file = os.path.join(temp, 'overcloud_containers.yaml')
        env_file = os.path.join(temp, 'containers_env.yaml')
        tmpl_file = os.path.join(temp, 'overcloud_containers.yaml.j2')
        aodh_file = os.path.join(temp, 'docker', 'services', 'aodh.yaml')
        roles_file = os.path.join(temp, 'roles_data.yaml')
        with open(roles_file, 'w') as f:
            f.write(self.roles_yaml)
        modify_vars_file = os.path.join(temp, 'modify_vars.yaml')
        with open(modify_vars_file, 'w') as f:
            f.write('foo: bar')
        mock_get.side_effect = requests.exceptions.SSLError('ouch')
        mock_bsf.return_value = set(['OS::TripleO::Services::AodhEvaluator'])

        resource_registry = {
            'parameter_defaults': {
                'NeutronMechanismDrivers': 'ovn',
                },
            'resource_registry': {
                'OS::TripleO::Services::AodhEvaluator': aodh_file,
                'OS::TripleO::Services::AodhApi': aodh_file
                }
            }
        pmef.return_value = None, resource_registry

        arglist = [
            '--template-file',
            tmpl_file,
            '--tag',
            'passed-ci',
            '--namespace',
            '192.0.2.0:8787/t',
            '--prefix',
            'os-',
            '--suffix',
            'foo',
            '--output-images-file',
            images_file,
            '--output-env-file',
            env_file,
            '--set',
            'ceph_namespace=myceph',
            '--set',
            'ceph_image=mydaemon',
            '--set',
            'ceph_tag=mytag',
            '-e',
            'environment/docker-ha.yaml',
            '--roles-file',
            roles_file,
            '--modify-role',
            'foo-role',
            '--modify-vars',
            modify_vars_file
        ]
        self.cmd.app.command_options = arglist
        verifylist = []
        mock_cip.return_value = {images_file: [{
            'imagename': '192.0.2.0:8787/t/os-aodh-apifoo:passed-ci',
        }, {
            'imagename': '192.0.2.0:8787/t/os-aodh-evaluatorfoo:passed-ci',
        }], env_file: {
            'DockerAodhApiImage':
                '192.0.2.0:8787/t/os-aodh-apifoo:passed-ci',
            'DockerAodhConfigImage':
                '192.0.2.0:8787/t/os-aodh-apifoo:passed-ci',
            'DockerAodhEvaluatorImage':
                '192.0.2.0:8787/t/os-aodh-evaluatorfoo:passed-ci',
            'DockerInsecureRegistryAddress': ['192.0.2.0:8787']
            }
        }

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        pmef.assert_called_once_with(['environment/docker-ha.yaml'],
                                     env_path_is_object=mock.ANY,
                                     object_request=mock.ANY)
        mock_cip.assert_called_once_with(
            excludes=[],
            includes=[],
            mapping_args={
                'namespace': '192.0.2.0:8787/t',
                'name_suffix': 'foo',
                'ceph_tag': 'mytag',
                'ceph_image': 'mydaemon',
                'tag': 'passed-ci',
                'neutron_driver': 'ovn',
                'ceph_namespace': 'myceph',
                'name_prefix': 'os-'
            },
            output_env_file=env_file,
            output_images_file=images_file,
            push_destination=None,
            service_filter=set([
                'OS::TripleO::Services::AodhEvaluator',
            ]),
            tag_from_label=None,
            modify_role='foo-role',
            modify_vars={'foo': 'bar'},
            append_tag=mock.ANY,
            template_file=tmpl_file
        )
        ci_data = {
            'container_images': [{
                'imagename': '192.0.2.0:8787/t/os-aodh-apifoo:passed-ci',
            }, {
                'imagename': '192.0.2.0:8787/t/os-aodh-evaluatorfoo:passed-ci',
            }]
        }
        env_data = {
            'parameter_defaults': {
                'DockerAodhApiImage':
                    '192.0.2.0:8787/t/os-aodh-apifoo:passed-ci',
                'DockerAodhConfigImage':
                    '192.0.2.0:8787/t/os-aodh-apifoo:passed-ci',
                'DockerAodhEvaluatorImage':
                    '192.0.2.0:8787/t/os-aodh-evaluatorfoo:passed-ci',
                'DockerInsecureRegistryAddress': ['192.0.2.0:8787']
            }
        }
        with open(images_file) as f:
            self.assertEqual(ci_data, yaml.safe_load(f))
        with open(env_file) as f:
            self.assertEqual(env_data, yaml.safe_load(f))


class TestTripleoImagePrepare(TestPluginV1):

    def setUp(self):
        super(TestTripleoImagePrepare, self).setUp()
        # Get the command object to test
        self.cmd = container_image.TripleOImagePrepare(self.app, None)

        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp_dir)
        self.prepare_default_file = os.path.join(
            self.temp_dir, 'prepare_env.yaml')
        default_param = kolla_builder.CONTAINER_IMAGE_PREPARE_PARAM
        self.default_env = {
            'parameter_defaults': {
                'ContainerImagePrepare': default_param
            }
        }
        with open(self.prepare_default_file, 'w') as f:
            yaml.safe_dump(self.default_env, f)

        self.roles_yaml = '''
        - name: EnabledRole
          CountDefault: 1
          ServicesDefault:
            - OS::TripleO::Services::AodhEvaluator
        - name: RoleDisabledViaRolesData
          CountDefault: 0
          ServicesDefault:
            - OS::TripleO::Services::AodhApi
        - name: RoleDisabledViaEnvironment
          CountDefault: 1
          ServicesDefault:
            - OS::TripleO::Services::Disabled
        - name: RoleOverwrittenViaEnvironment
          CountDefault: 1
          ServicesDefault:
            - OS::TripleO::Services::Overwritten
        '''
        self.roles_data_file = os.path.join(
            self.temp_dir, 'roles_data.yaml')
        with open(self.roles_data_file, 'w') as f:
            f.write(self.roles_yaml)

    @mock.patch('tripleo_common.utils.locks.processlock.'
                'ProcessLock')
    @mock.patch('tripleo_common.image.kolla_builder.'
                'container_images_prepare_multi')
    def test_tripleo_container_image_prepare(self, prepare_multi, mock_lock):

        mock_lockobj = mock.MagicMock()
        mock_lock.return_value = mock_lockobj
        env_file = os.path.join(self.temp_dir, 'containers_env.yaml')

        arglist = [
            '--environment-file', self.prepare_default_file,
            '--roles-file', self.roles_data_file,
            '--output-env-file', env_file
        ]
        verifylist = []

        self.app.command_options = [
            'tripleo', 'container', 'image', 'prepare', 'default'
        ] + arglist

        prepare_multi.return_value = {
            'DockerAodhApiImage':
                '192.0.2.0:8787/t/os-aodh-apifoo:passed-ci',
            'DockerAodhConfigImage':
                '192.0.2.0:8787/t/os-aodh-apifoo:passed-ci',
        }

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

        prepare_multi.assert_called_once_with(
            self.default_env,
            yaml.safe_load(self.roles_yaml),
            dry_run=False,
            cleanup='full',
            lock=mock_lockobj)

        with open(env_file) as f:
            result = yaml.safe_load(f)

        self.assertEqual({
            'parameter_defaults': {
                'DockerAodhApiImage':
                    '192.0.2.0:8787/t/os-aodh-apifoo:passed-ci',
                'DockerAodhConfigImage':
                    '192.0.2.0:8787/t/os-aodh-apifoo:passed-ci',
            }
        }, result)


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
        self.cmd.app.stdout = six.StringIO()
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


class TestContainerImageBuild(TestPluginV1):

    def setUp(self):
        super(TestContainerImageBuild, self).setUp()

        # Get the command object to test
        self.cmd = container_image.BuildImage(self.app, None)
        self.cmd.app.stdout = six.StringIO()
        self.uuid = str(uuid.uuid4())
        self.temp_dir = os.path.join(self.useFixture(
                                     fixtures.TempDir()).join())
        self.temp_dir_uuid = os.path.join(self.temp_dir, self.uuid)

        # Default conf file
        self.default_kolla_conf = os.path.join(
            sys.prefix, 'share', 'tripleo-common', 'container-images',
            'tripleo_kolla_config_overrides.conf')

    @mock.patch('sys.exit')
    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder',
                autospec=True)
    @mock.patch('os.makedirs')
    def test_container_image_build_noargs(self, mock_mkdirs, mock_builder,
                                          exit_mock):
        arglist = []
        verifylist = []
        mock_builder.return_value.build_images.return_value = 'done'

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        f, path = tempfile.mkstemp(dir=self.temp_dir)
        with mock.patch('tempfile.mkstemp') as mock_mkstemp:
            mock_mkstemp.return_value = f, path
            self.cmd.take_action(parsed_args)

        # argparse will complain that --config-file is missing and exit with 2
        exit_mock.assert_called_with(2)

    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder',
                autospec=True)
    @mock.patch('uuid.uuid4')
    def test_container_image_build(self, mock_uuid, mock_builder):
        arglist = [
            '--config-file',
            '/tmp/foo.yaml',
            '--config-file',
            '/tmp/bar.yaml',
            '--work-dir',
            self.temp_dir,
            '--kolla-config-file',
            '/tmp/kolla.conf'
        ]
        verifylist = []
        mock_builder.return_value.build_images.return_value = 'done'
        mock_uuid.return_value = self.uuid

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        f, path = tempfile.mkstemp(dir=self.temp_dir)
        with mock.patch('tempfile.mkstemp') as mock_mkstemp:
            with mock.patch('os.chdir'):
                mock_mkstemp.return_value = f, path
                self.cmd.take_action(parsed_args)

        mock_builder.assert_called_once_with([
            '/tmp/foo.yaml', '/tmp/bar.yaml'])
        mock_builder.return_value.build_images.assert_called_once_with([
            self.default_kolla_conf, '/tmp/kolla.conf',
            path
        ], [], False, self.temp_dir_uuid)

    @mock.patch('os.chdir')
    @mock.patch('os.fdopen', autospec=True)
    @mock.patch('tempfile.mkstemp')
    @mock.patch(
        'tripleoclient.utils.get_from_cfg')
    @mock.patch(
        'tripleoclient.utils.getboolean_from_cfg')
    @mock.patch('tripleo_common.image.builder.buildah.BuildahBuilder',
                autospec=True)
    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder',
                autospec=True)
    @mock.patch('tripleoclient.utils.get_read_config')
    @mock.patch('os.remove')
    def test_container_image_build_with_buildah(self, mock_remove,
                                                mock_read_conf,
                                                mock_builder, mock_buildah,
                                                mock_kolla_boolean_cfg,
                                                mock_kolla_cfg, mock_mkstemp,
                                                mock_fdopen, mock_chdir):
        arglist = [
            '--config-file',
            '/tmp/bar.yaml',
            '--kolla-config-file',
            '/tmp/kolla.conf',
            '--use-buildah',
            '--work-dir',
            self.temp_dir,
        ]

        parsed_args = self.check_parser(self.cmd, arglist, [])
        deps = '{"base": ["qrouterd"]}'
        mock_builder.return_value.build_images.return_value = deps

        mock_mkstemp.return_value = (1, '/tmp/whatever_file')

        mock_bb = mock.MagicMock()
        mock_bb.build_all = mock.MagicMock()
        mock_buildah.return_value = mock_bb
        self.cmd.take_action(parsed_args)

        cfg_files = list(parsed_args.kolla_config_files)
        cfg_files.append('/tmp/whatever_file')
        mock_read_conf.assert_any_call(cfg_files)
        cfg_calls = [
            mock.call(mock_read_conf.return_value, 'base'),
            mock.call(mock_read_conf.return_value, 'type'),
            mock.call(mock_read_conf.return_value, 'tag'),
            mock.call(mock_read_conf.return_value, 'namespace'),
            mock.call(mock_read_conf.return_value, 'registry'),
        ]
        cfg_boolean_calls = [
            mock.call(mock_read_conf.return_value, 'push'),
        ]
        mock_kolla_cfg.assert_has_calls(cfg_calls)
        mock_kolla_boolean_cfg.assert_has_calls(cfg_boolean_calls)
        mock_bb.build_all.assert_called_once()

    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder',
                autospec=True)
    @mock.patch('uuid.uuid4')
    def test_container_image_build_with_exclude(self, mock_uuid, mock_builder):
        arglist = [
            '--config-file',
            '/tmp/foo.yaml',
            '--config-file',
            '/tmp/bar.yaml',
            '--kolla-config-file',
            '/tmp/kolla.conf',
            '--work-dir',
            '/tmp/testing',
            '--exclude',
            'foo',
            '--exclude',
            'bar'
        ]
        verifylist = []
        mock_builder.return_value.build_images.return_value = 'done'
        mock_uuid.return_value = '123'

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        f, path = tempfile.mkstemp(dir=self.temp_dir)
        with mock.patch('tempfile.mkdtemp') as mock_mkd:
            mock_mkd.return_value = '/tmp/testing'
            with mock.patch('tempfile.mkstemp') as mock_mkstemp:
                with mock.patch('os.chdir'):
                    mock_mkstemp.return_value = f, path
                    self.cmd.take_action(parsed_args)

        mock_builder.assert_called_once_with([
            '/tmp/foo.yaml', '/tmp/bar.yaml'])
        mock_builder.return_value.build_images.assert_called_once_with([
            self.default_kolla_conf, '/tmp/kolla.conf',
            path
        ], ['foo', 'bar'], False, '/tmp/testing/123')

    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder',
                autospec=True)
    @mock.patch('os.remove')
    def test_container_image_build_list_images(self, mock_remove,
                                               mock_builder):
        arglist = [
            '--list-images',
            '--config-file',
            '/tmp/bar.yaml',
            '--work-dir',
            '/tmp/testing',
            '--kolla-config-file',
            '/tmp/kolla.conf'
        ]
        parsed_args = self.check_parser(self.cmd, arglist, [])
        deps = '{"base": ["qrouterd"]}'
        mock_builder.return_value.build_images.return_value = deps

        f, path = tempfile.mkstemp(dir=self.temp_dir)
        with mock.patch('tempfile.mkstemp') as mock_mkstemp:
            mock_mkstemp.return_value = f, path
            self.cmd.take_action(parsed_args)
            with open(path, 'r') as conf_file:
                self.assertEqual(
                    conf_file.readlines(),
                    ['[DEFAULT]\n', 'list_dependencies=true'])
        self.assertEqual('- base\n- qrouterd\n',
                         self.cmd.app.stdout.getvalue())

    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder',
                autospec=True)
    @mock.patch('os.remove')
    @mock.patch('os.makedirs')
    def test_container_image_build_list_deps(self, mock_mkdirs, mock_remove,
                                             mock_builder):
        arglist = [
            '--config-file',
            '/tmp/bar.yaml',
            '--kolla-config-file',
            '/tmp/kolla.conf',
            '--list-dependencies',
        ]
        parsed_args = self.check_parser(self.cmd, arglist, [])
        deps = '{"base": ["qrouterd"]}'
        mock_builder.return_value.build_images.return_value = deps

        f, path = tempfile.mkstemp(dir=self.temp_dir)
        with mock.patch('tempfile.mkstemp') as mock_mkstemp:
            mock_mkstemp.return_value = f, path
            self.cmd.take_action(parsed_args)
            with open(path, 'r') as conf_file:
                self.assertEqual(
                    conf_file.readlines(),
                    ['[DEFAULT]\n', 'list_dependencies=true'])
        self.assertEqual('base:\n- qrouterd\n',
                         self.cmd.app.stdout.getvalue())

    def test_images_from_deps(self):
        deps = yaml.safe_load('''base:
- qdrouterd
- cron
- ceph-base:
  - ceph-osd
  - ceph-rgw
  - ceph-mon
  - cephfs-fuse
  - ceph-mds
- redis
- etcd
- kubernetes-entrypoint
- kolla-toolbox
- telegraf
- openstack-base:
  - swift-base:
    - swift-proxy-server
    - swift-account
    - swift-container
    - swift-object-expirer
    - swift-rsyncd
    - swift-object''')

        images_yaml = '''- base
- qdrouterd
- cron
- ceph-base
- ceph-osd
- ceph-rgw
- ceph-mon
- cephfs-fuse
- ceph-mds
- redis
- etcd
- kubernetes-entrypoint
- kolla-toolbox
- telegraf
- openstack-base
- swift-base
- swift-proxy-server
- swift-account
- swift-container
- swift-object-expirer
- swift-rsyncd
- swift-object
'''
        images = []
        self.cmd.images_from_deps(images, deps)
        self.assertEqual(yaml.safe_load(images_yaml), images)
