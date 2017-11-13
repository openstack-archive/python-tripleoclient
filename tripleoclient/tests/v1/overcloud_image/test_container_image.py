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
import tempfile
import yaml

from tripleoclient.tests.v1.test_plugin import TestPluginV1
from tripleoclient.v1 import container_image


class TestContainerImageUpload(TestPluginV1):

    def setUp(self):
        super(TestContainerImageUpload, self).setUp()

        # Get the command object to test
        self.cmd = container_image.UploadImage(self.app, None)

    @mock.patch('sys.exit')
    @mock.patch('tripleo_common.image.image_uploader.ImageUploadManager',
                autospec=True)
    def test_container_image_upload_noargs(self, mock_manager, exit_mock):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)
        # argparse will complain that --config-file is missing and exit with 2
        exit_mock.assert_called_with(2)

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


class TestContainerImagePrepare(TestPluginV1):

    def setUp(self):
        super(TestContainerImagePrepare, self).setUp()

        # Get the command object to test
        self.cmd = container_image.PrepareImageFiles(self.app, None)

    def test_get_enabled_services(self):
        temp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp)
        resource_registry = {'parameter_defaults': {
            'RoleDisabledViaEnvironmentCount': 0,
            'RoleOverwrittenViaEnvironmentServices': [
                'OS::TripleO::Services::FromResourceRegistry'
            ]
        }}
        roles_file = '/foo/roles_data.yaml'
        roles_yaml = '''
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
        mock_open_context = mock.mock_open(read_data=roles_yaml)
        with mock.patch('six.moves.builtins.open', mock_open_context):
            enabled_services = self.cmd.get_enabled_services(resource_registry,
                                                             roles_file)
        mock_open_context.assert_called_once_with(roles_file)
        self.assertEqual(set(['OS::TripleO::Services::AodhEvaluator',
                              'OS::TripleO::Services::FromResourceRegistry']),
                         enabled_services)

    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder')
    @mock.patch('requests.get')
    def test_container_image_prepare_noargs(self, mock_get, mock_builder):
        arglist = []
        verifylist = []
        cift = mock.MagicMock()
        cift.return_value = {}

        mock_builder.return_value.container_images_from_template = cift

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_builder.assert_called_once_with([parsed_args.template_file])
        cift.assert_called_once_with(
            filter=mock.ANY,
            name_prefix='centos-binary-',
            name_suffix='',
            namespace='docker.io/tripleoupstream',
            neutron_driver=None,
            tag='latest'
        )

    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder')
    @mock.patch('heatclient.common.template_utils.'
                'process_multiple_environments_and_files')
    @mock.patch('requests.get')
    def test_container_image_prepare(self, mock_get, pmef, mock_builder):

        temp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp)
        images_file = os.path.join(temp, 'overcloud_containers.yaml')
        env_file = os.path.join(temp, 'containers_env.yaml')
        tmpl_file = os.path.join(temp, 'overcloud_containers.yaml.j2')
        aodh_file = os.path.join(temp, 'docker', 'services', 'aodh.yaml')
        mock_get.side_effect = requests.exceptions.SSLError('ouch')

        resource_registry = {'resource_registry': {
            'OS::TripleO::Services::AodhEvaluator': aodh_file,
            'OS::TripleO::Services::AodhApi': aodh_file
        }}
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
            'environment/docker.yaml'
        ]
        self.cmd.app.command_options = arglist
        verifylist = []
        cift = mock.MagicMock()
        cift.return_value = [{
            'imagename': '192.0.2.0:8787/t/os-aodh-apifoo:passed-ci',
            'params': ['DockerAodhApiImage', 'DockerAodhConfigImage'],
            'services': [
                'OS::TripleO::Services::AodhApi',
                'OS::TripleO::Services::AodhEvaluator',
            ],
        }, {
            'imagename': '192.0.2.0:8787/t/os-aodh-evaluatorfoo:passed-ci',
            'params': ['DockerAodhEvaluatorImage'],
            'services': [
                'OS::TripleO::Services::AodhEvaluator',
            ],
        }]

        mock_builder.return_value.container_images_from_template = cift

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_builder.assert_called_once_with([tmpl_file])
        pmef.assert_called_once_with(['environment/docker.yaml'],
                                     env_path_is_object=mock.ANY,
                                     object_request=mock.ANY)
        cift.assert_called_once_with(
            filter=mock.ANY,
            name_prefix='os-',
            name_suffix='foo',
            namespace='192.0.2.0:8787/t',
            tag='passed-ci',
            ceph_image='mydaemon',
            ceph_namespace='myceph',
            ceph_tag='mytag',
            neutron_driver=None
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

    def _test_container_image_prepare_helper(
            self, pmef, mock_builder, pmef_call_args,
            arg_list, neutron_driver, expected_container_template_params,
            expected_oc_yaml_contents, expected_env_contents):
        temp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp)
        images_file = os.path.join(temp, 'overcloud_containers.yaml')
        env_file = os.path.join(temp, 'containers_env.yaml')
        tmpl_file = os.path.join(temp, 'overcloud_containers.yaml.j2')

        resource_registry = {}
        if neutron_driver == 'odl':
            odlapi_file = os.path.join(temp, 'docker', 'services',
                                       'opendaylight.yaml')

            resource_registry = {'resource_registry': {
                'OS::TripleO::Services::OpenDaylightApi': odlapi_file
            }}
        elif neutron_driver == 'ovn':
            ovnapi_file = os.path.join(temp, 'docker', 'services',
                                       'overcloud_containers.yaml.j2')

            resource_registry = {'resource_registry': {
                'OS::TripleO::Services::OVNController': ovnapi_file
            }}

        pmef.return_value = None, resource_registry
        cmd_arglist = [
            '--template-file',
            tmpl_file,
            '--tag',
            'passed-ci',
            '--namespace',
            'tripleo',
            '--prefix',
            'os-',
            '--suffix',
            'foo',
            '--output-images-file',
            images_file,
            '--output-env-file',
            env_file,
        ]

        cmd_arglist.extend(arg_list)
        self.cmd.app.command_options = cmd_arglist
        verifylist = []
        cift = mock.MagicMock()
        cift.return_value = expected_container_template_params
        mock_builder.return_value.container_images_from_template = cift
        parsed_args = self.check_parser(self.cmd, cmd_arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_builder.assert_called_once_with([tmpl_file])
        pmef.assert_called_once_with(pmef_call_args,
                                     env_path_is_object=mock.ANY,
                                     object_request=mock.ANY)
        cift.assert_called_once_with(
            filter=mock.ANY,
            name_prefix='os-',
            name_suffix='foo',
            namespace='tripleo',
            tag='passed-ci',
            neutron_driver=neutron_driver,
        )

        with open(images_file) as f:
            self.assertEqual(expected_oc_yaml_contents, yaml.safe_load(f))
        with open(env_file) as f:
            self.assertEqual(expected_env_contents, yaml.safe_load(f))

    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder')
    @mock.patch('heatclient.common.template_utils.'
                'process_multiple_environments_and_files')
    @mock.patch('tripleoclient.v1.container_image.PrepareImageFiles.'
                'get_enabled_services')
    @mock.patch('requests.get')
    def test_container_image_prepare_for_odl(self, mock_get, ges, pmef,
                                             mock_builder):
        arglist = [
            '-e',
            'environments/services-docker/neutron-opendaylight.yaml',
        ]

        expected_container_template_params = [{
            'imagename':
                'tripleo/os-neutron-server-opendaylightfoo:passed-ci',
            'params':
                ['DockerNeutronApiImage', 'DockerNeutronConfigImage'],
            'services': [
                'OS::TripleO::Services::NeutronApi',
                'OS::TripleO::Services::NeutronDhcpAgent',
                'OS::TripleO::Services::NeutronMetadataAgent',
                'OS::TripleO::Services::NeutronServer',
                'OS::TripleO::Services::OpenDaylightApi',
                ],
            }, {
            'imagename': 'tripleo/os-opendaylightfoo:passed-ci',
            'params':
                ['DockerOpendaylightApiImage',
                 'DockerOpendaylightConfigImage'],
            'services': [
                'OS::TripleO::Services::OpenDaylightApi',
                ],
            }
        ]

        ges.return_value = (
            set(['OS::TripleO::Services::NeutronApi',
                 'OS::TripleO::Services::NeutronDhcpAgent',
                 'OS::TripleO::Services::NeutronMetadataAgent',
                 'OS::TripleO::Services::NeutronServer',
                 'OS::TripleO::Services::OpenDaylightApi']))

        pmef_call_args = [
            'environments/services-docker/neutron-opendaylight.yaml']

        expected_oc_yaml_contents = {
            'container_images': [{
                'imagename':
                    'tripleo/os-neutron-server-opendaylightfoo:passed-ci',
            }, {
                'imagename': 'tripleo/os-opendaylightfoo:passed-ci',
            }]
        }
        expected_env_contents = {
            'parameter_defaults': {
                'DockerNeutronApiImage':
                    'tripleo/os-neutron-server-opendaylightfoo:passed-ci',
                'DockerNeutronConfigImage':
                    'tripleo/os-neutron-server-opendaylightfoo:passed-ci',
                'DockerOpendaylightApiImage':
                    'tripleo/os-opendaylightfoo:passed-ci',
                'DockerOpendaylightConfigImage':
                    'tripleo/os-opendaylightfoo:passed-ci',
            }
        }

        self._test_container_image_prepare_helper(
            pmef, mock_builder, pmef_call_args, arglist, 'odl',
            expected_container_template_params, expected_oc_yaml_contents,
            expected_env_contents)

    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder')
    @mock.patch('heatclient.common.template_utils.'
                'process_multiple_environments_and_files')
    @mock.patch('tripleoclient.v1.container_image.PrepareImageFiles.'
                'get_enabled_services')
    @mock.patch('requests.get')
    def test_container_image_prepare_for_ovn(self, mock_get, ges, pmef,
                                             mock_builder):
        arglist = [
            '-e',
            'environments/services-docker/neutron-ovn.yaml',
        ]

        expected_container_template_params = [{
            'imagename':
                'tripleo/os-neutron-server-ovnfoo:passed-ci',
            'params':
                ['DockerNeutronApiImage', 'DockerNeutronConfigImage'],
            'services': [
                'OS::TripleO::Services::NeutronApi',
                'OS::TripleO::Services::NeutronServer',
                'OS::TripleO::Services::OVNController',
                'OS::TripleO::Services::OVNDBs',
                ],
            }, {
            'imagename': 'tripleo/os-ovn-controllerfoo:passed-ci',
            'params':
                ['DockerOvnControllerImage',
                 'DockerOvnControllerConfigImage'],
            'services': [
                'OS::TripleO::Services::OVNController',
                ],
            }
        ]

        ges.return_value = (
            set(['OS::TripleO::Services::NeutronApi',
                 'OS::TripleO::Services::NeutronServer',
                 'OS::TripleO::Services::OVNController',
                 'OS::TripleO::Services::OVNDBs']))

        pmef_call_args = [
            'environments/services-docker/neutron-ovn.yaml']

        expected_oc_yaml_contents = {
            'container_images': [{
                'imagename':
                    'tripleo/os-neutron-server-ovnfoo:passed-ci',
            }, {
                'imagename': 'tripleo/os-ovn-controllerfoo:passed-ci',
            }]
        }
        expected_env_contents = {
            'parameter_defaults': {
                'DockerNeutronApiImage':
                    'tripleo/os-neutron-server-ovnfoo:passed-ci',
                'DockerNeutronConfigImage':
                    'tripleo/os-neutron-server-ovnfoo:passed-ci',
                'DockerOvnControllerImage':
                    'tripleo/os-ovn-controllerfoo:passed-ci',
                'DockerOvnControllerConfigImage':
                    'tripleo/os-ovn-controllerfoo:passed-ci',
            }
        }

        self._test_container_image_prepare_helper(
            pmef, mock_builder, pmef_call_args, arglist, 'ovn',
            expected_container_template_params, expected_oc_yaml_contents,
            expected_env_contents)

    @mock.patch('requests.get')
    def test_detect_insecure_registry(self, mock_get):
        self.assertEqual(
            {},
            self.cmd.detect_insecure_registries(
                {'foo': 'docker.io/tripleo'}))
        self.assertEqual(
            {},
            self.cmd.detect_insecure_registries(
                {'foo': 'tripleo'}))

        mock_get.side_effect = requests.exceptions.ReadTimeout('ouch')
        self.assertEqual(
            {},
            self.cmd.detect_insecure_registries(
                {'foo': '192.0.2.0:8787/tripleo'}))

        mock_get.side_effect = requests.exceptions.SSLError('ouch')
        self.assertEqual(
            {'DockerInsecureRegistryAddress': ['192.0.2.0:8787']},
            self.cmd.detect_insecure_registries(
                {'foo': '192.0.2.0:8787/tripleo'}))

        self.assertEqual(
            {'DockerInsecureRegistryAddress': [
                '192.0.2.0:8787',
                '192.0.2.1:8787']},
            self.cmd.detect_insecure_registries({
                'foo': '192.0.2.0:8787/tripleo/foo',
                'bar': '192.0.2.0:8787/tripleo/bar',
                'baz': '192.0.2.1:8787/tripleo/baz',
            }))


class TestContainerImageBuild(TestPluginV1):

    def setUp(self):
        super(TestContainerImageBuild, self).setUp()

        # Get the command object to test
        self.cmd = container_image.BuildImage(self.app, None)
        self.cmd.app.stdout = six.StringIO()
        self.temp_dir = self.useFixture(fixtures.TempDir()).join()

    @mock.patch('sys.exit')
    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder',
                autospec=True)
    def test_container_image_build_noargs(self, mock_builder, exit_mock):
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
        mock_builder.return_value.build_images.return_value = 'done'

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        f, path = tempfile.mkstemp(dir=self.temp_dir)
        with mock.patch('tempfile.mkstemp') as mock_mkstemp:
            mock_mkstemp.return_value = f, path
            self.cmd.take_action(parsed_args)

        mock_builder.assert_called_once_with([
            '/tmp/foo.yaml', '/tmp/bar.yaml'])
        mock_builder.return_value.build_images.assert_called_once_with([
            '/tmp/kolla.conf',
            path
        ])

    @mock.patch('tripleo_common.image.kolla_builder.KollaImageBuilder',
                autospec=True)
    @mock.patch('os.remove')
    def test_container_image_build_list_images(self, mock_remove,
                                               mock_builder):
        arglist = [
            '--list-images',
            '--config-file',
            '/tmp/bar.yaml',
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
    def test_container_image_build_list_deps(self, mock_remove, mock_builder):
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
