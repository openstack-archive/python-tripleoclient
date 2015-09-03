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
from uuid import uuid4

from rdomanager_oscplugin.tests.v1.overcloud_deploy import fakes
from rdomanager_oscplugin.v1 import overcloud_deploy


class TestDeployValidators(fakes.TestDeployOvercloud):
    def setUp(self):
        super(TestDeployValidators, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_deploy.DeployOvercloud(self.app, None)

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_image_ids',
                return_value=('fb7a98fb-acb9-43ec-9b93-525d1286f9d8',
                              '8558de2e-1b72-4654-8ba9-cceb89e9194e'))
    def test_ironic_boot_checks(self, mock_image_ids):
        class FakeNode(object):
            uuid = 'fake-node-123'
            driver_info = None
            properties = None

        node = FakeNode()
        node.driver_info = {
            'deploy_kernel': 'fb7a98fb-acb9-43ec-9b93-525d1286f9d8',
            'deploy_ramdisk': '8558de2e-1b72-4654-8ba9-cceb89e9194e',
        }
        node.properties = {
            'capabilities': 'boot_option:local,profile:foobar'
        }
        self.cmd._check_ironic_boot_configuration(node)
        self.assertEqual(self.cmd.predeploy_errors, 0)
        self.assertEqual(self.cmd.predeploy_warnings, 0)

        node.properties['capabilities'] = 'profile:foobar'
        self.cmd._check_ironic_boot_configuration(node)
        self.assertEqual(self.cmd.predeploy_errors, 0)
        self.assertEqual(self.cmd.predeploy_warnings, 1)

        node.properties['capabilities'] = 'profile:foobar,boot_option:local'
        node.driver_info.pop('deploy_kernel')
        self.cmd._check_ironic_boot_configuration(node)
        self.assertEqual(self.cmd.predeploy_errors, 1)
        self.assertEqual(self.cmd.predeploy_warnings, 1)

    @mock.patch('rdomanager_oscplugin.v1.overcloud_deploy.DeployOvercloud.'
                '_image_ids',
                return_value=('fb7a98fb-acb9-43ec-9b93-525d1286f9d8',
                              '8558de2e-1b72-4654-8ba9-cceb89e9194e'))
    def test_boot_image_checks(self, mock_image_ids):
        self.cmd._check_boot_images()
        self.assertEqual(self.cmd.predeploy_errors, 0)
        self.assertEqual(self.cmd.predeploy_warnings, 0)

        mock_image_ids.return_value = (
            None, '8558de2e-1b72-4654-8ba9-cceb89e9194e')
        self.cmd._check_boot_images()
        self.assertEqual(self.cmd.predeploy_errors, 1)
        self.assertEqual(self.cmd.predeploy_warnings, 0)

        mock_image_ids.return_value = (
            '8558de2e-1b72-4654-8ba9-cceb89e9194e', None)
        self.cmd._check_boot_images()
        self.assertEqual(self.cmd.predeploy_errors, 2)
        self.assertEqual(self.cmd.predeploy_warnings, 0)

    def test_flavor_existence_check(self):
        class FakeFlavor(object):
            name = ''
            uuid = ''

            def __init__(self, name):
                self.uuid = uuid4()
                self.name = name

        arglist = [
            '--block-storage-flavor', 'block',
            '--block-storage-scale', '3',
            '--ceph-storage-flavor', 'ceph',
            '--ceph-storage-scale', '0',
            '--compute-flavor', 'compute',
            '--compute-scale', '3',
            '--control-flavor', 'control',
            '--control-scale', '1',
            '--swift-storage-flavor', 'swift',
            '--swift-storage-scale', '2',
            '--templates'
        ]
        verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        mock_flavor_list = mock.Mock(
            return_value=[
                FakeFlavor('block'),
                FakeFlavor('compute'),
                FakeFlavor('control'),
                FakeFlavor('swift'),
            ]
        )
        mock_flavors = mock.Mock()
        mock_flavors.attach_mock(mock_flavor_list, 'list')
        self.app.client_manager.compute.attach_mock(mock_flavors, 'flavors')

        self.cmd._check_flavors_exist(parsed_args)
        self.assertEqual(self.cmd.predeploy_errors, 0)
        self.assertEqual(self.cmd.predeploy_warnings, 0)

        mock_flavor_list_no_swift = mock.Mock(
            return_value=[
                FakeFlavor('block'),
                FakeFlavor('compute'),
                FakeFlavor('control'),
            ]
        )
        mock_flavors.attach_mock(mock_flavor_list_no_swift, 'list')
        self.cmd._check_flavors_exist(parsed_args)
        self.assertEqual(self.cmd.predeploy_errors, 1)
        self.assertEqual(self.cmd.predeploy_warnings, 0)

    def test_check_profiles(self):
        flavor_profile_map = {'ceph-flavor': 'ceph-profile'}
        node_profile_map = {
            None: ['e0e6a290-2321-4981-8a76-b230284119c2'],
            'ceph-profile': ['ea7d8a81-5e7c-4696-bd1e-8ee83da5b816']
        }

        self.cmd._check_profiles('ceph-storage', 'ceph-flavor', 1,
                                 flavor_profile_map,
                                 node_profile_map)
        self.assertEqual(self.cmd.predeploy_errors, 0)
        self.assertEqual(self.cmd.predeploy_warnings, 0)

        self.cmd._check_profiles('ceph-storage', 'ceph-flavor', 2,
                                 flavor_profile_map,
                                 node_profile_map)
        self.assertEqual(self.cmd.predeploy_errors, 1)
        self.assertEqual(self.cmd.predeploy_warnings, 0)
