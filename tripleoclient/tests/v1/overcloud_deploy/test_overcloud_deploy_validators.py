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

from osc_lib.tests import utils

from tripleoclient.tests.v1.overcloud_deploy import fakes
from tripleoclient.v1 import overcloud_deploy


class TestDeployValidators(fakes.TestDeployOvercloud):
    def setUp(self):
        super(TestDeployValidators, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_deploy.DeployOvercloud(self.app, None)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_check_node_boot_configuration')
    def test_ironic_boot_checks(self, mock_node_boot_check):
        class FakeNode(object):
            uuid = None

            def __init__(self, uuid):
                self.uuid = uuid

        bm_client = self.app.client_manager.baremetal
        mock_node = mock.Mock()
        bm_client.attach_mock(mock_node, 'node')

        fake_nodes = [FakeNode(uuid) for uuid in (
            '97dd6459-cf2d-4eea-865e-84fee3bf5e6d',
            '1867d71b-d0a5-44c6-b83e-ada8b16de556'
        )]
        # return a list of FakeNodes, replaces bm_client.node.list
        mock_maint_nodes = mock.Mock(return_value=fake_nodes)
        mock_node.attach_mock(mock_maint_nodes, 'list')

        # get a FakeNode by its UUID, replaces bm_client.node.get

        self.cmd._check_ironic_boot_configuration(bm_client)

        mock_maint_nodes.assert_called_once_with(detail=True,
                                                 maintenance=False)

    def test_image_ids(self):
        image_client = self.app.client_manager.image
        image_client.images = {}
        image_ids = self.cmd._image_ids()

        image_client.images = {
            'bm-deploy-kernel':
            mock.Mock(id='fb7a98fb-acb9-43ec-9b93-525d1286f9d8'),
            'bm-deploy-ramdisk':
            mock.Mock(id='8558de2e-1b72-4654-8ba9-cceb89e9194e'),
        }

        image_ids = self.cmd._image_ids()
        self.assertEqual(image_ids, ('fb7a98fb-acb9-43ec-9b93-525d1286f9d8',
                                     '8558de2e-1b72-4654-8ba9-cceb89e9194e'))

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
                '_image_ids',
                return_value=('fb7a98fb-acb9-43ec-9b93-525d1286f9d8',
                              '8558de2e-1b72-4654-8ba9-cceb89e9194e'))
    def test_node_boot_checks(self, mock_image_ids):
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
        self.cmd._check_node_boot_configuration(node)
        self.assertEqual(self.cmd.predeploy_errors, 0)
        self.assertEqual(self.cmd.predeploy_warnings, 0)

        node.properties['capabilities'] = 'profile:foobar'
        self.cmd._check_node_boot_configuration(node)
        self.assertEqual(self.cmd.predeploy_errors, 0)
        self.assertEqual(self.cmd.predeploy_warnings, 1)

        node.properties['capabilities'] = 'profile:foobar,boot_option:local'
        node.driver_info.pop('deploy_kernel')
        self.cmd._check_node_boot_configuration(node)
        self.assertEqual(self.cmd.predeploy_errors, 1)
        self.assertEqual(self.cmd.predeploy_warnings, 1)

    @mock.patch('tripleoclient.v1.overcloud_deploy.DeployOvercloud.'
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


class FakeFlavor(object):
    name = ''
    uuid = ''

    def __init__(self, name):
        self.uuid = uuid4()
        self.name = name

    def get_keys(self):
        return {'capabilities:boot_option': 'local'}


class TestCollectFlavors(fakes.TestDeployOvercloud):
    def setUp(self):
        super(TestCollectFlavors, self).setUp()
        self.cmd = overcloud_deploy.DeployOvercloud(self.app, None)
        self.arglist = [
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
        self.verifylist = [
            ('templates', '/usr/share/openstack-tripleo-heat-templates/'),
        ]

        self.mock_flavors = mock.Mock()
        self.app.client_manager.compute.attach_mock(self.mock_flavors,
                                                    'flavors')

    def test_ok(self):
        parsed_args = self.check_parser(self.cmd, self.arglist,
                                        self.verifylist)

        expected_result = {
            'block': (FakeFlavor('block'), 3),
            'compute': (FakeFlavor('compute'), 3),
            'control': (FakeFlavor('control'), 1),
            'swift': (FakeFlavor('swift'), 2)
        }
        mock_flavor_list = mock.Mock(
            return_value=[
                flavor for flavor, scale in expected_result.values()
            ]
        )
        self.mock_flavors.attach_mock(mock_flavor_list, 'list')

        result = self.cmd._collect_flavors(parsed_args)
        self.assertEqual(self.cmd.predeploy_errors, 0)
        self.assertEqual(self.cmd.predeploy_warnings, 0)
        self.assertEqual(expected_result, result)

    def test_flavor_not_found(self):
        parsed_args = self.check_parser(self.cmd, self.arglist,
                                        self.verifylist)

        expected_result = {
            'block': (FakeFlavor('block'), 3),
            'compute': (FakeFlavor('compute'), 3),
            'control': (FakeFlavor('control'), 1),
        }
        mock_flavor_list = mock.Mock(
            return_value=[
                flavor for flavor, scale in expected_result.values()
            ]
        )
        self.mock_flavors.attach_mock(mock_flavor_list, 'list')
        result = self.cmd._collect_flavors(parsed_args)
        self.assertEqual(self.cmd.predeploy_errors, 1)
        self.assertEqual(self.cmd.predeploy_warnings, 0)
        self.assertEqual(expected_result, result)

    def test_same_flavor(self):
        self.arglist = [
            '--compute-flavor', 'baremetal',
            '--compute-scale', '3',
            '--control-flavor', 'baremetal',
            '--control-scale', '1',
            '--templates'
        ]
        parsed_args = self.check_parser(self.cmd, self.arglist,
                                        self.verifylist)

        expected_result = {
            'baremetal': (FakeFlavor('baremetal'), 4),
        }
        mock_flavor_list = mock.Mock(
            return_value=[
                flavor for flavor, scale in expected_result.values()
            ]
        )
        self.mock_flavors.attach_mock(mock_flavor_list, 'list')

        result = self.cmd._collect_flavors(parsed_args)
        self.assertEqual(self.cmd.predeploy_errors, 0)
        self.assertEqual(self.cmd.predeploy_warnings, 0)
        self.assertEqual(expected_result, result)

    def test_error_default(self):
        self.check_parser(self.cmd, ['--templates'],
                          [('validation_errors_fatal', True)])

    def test_error_deprecated(self):
        self.check_parser(self.cmd,
                          ['--templates', '--validation-errors-fatal'],
                          [('validation_errors_fatal', True)])

    def test_error_nonfatal(self):
        self.check_parser(self.cmd,
                          ['--templates', '--validation-errors-nonfatal'],
                          [('validation_errors_fatal', False)])

    def test_error_exclusive(self):
        self.assertRaises(utils.ParserException,
                          self.check_parser, self.cmd,
                          ['--templates', '--validation-errors-nonfatal',
                           '--validation-errors-fatal'], [])
