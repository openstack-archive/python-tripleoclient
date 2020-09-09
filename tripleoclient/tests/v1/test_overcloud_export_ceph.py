#   Copyright 2020 Red Hat, Inc.
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
import os

import mock

from osc_lib.tests import utils

from tripleoclient.v1 import overcloud_export_ceph


class TestOvercloudExportCeph(utils.TestCommand):

    def setUp(self):
        super(TestOvercloudExportCeph, self).setUp()

        self.cmd = overcloud_export_ceph.ExportOvercloudCeph(self.app, None)
        self.tripleoclient = mock.Mock()
        self.app.client_manager.tripleoclient = self.tripleoclient
        self.mock_open = mock.mock_open()

    @mock.patch('os.path.exists')
    @mock.patch('yaml.safe_dump')
    @mock.patch('tripleoclient.export.export_ceph')
    def test_export_ceph(self, mock_export_ceph,
                         mock_safe_dump,
                         mock_exists):
        argslist = ['--stack', 'dcn0']
        verifylist = [('stack', 'dcn0')]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        mock_exists.return_value = False
        expected = {
            'external_cluster_mon_ips': '192.168.24.42',
            'keys': [
                {'name': 'client.openstack'}
            ],
            'ceph_conf_overrides': {
                'client': {
                    'keyring': '/etc/ceph/dcn0.client.openstack.keyring'
                }
            },
            'cluster': 'dcn0',
            'fsid': 'a5a22d37-e01f-4fa0-a440-c72585c7487f',
            'dashboard_enabled': False
        }
        data = {}
        data['parameter_defaults'] = {}
        data['parameter_defaults']['CephExternalMultiConfig'] = [expected]
        mock_export_ceph.return_value = expected

        with mock.patch('six.moves.builtins.open', self.mock_open):
            self.cmd.take_action(parsed_args)
        path = os.path.join(os.environ.get('HOME'), 'config-download')
        mock_export_ceph.assert_called_once_with('dcn0', 'openstack', path)
        self.assertEqual(data, mock_safe_dump.call_args[0][0])
