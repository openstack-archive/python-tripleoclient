#   Copyright 2019 Red Hat, Inc.
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
import os

from io import StringIO
import mock
import six
from unittest import TestCase
import yaml

from tripleoclient import export


class TestExport(TestCase):
    def setUp(self):
        self.unlink_patch = mock.patch('os.unlink')
        self.addCleanup(self.unlink_patch.stop)
        self.unlink_patch.start()
        self.mock_log = mock.Mock('logging.getLogger')

        outputs = [
            {'output_key': 'EndpointMap',
             'output_value': dict(em_key='em_value')},
            {'output_key': 'HostsEntry',
             'output_value': 'hosts entry'},
            {'output_key': 'GlobalConfig',
             'output_value': dict(gc_key='gc_value')},
        ]
        self.mock_stack = mock.Mock()
        self.mock_stack.to_dict.return_value = dict(outputs=outputs)
        self.mock_open = mock.mock_open(read_data='{"an_key":"an_value"}')

    @mock.patch('tripleoclient.utils.get_stack')
    def test_export_stack(self, mock_get_stack):
        heat = mock.Mock()
        mock_get_stack.return_value = self.mock_stack
        with mock.patch('six.moves.builtins.open', self.mock_open):
            data = export.export_stack(heat, "overcloud")

        expected = \
            {'AllNodesExtraMapData': {u'an_key': u'an_value'},
             'EndpointMapOverride': {'em_key': 'em_value'},
             'ExtraHostFileEntries': 'hosts entry',
             'GlobalConfigExtraMapData': {'gc_key': 'gc_value'}}

        self.assertEqual(expected, data)
        self.mock_open.assert_called_once_with(
            os.path.join(
                os.environ.get('HOME'),
                'config-download/overcloud/group_vars/overcloud.json'),
            'r')

    @mock.patch('tripleoclient.utils.get_stack')
    def test_export_stack_should_filter(self, mock_get_stack):
        heat = mock.Mock()
        mock_get_stack.return_value = self.mock_stack
        self.mock_open = mock.mock_open(
            read_data='{"an_key":"an_value","ovn_dbs_vip":"vip"}')
        with mock.patch('six.moves.builtins.open', self.mock_open):
            data = export.export_stack(heat, "overcloud", should_filter=True)

        expected = \
            {'AllNodesExtraMapData': {u'ovn_dbs_vip': u'vip'},
             'EndpointMapOverride': {'em_key': 'em_value'},
             'ExtraHostFileEntries': 'hosts entry',
             'GlobalConfigExtraMapData': {'gc_key': 'gc_value'}}

        self.assertEqual(expected, data)
        self.mock_open.assert_called_once_with(
            os.path.join(
                os.environ.get('HOME'),
                'config-download/overcloud/group_vars/overcloud.json'),
            'r')

    @mock.patch('tripleoclient.utils.get_stack')
    def test_export_stack_cd_dir(self, mock_get_stack):
        heat = mock.Mock()
        mock_get_stack.return_value = self.mock_stack
        with mock.patch('six.moves.builtins.open', self.mock_open):
            export.export_stack(heat, "overcloud",
                                config_download_dir='/foo')
        self.mock_open.assert_called_once_with(
            '/foo/overcloud/group_vars/overcloud.json', 'r')

    @mock.patch('tripleoclient.utils.get_stack')
    def test_export_stack_stack_name(self, mock_get_stack):
        heat = mock.Mock()
        mock_get_stack.return_value = self.mock_stack
        with mock.patch('six.moves.builtins.open', self.mock_open):
            export.export_stack(heat, "control")
        mock_get_stack.assert_called_once_with(heat, 'control')

    def test_export_passwords(self):
        swift = mock.Mock()
        mock_passwords = {
            'passwords': {
                'a': 'A',
                'b': 'B'
            }
        }
        sio = StringIO()
        sio.write(six.text_type(yaml.dump(mock_passwords)))
        sio.seek(0)
        swift.get_object.return_value = ("", sio)
        data = export.export_passwords(swift, 'overcloud')

        swift.get_object.assert_called_once_with(
            'overcloud', 'plan-environment.yaml')

        self.assertEqual(mock_passwords['passwords'], data)

    def test_export_passwords_excludes(self):
        swift = mock.Mock()
        mock_passwords = {
            'passwords': {
                'a': 'A',
                'b': 'B',
                'Cephkey': 'cephkey',
                'cephkey': 'cephkey',
                'CEPH': 'cephkey'
            }
        }
        sio = StringIO()
        sio.write(six.text_type(yaml.dump(mock_passwords)))
        sio.seek(0)
        swift.get_object.return_value = ("", sio)
        data = export.export_passwords(swift, 'overcloud')

        mock_passwords['passwords'].pop('Cephkey')
        mock_passwords['passwords'].pop('cephkey')
        mock_passwords['passwords'].pop('CEPH')

        self.assertEqual(mock_passwords['passwords'], data)
