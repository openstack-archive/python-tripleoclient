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

import json
import tempfile
from unittest import mock

from osc_lib.tests import utils as test_utils

from tripleoclient.tests import fakes as ooofakes
from tripleoclient.tests.v1.baremetal import fakes
from tripleoclient.v1 import overcloud_raid


class TestCreateRAID(fakes.TestBaremetal):

    def setUp(self):
        super(TestCreateRAID, self).setUp()
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.app.options = ooofakes.FakeOptions()
        self.cmd = overcloud_raid.CreateRAID(self.app, app_args)

        self.conf = {
            "logical_disks": [
                {"foo": "bar"},
                {"foo2": "bar2"}
            ]
        }
        execution = mock.MagicMock(
            output=json.dumps({
                "result": None
            })
        )
        execution.id = "IDID"
        playbook_runner = mock.patch(
            'tripleoclient.utils.run_ansible_playbook',
            autospec=True
        )
        playbook_runner.start()

    def test_ok(self):
        conf = json.dumps(self.conf)
        arglist = ['--node', 'uuid1', '--node', 'uuid2', conf]
        verifylist = [
            ('node', ['uuid1', 'uuid2']),
            ('configuration', conf)
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

    def test_from_file(self):
        with tempfile.NamedTemporaryFile('w+t') as fp:
            json.dump(self.conf, fp)
            fp.flush()
            arglist = ['--node', 'uuid1', '--node', 'uuid2', fp.name]
            verifylist = [
                ('node', ['uuid1', 'uuid2']),
                ('configuration', fp.name)
            ]
            parsed_args = self.check_parser(self.cmd, arglist, verifylist)

            self.cmd.take_action(parsed_args)

    def test_no_nodes(self):
        arglist = ['{}']
        verifylist = [
            ('configuration', '{}')
        ]
        self.assertRaises(test_utils.ParserException, self.check_parser,
                          self.cmd, arglist, verifylist)

    def test_not_yaml(self):
        arglist = ['--node', 'uuid1', '--node', 'uuid2', ':']
        verifylist = [
            ('node', ['uuid1', 'uuid2']),
            ('configuration', ':')
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(RuntimeError, 'cannot be parsed as YAML',
                               self.cmd.take_action, parsed_args)

    def test_bad_type(self):
        for conf in ('[]', '{logical_disks: 42}', '{logical_disks: [42]}'):
            arglist = ['--node', 'uuid1', '--node', 'uuid2', conf]
            verifylist = [
                ('node', ['uuid1', 'uuid2']),
                ('configuration', conf)
            ]
            parsed_args = self.check_parser(self.cmd, arglist, verifylist)

            self.assertRaises(TypeError, self.cmd.take_action, parsed_args)

    def test_bad_value(self):
        conf = '{another_key: [{}]}'
        arglist = ['--node', 'uuid1', '--node', 'uuid2', conf]
        verifylist = [
            ('node', ['uuid1', 'uuid2']),
            ('configuration', conf)
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaises(ValueError, self.cmd.take_action, parsed_args)
