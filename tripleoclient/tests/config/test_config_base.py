#   Copyright 2018 Red Hat, Inc.
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

from oslo_config import cfg
from tripleoclient.config.base import BaseConfig
from tripleoclient.tests import base


class TestBaseConfig(base.TestCase):
    def setUp(self):
        super(TestBaseConfig, self).setUp()
        # Get the class object to test
        self.config = BaseConfig()

    def test_sort_opts(self):
        _opts = [
            cfg.BoolOpt('b', default=True),
            cfg.BoolOpt('a', default=True)
        ]
        expected = [
            cfg.BoolOpt('a', default=True),
            cfg.BoolOpt('b', default=True)
        ]
        ret = self.config.sort_opts(_opts)
        self.assertEqual(expected, ret)

    def test_get_base_opts(self):
        ret = self.config.get_base_opts()
        expected = ['cleanup', 'output_dir']
        self.assertEqual(expected, [x.name for x in ret])
