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

from unittest import TestCase

from rdomanager_oscplugin.v1 import util


class TestPasswordsUtil(TestCase):

    def test_generate_passwords(self):

        passwords = util.generate_overcloud_passwords()
        passwords2 = util.generate_overcloud_passwords()

        self.assertEqual(len(passwords), 13)
        self.assertNotEqual(passwords, passwords2)
