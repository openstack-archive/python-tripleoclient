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
import uuid

from unittest import mock

from tripleoclient.tests import fakes


class TestDeleteNode(fakes.FakePlaybookExecution):

    def setUp(self):
        super(TestDeleteNode, self).setUp()


class TestOvercloudNode(fakes.FakePlaybookExecution):

    def setUp(self):
        super(TestOvercloudNode, self).setUp()

        self.mock_playbook = mock.patch(
            'tripleoclient.utils.run_ansible_playbook',
            autospec=True
        )
        self.mock_playbook.start()
        self.addCleanup(self.mock_playbook.stop)


def make_fake_machine(machine_name, provision_state='manageable',
                      is_maintenance=False, machine_id=None):
    if not machine_id:
        machine_id = uuid.uuid4().hex
    return(fakes.FakeMachine(id=machine_id, name=machine_name,
                             provision_state=provision_state,
                             is_maintenance=is_maintenance))
