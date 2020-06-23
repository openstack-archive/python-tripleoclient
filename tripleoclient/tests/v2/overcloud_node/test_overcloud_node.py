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

import collections
import fixtures
import json
import mock
import os
import tempfile

from osc_lib.tests import utils as test_utils

from tripleoclient import constants
from tripleoclient.tests.v2.overcloud_node import fakes
from tripleoclient.v2 import overcloud_node


class TestImportNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestImportNode, self).setUp()

        self.nodes_list = [{
            "pm_user": "stack",
            "pm_addr": "192.168.122.1",
            "pm_password": "KEY1",
            "pm_type": "pxe_ssh",
            "mac": [
                "00:0b:d0:69:7e:59"
            ],
        }, {
            "pm_user": "stack",
            "pm_addr": "192.168.122.2",
            "pm_password": "KEY2",
            "pm_type": "pxe_ssh",
            "mac": [
                "00:0b:d0:69:7e:58"
            ]
        }]

        # NOTE(cloudnull): Workflow and client calls are still mocked because
        #                  mistal is still presnet here.
        self.workflow = self.app.client_manager.workflow_engine
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()
        self.websocket.wait_for_messages.return_value = [{
            "status": "SUCCESS",
            "message": "Success",
            "registered_nodes": [{
                "uuid": "MOCK_NODE_UUID"
            }],
            "execution_id": execution.id
        }]

        self.json_file = tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.json')
        json.dump(self.nodes_list, self.json_file)
        self.json_file.close()
        self.addCleanup(os.unlink, self.json_file.name)

        # Get the command object to test
        self.cmd = overcloud_node.ImportNode(self.app, None)

        image = collections.namedtuple('image', ['id', 'name'])
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.image.images.list.return_value = [
            image(id=3, name='overcloud-full'),
        ]

        self.http_boot = '/var/lib/ironic/httpboot'

        self.useFixture(fixtures.MockPatch(
            'os.path.exists', autospec=True,
            side_effect=lambda path: path in [os.path.join(self.http_boot, i)
                                              for i in ('agent.kernel',
                                                        'agent.ramdisk')]))

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_import_only(self, mock_playbook):
        parsed_args = self.check_parser(self.cmd,
                                        [self.json_file.name],
                                        [('introspect', False),
                                         ('provide', False)])
        self.cmd.take_action(parsed_args)

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_import_and_introspect(self, mock_playbook):
        parsed_args = self.check_parser(self.cmd,
                                        [self.json_file.name,
                                         '--introspect'],
                                        [('introspect', True),
                                         ('provide', False)])
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook=mock.ANY,
            inventory=mock.ANY,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=mock.ANY,
            extra_vars={
                'node_uuids': ['MOCK_NODE_UUID'],
                'run_validations': False,
                'concurrency': 20
            }
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_import_and_provide(self, mock_playbook):
        parsed_args = self.check_parser(self.cmd,
                                        [self.json_file.name,
                                         '--provide'],
                                        [('introspect', False),
                                         ('provide', True)])
        self.cmd.take_action(parsed_args)

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_import_and_introspect_and_provide(self, mock_playbook):
        parsed_args = self.check_parser(self.cmd,
                                        [self.json_file.name,
                                         '--introspect',
                                         '--provide'],
                                        [('introspect', True),
                                         ('provide', True)])
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_with(
            workdir=mock.ANY,
            playbook=mock.ANY,
            inventory=mock.ANY,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=mock.ANY,
            extra_vars={
                'node_uuids': ['MOCK_NODE_UUID']
            }
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_import_with_netboot(self, mock_playbook):
        parsed_args = self.check_parser(self.cmd,
                                        [self.json_file.name,
                                         '--no-deploy-image'],
                                        [('no_deploy_image', True)])
        self.cmd.take_action(parsed_args)

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_import_with_no_deployed_image(self, mock_playbook):
        parsed_args = self.check_parser(self.cmd,
                                        [self.json_file.name,
                                         '--instance-boot-option',
                                         'netboot'],
                                        [('instance_boot_option', 'netboot')])
        self.cmd.take_action(parsed_args)


class TestIntrospectNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestIntrospectNode, self).setUp()

        # Get the command object to test
        self.workflow = self.app.client_manager.workflow_engine
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()
        self.websocket.wait_for_messages.return_value = iter([{
            "status": "SUCCESS",
            "message": "Success",
            "introspected_nodes": {},
            "execution_id": execution.id
        }] * 2)

        # Get the command object to test
        self.cmd = overcloud_node.IntrospectNode(self.app, None)

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_introspect_all_manageable_nodes_without_provide(self,
                                                             mock_playbook):
        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable'],
                                        [('all_manageable', True)])
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook=mock.ANY,
            inventory=mock.ANY,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=mock.ANY,
            extra_vars={
                'node_uuids': [],
                'run_validations': False,
                'concurrency': 20,
                'node_timeout': 1200,
                'max_retries': 1,
                'retry_timeout': 120,
            }
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_introspect_all_manageable_nodes_with_provide(self,
                                                          mock_playbook):
        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable', '--provide'],
                                        [('all_manageable', True),
                                         ('provide', True)])
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_with(
            workdir=mock.ANY,
            playbook='cli-overcloud-node-provide.yaml',
            inventory=mock.ANY,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=mock.ANY,
            extra_vars={
                'node_uuids': []
            }
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_introspect_nodes_without_provide(self, mock_playbook):
        nodes = ['node_uuid1', 'node_uuid2']
        parsed_args = self.check_parser(self.cmd,
                                        nodes,
                                        [('node_uuids', nodes)])
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_once_with(
            workdir=mock.ANY,
            playbook='cli-baremetal-introspect.yaml',
            inventory=mock.ANY,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=mock.ANY,
            extra_vars={
                'node_uuids': nodes,
                'run_validations': False,
                'concurrency': 20,
                'node_timeout': 1200,
                'max_retries': 1,
                'retry_timeout': 120,
            }
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_introspect_nodes_with_provide(self, mock_playbook):
        nodes = ['node_uuid1', 'node_uuid2']
        argslist = nodes + ['--provide']
        parsed_args = self.check_parser(self.cmd,
                                        argslist,
                                        [('node_uuids', nodes),
                                         ('provide', True)])
        self.cmd.take_action(parsed_args)
        mock_playbook.assert_called_with(
            workdir=mock.ANY,
            playbook='cli-overcloud-node-provide.yaml',
            inventory=mock.ANY,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=mock.ANY,
            extra_vars={
                'node_uuids': nodes
            }
        )

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_introspect_no_node_or_flag_specified(self, mock_playbook):
        self.assertRaises(test_utils.ParserException,
                          self.check_parser,
                          self.cmd, [], [])

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_introspect_uuids_and_all_both_specified(self, mock_playbook):
        argslist = ['node_id1', 'node_id2', '--all-manageable']
        verifylist = [('node_uuids', ['node_id1', 'node_id2']),
                      ('all_manageable', True)]
        self.assertRaises(test_utils.ParserException,
                          self.check_parser,
                          self.cmd, argslist, verifylist)

    def _check_introspect_all_manageable(self, parsed_args, provide=False):
        self.websocket.wait_for_messages.return_value = iter([{
            "status": "SUCCESS",
            "message": "Success",
            "introspected_nodes": {},
            "execution_id": "IDID"
        }] * 2)

        self.cmd.take_action(parsed_args)

        call_list = [mock.call(
            'tripleo.baremetal.v1.introspect_manageable_nodes',
            workflow_input={'run_validations': False, 'concurrency': 20}
        )]

        if provide:
            call_list.append(mock.call(
                'tripleo.baremetal.v1.provide_manageable_nodes',
                workflow_input={}
            ))

        self.workflow.executions.create.assert_has_calls(call_list)
        self.assertEqual(self.workflow.executions.create.call_count,
                         2 if provide else 1)

    def _check_introspect_nodes(self, parsed_args, nodes, provide=False):
        self.websocket.wait_for_messages.return_value = [{
            "status": "SUCCESS",
            "message": "Success",
            "execution_id": "IDID",
        }]

        self.cmd.take_action(parsed_args)

        call_list = [mock.call(
            'tripleo.baremetal.v1.introspect', workflow_input={
                'node_uuids': nodes,
                'run_validations': False,
                'concurrency': 20}
        )]

        if provide:
            call_list.append(mock.call(
                'tripleo.baremetal.v1.provide', workflow_input={
                    'node_uuids': nodes}
            ))

        self.workflow.executions.create.assert_has_calls(call_list)
        self.assertEqual(self.workflow.executions.create.call_count,
                         2 if provide else 1)


class TestProvisionNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestProvisionNode, self).setUp()
        self.cmd = overcloud_node.ProvisionNode(self.app, None)
        self.cmd.app_args = mock.Mock(verbose_level=1)

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_ok(self, mock_playbook):
        with tempfile.NamedTemporaryFile() as inp:
            with tempfile.NamedTemporaryFile() as outp:
                with tempfile.NamedTemporaryFile() as keyf:
                    inp.write(b'- name: Compute\n- name: Controller\n')
                    inp.flush()
                    keyf.write(b'I am a key')
                    keyf.flush()
                    with open('{}.pub'.format(keyf.name), 'w') as f:
                        f.write('I am a key')

                    argslist = ['--output', outp.name,
                                '--overcloud-ssh-key', keyf.name,
                                inp.name]
                    verifylist = [('input', inp.name),
                                  ('output', outp.name),
                                  ('overcloud_ssh_key', keyf.name)]

                    parsed_args = self.check_parser(self.cmd,
                                                    argslist, verifylist)
                    self.cmd.take_action(parsed_args)

        mock_playbook.assert_called_once_with(
            extra_vars={
                'stack_name': 'overcloud',
                'baremetal_deployment': [
                    {'name': 'Compute'},
                    {'name': 'Controller'}
                ],
                'baremetal_deployed_path': mock.ANY,
                'ssh_public_keys': 'I am a key',
                'ssh_user_name': 'heat-admin',
                'node_timeout': 3600,
                'concurrency': 20
            },
            inventory='localhost,',
            playbook='cli-overcloud-node-provision.yaml',
            playbook_dir='/usr/share/ansible/tripleo-playbooks',
            verbosity=mock.ANY,
            workdir=mock.ANY
        )


class TestUnprovisionNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestUnprovisionNode, self).setUp()
        self.cmd = overcloud_node.UnprovisionNode(self.app, None)
        self.cmd.app_args = mock.Mock(verbose_level=1)

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    @mock.patch('tripleoclient.utils.tempfile')
    @mock.patch('tripleoclient.utils.prompt_user_for_confirmation')
    def test_ok(self, mock_prompt, mock_tempfile, mock_playbook):
        tmp = tempfile.mkdtemp()
        mock_tempfile.mkdtemp.return_value = tmp
        mock_prompt.return_value = True
        unprovision_confirm = os.path.join(tmp, 'unprovision_confirm.json')
        with open(unprovision_confirm, 'w') as confirm:
            confirm.write(json.dumps([
                {'hostname': 'compute-0', 'name': 'baremetal-1'},
                {'hostname': 'controller-0', 'name': 'baremetal-2'}
            ]))

        with tempfile.NamedTemporaryFile() as inp:
            inp.write(b'- name: Compute\n- name: Controller\n')
            inp.flush()
            argslist = ['--all', inp.name]
            verifylist = [('input', inp.name), ('all', True)]

            parsed_args = self.check_parser(self.cmd,
                                            argslist, verifylist)
            self.cmd.take_action(parsed_args)
        mock_playbook.assert_has_calls([
            mock.call(
                extra_vars={
                    'stack_name': 'overcloud',
                    'baremetal_deployment': [
                        {'name': 'Compute'},
                        {'name': 'Controller'}
                    ],
                    'all': True,
                    'prompt': True,
                    'unprovision_confirm': unprovision_confirm
                },
                inventory='localhost,',
                playbook='cli-overcloud-node-unprovision.yaml',
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=mock.ANY,
                workdir=tmp
            ),
            mock.call(
                extra_vars={
                    'stack_name': 'overcloud',
                    'baremetal_deployment': [
                        {'name': 'Compute'},
                        {'name': 'Controller'}
                    ],
                    'all': True,
                    'prompt': False
                },
                inventory='localhost,',
                playbook='cli-overcloud-node-unprovision.yaml',
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=mock.ANY,
                workdir=tmp
            )
        ])
