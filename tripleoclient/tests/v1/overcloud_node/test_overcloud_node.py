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
import copy
import fixtures
import json
import mock
import os
import sys
import tempfile

from osc_lib import exceptions as oscexc
from osc_lib.tests import utils as test_utils
import yaml

from tripleoclient import exceptions
from tripleoclient import plugin
from tripleoclient.tests import fakes as ooofakes
from tripleoclient.tests.v1.overcloud_node import fakes
from tripleoclient.v1 import overcloud_node
from tripleoclient.v2 import overcloud_node as overcloud_node_v2


class TestDeleteNode(fakes.TestDeleteNode):

    def setUp(self):
        super(TestDeleteNode, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_node.DeleteNode(self.app, None)
        self.cmd.app_args = mock.Mock(verbose_level=1)
        self.app.client_manager.workflow_engine = mock.Mock()
        self.tripleoclient = mock.Mock()

        self.workflow = self.app.client_manager.workflow_engine
        self.stack_name = self.app.client_manager.orchestration.stacks.get
        stack = self.stack_name.return_value = mock.Mock(
            stack_name="overcloud"
        )
        stack.output_show.return_value = {'output': {'output_value': []}}
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution

        delete_node = mock.patch(
            'tripleo_common.actions.scale.ScaleDownAction.run',
            autospec=True
        )
        delete_node.start()
        delete_node.return_value = None
        self.addCleanup(delete_node.stop)

        wait_stack = mock.patch(
            'tripleoclient.utils.wait_for_stack_ready',
            autospec=True
        )
        wait_stack.start()
        wait_stack.return_value = None
        self.addCleanup(wait_stack.stop)
        self.app.client_manager.compute.servers.get.return_value = None

    @mock.patch('heatclient.common.event_utils.get_events',
                autospec=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_node_delete(self, mock_playbook, mock_get_events):
        argslist = ['instance1', 'instance2', '--templates',
                    '--stack', 'overcast', '--timeout', '90', '--yes']
        verifylist = [
            ('stack', 'overcast'),
            ('nodes', ['instance1', 'instance2'])
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    @mock.patch('tripleoclient.utils.prompt_user_for_confirmation',
                return_value=False)
    def test_node_delete_no_confirm(self, confirm_mock):
        argslist = ['instance1', 'instance2', '--templates',
                    '--stack', 'overcast', '--timeout', '90']
        verifylist = [
            ('stack', 'overcast'),
            ('nodes', ['instance1', 'instance2'])
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.assertRaises(oscexc.CommandError,
                          self.cmd.take_action,
                          parsed_args)

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True,
                side_effect=exceptions.InvalidConfiguration)
    def test_node_wrong_stack(self, mock_playbook):
        argslist = ['instance1', '--templates',
                    '--stack', 'overcast', '--yes']
        verifylist = [
            ('stack', 'overcast'),
            ('nodes', ['instance1', ])
        ]
        self.stack_name.return_value = None

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)

        self.assertRaises(exceptions.InvalidConfiguration,
                          self.cmd.take_action,
                          parsed_args)

    @mock.patch('heatclient.common.event_utils.get_events',
                autospec=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    def test_node_delete_without_stack(self, mock_playbook,
                                       mock_get_events):
        arglist = ['instance1', '--yes']

        verifylist = [
            ('stack', 'overcloud'),
            ('nodes', ['instance1']),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self.cmd.take_action(parsed_args)

    @mock.patch('heatclient.common.event_utils.get_events',
                autospec=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    @mock.patch('tripleoclient.utils.tempfile')
    def test_node_delete_baremetal_deployment(self,
                                              mock_tempfile,
                                              mock_playbook,
                                              mock_get_events):

        bm_yaml = [{
            'name': 'Compute',
            'count': 5,
            'instances': [{
                'name': 'baremetal-2',
                'hostname': 'overcast-compute-0',
                'provisioned': False
            }],
        }, {
            'name': 'Controller',
            'count': 2,
            'instances': [{
                'name': 'baremetal-1',
                'hostname': 'overcast-controller-1',
                'provisioned': False
            }]
        }]

        tmp = tempfile.mkdtemp()
        mock_tempfile.mkdtemp.side_effect = [
            tmp,
            tempfile.mkdtemp(),
            tempfile.mkdtemp(),
            tempfile.mkdtemp()
        ]

        unprovision_confirm = os.path.join(tmp, 'unprovision_confirm.json')
        with open(unprovision_confirm, 'w') as confirm:
            confirm.write(json.dumps([
                {
                    'hostname': 'overcast-controller-1',
                    'name': 'baremetal-1',
                    'id': 'aaaa'
                }, {
                    'hostname': 'overcast-compute-0',
                    'name': 'baremetal-2',
                    'id': 'bbbb'
                }
            ]))

        with tempfile.NamedTemporaryFile(mode='w') as inp:
            yaml.dump(bm_yaml, inp, encoding='utf-8')
            inp.flush()

            argslist = ['--baremetal-deployment', inp.name, '--templates',
                        '--stack', 'overcast', '--overcloud-ssh-port-timeout',
                        '42', '--timeout', '90', '--yes']
            verifylist = [
                ('stack', 'overcast'),
                ('overcloud_ssh_port_timeout', 42),
                ('baremetal_deployment', inp.name)
            ]
            parsed_args = self.check_parser(self.cmd, argslist, verifylist)

            self.cmd.take_action(parsed_args)

        # Verify
        mock_playbook.assert_has_calls([
            mock.call(
                playbook='cli-overcloud-node-unprovision.yaml',
                inventory='localhost,',
                verbosity=mock.ANY,
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                extra_vars={
                    'stack_name': 'overcast',
                    'baremetal_deployment': [{
                        'count': 5,
                        'instances': [{
                            'hostname': 'overcast-compute-0',
                            'name': 'baremetal-2',
                            'provisioned': False
                        }],
                        'name': 'Compute'
                    }, {
                        'count': 2,
                        'instances': [{
                            'hostname': 'overcast-controller-1',
                            'name': 'baremetal-1',
                            'provisioned': False
                        }], 'name': 'Controller'
                    }],
                    'prompt': True,
                    'unprovision_confirm': unprovision_confirm,
                },
            ),
            mock.call(
                playbook='cli-grant-local-access.yaml',
                inventory='localhost,',
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                verbosity=mock.ANY,
                extra_vars={
                    'access_path': os.path.join(os.environ.get('HOME'),
                                                'config-download'),
                    'execution_user': mock.ANY},
            ),
            mock.call(
                playbook=mock.ANY,
                inventory=mock.ANY,
                workdir=mock.ANY,
                playbook_dir=mock.ANY,
                skip_tags='opendev-validation',
                ansible_cfg=None,
                verbosity=mock.ANY,
                ssh_user='tripleo-admin',
                key=mock.ANY,
                limit_hosts='overcast-controller-1:overcast-compute-0',
                ansible_timeout=42,
                reproduce_command=True,
                extra_env_variables={'ANSIBLE_BECOME': True},
                extra_vars=None,
                tags=None,
                timeout=90,
                forks=None
            ),
            mock.call(
                inventory='localhost,',
                playbook='cli-overcloud-node-unprovision.yaml',
                verbosity=mock.ANY,
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                extra_vars={
                    'stack_name': 'overcast',
                    'baremetal_deployment': [{
                        'count': 5,
                        'instances': [{
                            'hostname': 'overcast-compute-0',
                            'name': 'baremetal-2',
                            'provisioned': False
                        }], 'name': 'Compute'
                    }, {
                        'count': 2,
                        'instances': [{
                            'hostname': 'overcast-controller-1',
                            'name': 'baremetal-1',
                            'provisioned': False
                        }],
                        'name': 'Controller'
                    }],
                    'prompt': False
                },
            )
        ])

    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    @mock.patch('tripleoclient.utils.tempfile')
    def test_nodes_to_delete(self, mock_tempfile, mock_playbook):
        bm_yaml = [{
            'name': 'Compute',
            'count': 5,
            'instances': [{
                'name': 'baremetal-2',
                'hostname': 'overcast-compute-0',
                'provisioned': False
            }],
        }, {
            'name': 'Controller',
            'count': 2,
            'instances': [{
                'name': 'baremetal-1',
                'hostname': 'overcast-controller-1',
                'provisioned': False
            }]
        }]

        tmp = tempfile.mkdtemp()
        mock_tempfile.mkdtemp.return_value = tmp

        unprovision_confirm = os.path.join(tmp, 'unprovision_confirm.json')
        with open(unprovision_confirm, 'w') as confirm:
            confirm.write(json.dumps([
                {
                    'hostname': 'compute-0',
                    'name': 'baremetal-1',
                    'id': 'aaaa'
                }, {
                    'hostname': 'controller-0',
                    'name': 'baremetal-2',
                    'id': 'bbbb'
                }
            ]))

        argslist = ['--baremetal-deployment', '/foo/bm_deploy.yaml']
        verifylist = [
            ('baremetal_deployment', '/foo/bm_deploy.yaml')
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        nodes_text, nodes = self.cmd._nodes_to_delete(parsed_args, bm_yaml)
        expected = '''+--------------+-------------+------+
| hostname     | name        | id   |
+--------------+-------------+------+
| compute-0    | baremetal-1 | aaaa |
| controller-0 | baremetal-2 | bbbb |
+--------------+-------------+------+
'''
        self.assertEqual(expected, nodes_text)
        self.assertEqual(['compute-0', 'controller-0'], nodes)

    def test_check_skiplist_exists(self):
        mock_warning = mock.MagicMock()
        mock_log = mock.MagicMock()
        mock_log.warning = mock_warning
        env = {'parameter_defaults': {}}

        old_logger = self.cmd.log
        self.cmd.log = mock_log
        self.cmd._check_skiplist_exists(env)
        self.cmd.log = old_logger
        mock_warning.assert_not_called()

    def test_check_skiplist_exists_empty(self):
        mock_warning = mock.MagicMock()
        mock_log = mock.MagicMock()
        mock_log.warning = mock_warning
        env = {'parameter_defaults': {'DeploymentServerBlacklist': []}}

        old_logger = self.cmd.log
        self.cmd.log = mock_log
        self.cmd._check_skiplist_exists(env)
        self.cmd.log = old_logger
        mock_warning.assert_not_called()

    def test_check_skiplist_exists_warns(self):
        mock_warning = mock.MagicMock()
        mock_log = mock.MagicMock()
        mock_log.warning = mock_warning
        env = {'parameter_defaults': {'DeploymentServerBlacklist': ['a']}}

        old_logger = self.cmd.log
        self.cmd.log = mock_log
        self.cmd._check_skiplist_exists(env)
        self.cmd.log = old_logger
        expected_message = ('[WARNING] DeploymentServerBlacklist is ignored '
                            'when executing scale down actions. If the '
                            'node(s) being removed should *NOT* have any '
                            'actions executed on them, please shut them off '
                            'prior to their removal.')
        mock_warning.assert_called_once_with(expected_message)


class TestProvideNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestProvideNode, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_node.ProvideNode(self.app, None)

    def test_provide_all_manageable_nodes(self):

        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable'],
                                        [('all_manageable', True)])
        self.cmd.take_action(parsed_args)

    def test_provide_one_node(self):
        node_id = 'node_uuid1'

        parsed_args = self.check_parser(self.cmd,
                                        [node_id],
                                        [('node_uuids', [node_id])])
        self.cmd.take_action(parsed_args)

    def test_provide_multiple_nodes(self):
        node_id1 = 'node_uuid1'
        node_id2 = 'node_uuid2'

        argslist = [node_id1, node_id2]
        verifylist = [('node_uuids', [node_id1, node_id2])]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)


class TestCleanNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestCleanNode, self).setUp()

        self.workflow = self.app.client_manager.workflow_engine
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()

        # Get the command object to test
        self.cmd = overcloud_node.CleanNode(self.app, None)

    def _check_clean_all_manageable(self, parsed_args, provide=False):
        self.cmd.take_action(parsed_args)

    def _check_clean_nodes(self, parsed_args, nodes, provide=False):
        self.cmd.take_action(parsed_args)

    def test_clean_all_manageable_nodes_without_provide(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable'],
                                        [('all_manageable', True)])
        self._check_clean_all_manageable(parsed_args, provide=False)

    def test_clean_all_manageable_nodes_with_provide(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable', '--provide'],
                                        [('all_manageable', True),
                                         ('provide', True)])
        self._check_clean_all_manageable(parsed_args, provide=True)

    def test_clean_nodes_without_provide(self):
        nodes = ['node_uuid1', 'node_uuid2']
        parsed_args = self.check_parser(self.cmd,
                                        nodes,
                                        [('node_uuids', nodes)])
        self._check_clean_nodes(parsed_args, nodes, provide=False)

    def test_clean_nodes_with_provide(self):
        nodes = ['node_uuid1', 'node_uuid2']
        argslist = nodes + ['--provide']

        parsed_args = self.check_parser(self.cmd,
                                        argslist,
                                        [('node_uuids', nodes),
                                         ('provide', True)])
        self._check_clean_nodes(parsed_args, nodes, provide=True)


class TestImportNodeMultiArch(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestImportNodeMultiArch, self).setUp()

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
            "arch": "x86_64",
            "mac": [
                "00:0b:d0:69:7e:58"
            ]
        }, {
            "pm_user": "stack",
            "pm_addr": "192.168.122.3",
            "pm_password": "KEY3",
            "pm_type": "pxe_ssh",
            "arch": "x86_64",
            "platform": "SNB",
            "mac": [
                "00:0b:d0:69:7e:58"
            ]
        }]
        self.json_file = tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.json')
        json.dump(self.nodes_list, self.json_file)
        self.json_file.close()
        self.addCleanup(os.unlink, self.json_file.name)

        self.workflow = self.app.client_manager.workflow_engine
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()

        # Get the command object to test
        self.cmd = overcloud_node_v2.ImportNode(self.app, None)

        image = collections.namedtuple('image', ['id', 'name'])
        self.app.client_manager.image = mock.Mock()
        self.app.client_manager.image.images.list.return_value = [
            image(id=3, name='overcloud-full'),
            image(id=6, name='x86_64-overcloud-full'),
            image(id=9, name='SNB-x86_64-overcloud-full'),
        ]

        self.http_boot = '/var/lib/ironic/httpboot'

        self.mock_playbook = mock.patch(
            "tripleoclient.utils.run_ansible_playbook", spec=True)
        self.mock_run_ansible_playbook = self.mock_playbook.start()
        self.addCleanup(self.mock_playbook.stop)

        existing = ['agent', 'x86_64/agent', 'SNB-x86_64/agent']
        existing = {os.path.join(self.http_boot, name + ext)
                    for name in existing for ext in ('.kernel', '.ramdisk')}

        self.useFixture(fixtures.MockPatch(
            'os.path.exists', autospec=True,
            side_effect=lambda path: path in existing))

    def _check_workflow_call(self, parsed_args, introspect=False,
                             provide=False, local=None, no_deploy_image=False):
        self.websocket.wait_for_messages.return_value = [{
            "status": "SUCCESS",
            "message": "Success",
            "registered_nodes": [{
                "uuid": "MOCK_NODE_UUID"
            }],
            "execution_id": "IDID"
        }]

        file_return_nodes = [
            {
                'uuid': 'MOCK_NODE_UUID'
            }
        ]
        mock_open = mock.mock_open(read_data=json.dumps(file_return_nodes))
        # TODO(cloudnull): Remove this when py27 is dropped
        if sys.version_info >= (3, 0):
            mock_open_path = 'builtins.open'
        else:
            mock_open_path = 'tripleoclient.v1.overcloud_node.open'
        with mock.patch(mock_open_path, mock_open):
            self.cmd.take_action(parsed_args)

        nodes_list = copy.deepcopy(self.nodes_list)
        if not no_deploy_image:
            nodes_list[0]['kernel_id'] = (
                'file://%s/agent.kernel' % self.http_boot)
            nodes_list[0]['ramdisk_id'] = (
                'file://%s/agent.ramdisk' % self.http_boot)
            nodes_list[1]['kernel_id'] = (
                'file://%s/x86_64/agent.kernel' % self.http_boot)
            nodes_list[1]['ramdisk_id'] = (
                'file://%s/x86_64/agent.ramdisk' % self.http_boot)
            nodes_list[2]['kernel_id'] = (
                'file://%s/SNB-x86_64/agent.kernel' % self.http_boot)
            nodes_list[2]['ramdisk_id'] = (
                'file://%s/SNB-x86_64/agent.ramdisk' % self.http_boot)

        if introspect:
            self.mock_run_ansible_playbook.assert_called_with(
                extra_vars={
                    'node_uuids': ['MOCK_NODE_UUID']},
                inventory='localhost,',
                playbook='cli-overcloud-node-provide.yaml',
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                workdir=mock.ANY,
            )

    def test_import_only(self):
        argslist = [self.json_file.name]
        verifylist = [('introspect', False),
                      ('provide', False)]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self._check_workflow_call(parsed_args)

    def test_import_with_netboot(self):
        arglist = [self.json_file.name, '--instance-boot-option', 'netboot']
        verifylist = [('instance_boot_option', 'netboot')]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self._check_workflow_call(parsed_args, local=False)

    def test_import_with_no_deployed_image(self):
        arglist = [self.json_file.name, '--no-deploy-image']
        verifylist = [('no_deploy_image', True)]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self._check_workflow_call(parsed_args, no_deploy_image=True)


class TestConfigureNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestConfigureNode, self).setUp()

        self.workflow = self.app.client_manager.workflow_engine
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        self.websocket = client.messaging_websocket()
        self.websocket.wait_for_messages.return_value = iter([{
            "status": "SUCCESS",
            "message": "",
            "execution_id": "IDID"
        }])

        # Get the command object to test
        self.cmd = overcloud_node.ConfigureNode(self.app, None)

        self.http_boot = '/var/lib/ironic/httpboot'

        self.workflow_input = {
            'kernel_name': 'file://%s/agent.kernel' % self.http_boot,
            'ramdisk_name': 'file://%s/agent.ramdisk' % self.http_boot,
            'instance_boot_option': None,
            'root_device': None,
            'root_device_minimum_size': 4,
            'overwrite_root_device_hints': False
        }

    def test_configure_all_manageable_nodes(self):
        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable'],
                                        [('all_manageable', True)])
        self.cmd.take_action(parsed_args)

    def test_configure_specified_nodes(self):
        argslist = ['node_uuid1', 'node_uuid2']
        verifylist = [('node_uuids', ['node_uuid1', 'node_uuid2'])]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    def test_configure_no_node_or_flag_specified(self):
        self.assertRaises(test_utils.ParserException,
                          self.check_parser,
                          self.cmd, [], [])

    def test_configure_uuids_and_all_both_specified(self):
        argslist = ['node_id1', 'node_id2', '--all-manageable']
        verifylist = [('node_uuids', ['node_id1', 'node_id2']),
                      ('all_manageable', True)]
        self.assertRaises(test_utils.ParserException,
                          self.check_parser,
                          self.cmd, argslist, verifylist)

    def test_configure_kernel_and_ram(self):
        argslist = ['--all-manageable', '--deploy-ramdisk', 'test_ramdisk',
                    '--deploy-kernel', 'test_kernel']
        verifylist = [('deploy_kernel', 'test_kernel'),
                      ('deploy_ramdisk', 'test_ramdisk')]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    def test_configure_instance_boot_option(self):
        argslist = ['--all-manageable', '--instance-boot-option', 'netboot']
        verifylist = [('instance_boot_option', 'netboot')]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    def test_configure_root_device(self):
        argslist = ['--all-manageable',
                    '--root-device', 'smallest',
                    '--root-device-minimum-size', '2',
                    '--overwrite-root-device-hints']
        verifylist = [('root_device', 'smallest'),
                      ('root_device_minimum_size', 2),
                      ('overwrite_root_device_hints', True)]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    def test_configure_specified_node_with_all_arguments(self):
        argslist = ['node_id',
                    '--deploy-kernel', 'test_kernel',
                    '--deploy-ramdisk', 'test_ramdisk',
                    '--instance-boot-option', 'netboot',
                    '--root-device', 'smallest',
                    '--root-device-minimum-size', '2',
                    '--overwrite-root-device-hints']
        verifylist = [('node_uuids', ['node_id']),
                      ('deploy_kernel', 'test_kernel'),
                      ('deploy_ramdisk', 'test_ramdisk'),
                      ('instance_boot_option', 'netboot'),
                      ('root_device', 'smallest'),
                      ('root_device_minimum_size', 2),
                      ('overwrite_root_device_hints', True)]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)


class TestDiscoverNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestDiscoverNode, self).setUp()

        self.workflow = self.app.client_manager.workflow_engine
        execution = mock.Mock()
        execution.id = "IDID"
        self.workflow.executions.create.return_value = execution
        client = self.app.client_manager.tripleoclient
        client.create_mistral_context = plugin.ClientWrapper(
            instance=ooofakes.FakeInstanceData
        ).create_mistral_context
        self.websocket = client.messaging_websocket()

        self.cmd = overcloud_node.DiscoverNode(self.app, None)

        self.gcn = mock.patch(
            'tripleo_common.actions.baremetal.GetCandidateNodes',
            autospec=True
        )
        self.gcn.start()
        self.addCleanup(self.gcn.stop)

        self.websocket.wait_for_messages.return_value = [{
            "status": "SUCCESS",
            "message": "Success",
            "registered_nodes": [{
                "uuid": "MOCK_NODE_UUID"
            }],
            "execution_id": "IDID"
        }]

        self.http_boot = '/var/lib/ironic/httpboot'

    def test_with_ip_range(self):
        argslist = ['--range', '10.0.0.0/24',
                    '--credentials', 'admin:password']
        verifylist = [('ip_addresses', '10.0.0.0/24'),
                      ('credentials', ['admin:password'])]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    def test_with_address_list(self):
        argslist = ['--ip', '10.0.0.1', '--ip', '10.0.0.2',
                    '--credentials', 'admin:password']
        verifylist = [('ip_addresses', ['10.0.0.1', '10.0.0.2']),
                      ('credentials', ['admin:password'])]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    def test_with_all_options(self):
        argslist = ['--range', '10.0.0.0/24',
                    '--credentials', 'admin:password',
                    '--credentials', 'admin2:password2',
                    '--port', '623', '--port', '6230',
                    '--introspect', '--provide', '--run-validations',
                    '--no-deploy-image', '--instance-boot-option', 'netboot',
                    '--concurrency', '10']
        verifylist = [('ip_addresses', '10.0.0.0/24'),
                      ('credentials', ['admin:password', 'admin2:password2']),
                      ('port', [623, 6230]),
                      ('introspect', True),
                      ('run_validations', True),
                      ('concurrency', 10),
                      ('provide', True),
                      ('no_deploy_image', True),
                      ('instance_boot_option', 'netboot')]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)


class TestExtractProvisionedNode(test_utils.TestCommand):

    def setUp(self):
        super(TestExtractProvisionedNode, self).setUp()

        self.orchestration = mock.Mock()
        self.app.client_manager.orchestration = self.orchestration

        self.baremetal = mock.Mock()
        self.app.client_manager.baremetal = self.baremetal

        self.cmd = overcloud_node.ExtractProvisionedNode(self.app, None)

        self.extract_file = tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.yaml')
        self.extract_file.close()
        self.addCleanup(os.unlink, self.extract_file.name)

    def test_extract(self):
        stack_dict = {
            'parameters': {
                'ComputeHostnameFormat': '%stackname%-novacompute-%index%',
                'ControllerHostnameFormat': '%stackname%-controller-%index%'
            },
            'outputs': [{
                'output_key': 'AnsibleHostVarsMap',
                'output_value': {
                    'Compute': [
                        'overcloud-novacompute-0'
                    ],
                    'Controller': [
                        'overcloud-controller-0',
                        'overcloud-controller-1',
                        'overcloud-controller-2'
                    ],
                }
            }]
        }
        stack = mock.Mock()
        stack.to_dict.return_value = stack_dict
        self.orchestration.stacks.get.return_value = stack

        nodes = [
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
            mock.Mock()
        ]
        nodes[0].name = 'bm-0'
        nodes[1].name = 'bm-1'
        nodes[2].name = 'bm-2'
        nodes[3].name = 'bm-3'

        nodes[0].instance_info = {'display_name': 'overcloud-controller-0'}
        nodes[1].instance_info = {'display_name': 'overcloud-controller-1'}
        nodes[2].instance_info = {'display_name': 'overcloud-controller-2'}
        nodes[3].instance_info = {'display_name': 'overcloud-novacompute-0'}

        self.baremetal.node.list.return_value = nodes

        argslist = ['--output', self.extract_file.name, '--yes']
        self.app.command_options = argslist
        verifylist = [('output', self.extract_file.name), ('yes', True)]

        parsed_args = self.check_parser(self.cmd,
                                        argslist, verifylist)
        self.cmd.take_action(parsed_args)

        result = self.cmd.app.stdout.make_string()
        self.assertEqual([{
            'name': 'Compute',
            'count': 1,
            'hostname_format': '%stackname%-novacompute-%index%',
            'instances': [{
                'hostname': 'overcloud-novacompute-0',
                'name': 'bm-3'
            }],
        }, {
            'name': 'Controller',
            'count': 3,
            'hostname_format': '%stackname%-controller-%index%',
            'instances': [{
                'hostname': 'overcloud-controller-0',
                'name': 'bm-0'
            }, {
                'hostname': 'overcloud-controller-1',
                'name': 'bm-1'
            }, {
                'hostname': 'overcloud-controller-2',
                'name': 'bm-2'
            }],
        }], yaml.safe_load(result))

        with open(self.extract_file.name) as f:
            self.assertEqual(yaml.safe_load(result), yaml.safe_load(f))

    def test_extract_empty(self):
        stack_dict = {
            'parameters': {},
            'outputs': []
        }
        stack = mock.Mock()
        stack.to_dict.return_value = stack_dict
        self.orchestration.stacks.get.return_value = stack

        nodes = []

        self.baremetal.node.list.return_value = nodes

        argslist = []
        self.app.command_options = argslist
        verifylist = []

        parsed_args = self.check_parser(self.cmd,
                                        argslist, verifylist)
        self.cmd.take_action(parsed_args)
        result = self.cmd.app.stdout.make_string()
        self.assertIsNone(yaml.safe_load(result))
