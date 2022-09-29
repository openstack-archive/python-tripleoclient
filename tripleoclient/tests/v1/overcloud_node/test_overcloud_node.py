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
import os
import tempfile
from unittest import mock

import openstack

from osc_lib import exceptions as oscexc
from osc_lib.tests import utils as test_utils
from oslo_utils import units
import yaml

from tripleoclient import exceptions
from tripleoclient.tests.v1.overcloud_node import fakes
from tripleoclient.v1 import overcloud_node
from tripleoclient.v2 import overcloud_node as overcloud_node_v2


class TestDeleteNode(fakes.TestDeleteNode):

    def setUp(self):
        super(TestDeleteNode, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_node.DeleteNode(self.app, None)
        self.cmd.app_args = mock.Mock(verbose_level=1)
        self.tripleoclient = mock.Mock()

        self.stack_name = self.app.client_manager.orchestration.stacks.get
        stack = self.stack_name.return_value = mock.Mock(
            stack_name="overcloud"
        )
        stack.output_show.return_value = {'output': {'output_value': []}}

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
    def test_node_delete(self, mock_playbook,
                         mock_get_events):
        argslist = ['instance1', 'instance2', '--stack', 'overcast',
                    '--timeout', '90', '--yes']
        verifylist = [
            ('stack', 'overcast'),
            ('nodes', ['instance1', 'instance2'])
        ]
        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    @mock.patch('tripleoclient.utils.prompt_user_for_confirmation',
                return_value=False)
    def test_node_delete_no_confirm(self, confirm_mock):
        argslist = ['instance1', 'instance2', '--stack', 'overcast',
                    '--timeout', '90']
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
        argslist = ['instance1', '--stack', 'overcast', '--yes']
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

    @mock.patch('tripleoclient.utils.get_key')
    @mock.patch('tripleoclient.utils.get_default_working_dir')
    @mock.patch('heatclient.common.event_utils.get_events',
                autospec=True)
    @mock.patch('tripleoclient.utils.run_ansible_playbook',
                autospec=True)
    @mock.patch('tripleoclient.utils.tempfile')
    def test_node_delete_baremetal_deployment(self,
                                              mock_tempfile,
                                              mock_playbook,
                                              mock_get_events,
                                              mock_dir,
                                              mock_key):

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
            tempfile.mkdtemp(),
            tempfile.mkdtemp()
        ]

        mock_dir.return_value = "/home/stack/overcloud-deploy"
        ansible_dir = "{}/config-download/overcast".format(
            mock_dir.return_value
        )

        inventory = "{}/tripleo-ansible-inventory.yaml".format(
            ansible_dir
        )

        ansible_cfg = "{}/ansible.cfg".format(
            ansible_dir
        )

        mock_key.return_value = '/home/stack/.ssh/id_rsa_tripleo'

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

            argslist = ['--baremetal-deployment', inp.name, '--stack',
                        'overcast', '--overcloud-ssh-port-timeout', '42',
                        '--timeout', '90', '--yes']
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
                timeout=mock.ANY,
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
                playbook='scale_playbook.yaml',
                inventory=inventory,
                workdir=ansible_dir,
                playbook_dir=ansible_dir,
                ansible_cfg=ansible_cfg,
                ssh_user='tripleo-admin',
                limit_hosts='overcast-controller-1:overcast-compute-0',
                reproduce_command=True,
                ignore_unreachable=True,
                timeout=mock.ANY,
                extra_env_variables={
                    "ANSIBLE_BECOME": True,
                    "ANSIBLE_PRIVATE_KEY_FILE":
                    "/home/stack/.ssh/id_rsa_tripleo"
                }
            ),
            mock.call(
                inventory='localhost,',
                playbook='cli-overcloud-node-unprovision.yaml',
                verbosity=mock.ANY,
                workdir=mock.ANY,
                playbook_dir='/usr/share/ansible/tripleo-playbooks',
                timeout=mock.ANY,
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
                    'prompt': False,
                    'manage_network_ports': True
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


@mock.patch.object(openstack.baremetal.v1._proxy, 'Proxy',
                   autospec=True, name='mock_bm')
@mock.patch('openstack.config', autospec=True,
            name='mock_conf')
@mock.patch('openstack.connect', autospec=True,
            name='mock_connect')
@mock.patch.object(openstack.connection,
                   'Connection', autospec=True)
class TestProvideNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestProvideNode, self).setUp()
        # Get the command object to test
        self.cmd = overcloud_node.ProvideNode(self.app, None)

        iterate_timeout = mock.MagicMock()
        iterate_timeout.start()

        self.fake_baremetal_node = fakes.make_fake_machine(
            machine_name='node1',
            machine_id='4e540e11-1366-4b57-85d5-319d168d98a1'
        )
        self.fake_baremetal_node2 = fakes.make_fake_machine(
            machine_name='node2',
            machine_id='9070e42d-1ad7-4bd0-b868-5418bc9c7176'
        )

    def test_provide_all_manageable_nodes(self, mock_conn,
                                          mock_connect, mock_conf,
                                          mock_bm):

        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm

        mock_bm.baremetal.nodes.side_effect = [
            iter([self.fake_baremetal_node]),
            iter([self.fake_baremetal_node2])
        ]
        mock_bm.baremetal.get_node.side_effect = [
            self.fake_baremetal_node,
            self.fake_baremetal_node2]

        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable'],
                                        [('all_manageable', True)])
        self.cmd.take_action(parsed_args)

    def test_provide_one_node(self, mock_conn,
                              mock_connect, mock_conf,
                              mock_bm):
        node_id = 'node_uuid1'

        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm
        mock_bm.baremetal.get_node.side_effect = [
            self.fake_baremetal_node]

        parsed_args = self.check_parser(self.cmd,
                                        [node_id],
                                        [('node_uuids', [node_id])])
        self.cmd.take_action(parsed_args)

    def test_provide_multiple_nodes(self, mock_conn,
                                    mock_connect, mock_conf,
                                    mock_bm):
        node_id1 = 'node_uuid1'
        node_id2 = 'node_uuid2'

        argslist = [node_id1, node_id2]
        verifylist = [('node_uuids', [node_id1, node_id2])]

        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm
        mock_bm.baremetal.get_node.side_effect = [
            self.fake_baremetal_node,
            self.fake_baremetal_node2
        ]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)


@mock.patch.object(openstack.baremetal.v1._proxy, 'Proxy',
                   autospec=True, name='mock_bm')
@mock.patch('openstack.config', autospec=True,
            name='mock_conf')
@mock.patch('openstack.connect', autospec=True,
            name='mock_connect')
@mock.patch.object(openstack.connection,
                   'Connection', autospec=True)
class TestCleanNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestCleanNode, self).setUp()

        # Get the command object to test
        self.cmd = overcloud_node.CleanNode(self.app, None)

        self.fake_baremetal_node = fakes.make_fake_machine(
            machine_name='node1',
            machine_id='4e540e11-1366-4b57-85d5-319d168d98a1'
        )
        self.fake_baremetal_node2 = fakes.make_fake_machine(
            machine_name='node2',
            machine_id='9070e42d-1ad7-4bd0-b868-5418bc9c7176'
        )

    def _check_clean_all_manageable(self, parsed_args, mock_conn,
                                    mock_connect, mock_conf,
                                    mock_bm,
                                    provide=False):
        mock_bm.baremetal.nodes.side_effect = [
            iter([self.fake_baremetal_node]),
            iter([self.fake_baremetal_node])
        ]
        mock_bm.baremetal.get_node.side_effect = [
            self.fake_baremetal_node,
            self.fake_baremetal_node]
        self.cmd.take_action(parsed_args)

    def _check_clean_nodes(self, parsed_args, nodes, mock_conn,
                           mock_connect, mock_conf,
                           mock_bm, provide=False):
        self.cmd.take_action(parsed_args)

    def test_clean_all_manageable_nodes_without_provide(self, mock_conn,
                                                        mock_connect,
                                                        mock_conf,
                                                        mock_bm):
        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm
        mock_bm.baremetal.nodes.return_value = iter([
            self.fake_baremetal_node
        ])
        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable'],
                                        [('all_manageable', True)])
        self._check_clean_all_manageable(parsed_args, mock_conn,
                                         mock_connect, mock_conf,
                                         mock_bm, provide=False)

    def test_clean_all_manageable_nodes_with_provide(self, mock_conn,
                                                     mock_connect, mock_conf,
                                                     mock_bm):
        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm
        mock_bm.baremetal.nodes.side_effect = [
            iter([self.fake_baremetal_node]),
            iter([self.fake_baremetal_node])]
        mock_bm.baremetal.get_node.side_effect = [
            self.fake_baremetal_node,
            self.fake_baremetal_node]
        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable', '--provide'],
                                        [('all_manageable', True),
                                         ('provide', True)])
        self._check_clean_all_manageable(parsed_args, mock_conn,
                                         mock_connect, mock_conf,
                                         mock_bm, provide=False)

    def test_clean_nodes_without_provide(self, mock_conn,
                                         mock_connect, mock_conf,
                                         mock_bm):
        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm
        nodes = ['node_uuid1', 'node_uuid2']
        parsed_args = self.check_parser(self.cmd,
                                        nodes,
                                        [('node_uuids', nodes)])
        self._check_clean_nodes(parsed_args, nodes, mock_conn,
                                mock_connect, mock_conf,
                                mock_bm, provide=False)

    def test_clean_nodes_with_provide(self, mock_conn,
                                      mock_connect, mock_conf,
                                      mock_bm):
        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm

        nodes = ['node_uuid1', 'node_uuid2']
        argslist = nodes + ['--provide']

        mock_bm.baremetal.get_node.side_effect = [
            self.fake_baremetal_node,
            self.fake_baremetal_node2
        ]

        parsed_args = self.check_parser(self.cmd,
                                        argslist,
                                        [('node_uuids', nodes),
                                         ('provide', True)])
        self._check_clean_nodes(parsed_args, nodes, mock_conn,
                                mock_connect, mock_conf,
                                mock_bm, provide=False)


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
        file_return_nodes = [
            {
                'uuid': 'MOCK_NODE_UUID'
            }
        ]
        mock_open = mock.mock_open(read_data=json.dumps(file_return_nodes))
        with mock.patch('builtins.open', mock_open):
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


@mock.patch.object(openstack.baremetal.v1._proxy, 'Proxy',
                   autospec=True, name='mock_bm')
@mock.patch('openstack.config', autospec=True,
            name='mock_conf')
@mock.patch('openstack.connect', autospec=True,
            name='mock_connect')
@mock.patch.object(openstack.connection,
                   'Connection', autospec=True)
class TestConfigureNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestConfigureNode, self).setUp()

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
        # Mock disks
        self.disks = [
            {'name': '/dev/sda', 'size': 11 * units.Gi},
            {'name': '/dev/sdb', 'size': 2 * units.Gi},
            {'name': '/dev/sdc', 'size': 5 * units.Gi},
            {'name': '/dev/sdd', 'size': 21 * units.Gi},
            {'name': '/dev/sde', 'size': 13 * units.Gi},
        ]

        for i, disk in enumerate(self.disks):
            disk['wwn'] = 'wwn%d' % i
            disk['serial'] = 'serial%d' % i

        self.fake_baremetal_node = fakes.make_fake_machine(
            machine_name='node1',
            machine_id='4e540e11-1366-4b57-85d5-319d168d98a1'
        )
        self.fake_baremetal_node2 = fakes.make_fake_machine(
            machine_name='node2',
            machine_id='9070e42d-1ad7-4bd0-b868-5418bc9c7176'
        )

    def test_configure_all_manageable_nodes(self, mock_conn,
                                            mock_connect, mock_conf,
                                            mock_bm):
        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm
        mock_bm.baremetal.nodes.side_effect = [
            iter([self.fake_baremetal_node]),
            iter([self.fake_baremetal_node])]
        parsed_args = self.check_parser(self.cmd,
                                        ['--all-manageable'],
                                        [('all_manageable', True)])
        self.cmd.take_action(parsed_args)

    def test_configure_specified_nodes(self, mock_conn,
                                       mock_connect, mock_conf,
                                       mock_bm):
        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm
        argslist = ['node_uuid1', 'node_uuid2']
        verifylist = [('node_uuids', ['node_uuid1', 'node_uuid2'])]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    def test_configure_no_node_or_flag_specified(self, mock_conn,
                                                 mock_connect, mock_conf,
                                                 mock_bm):
        self.assertRaises(test_utils.ParserException,
                          self.check_parser,
                          self.cmd, [], [])

    def test_configure_uuids_and_all_both_specified(self, mock_conn,
                                                    mock_connect, mock_conf,
                                                    mock_bm):
        argslist = ['node_id1', 'node_id2', '--all-manageable']
        verifylist = [('node_uuids', ['node_id1', 'node_id2']),
                      ('all_manageable', True)]
        self.assertRaises(test_utils.ParserException,
                          self.check_parser,
                          self.cmd, argslist, verifylist)

    def test_configure_kernel_and_ram(self, mock_conn,
                                      mock_connect, mock_conf,
                                      mock_bm):
        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm
        mock_bm.baremetal_introspection = mock_bm

        introspector_client = mock_bm.baremetal_introspection
        introspector_client.get_introspection_data = mock_bm
        introspector_client.get_introspection_data.return_value = {
            'inventory': {'disks': self.disks}
        }

        mock_bm.baremetal.nodes.side_effect = [
            iter([self.fake_baremetal_node]),
            iter([self.fake_baremetal_node])]

        argslist = ['--all-manageable', '--deploy-ramdisk', 'test_ramdisk',
                    '--deploy-kernel', 'test_kernel']
        verifylist = [('deploy_kernel', 'test_kernel'),
                      ('deploy_ramdisk', 'test_ramdisk')]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    def test_configure_instance_boot_option(self, mock_conn,
                                            mock_connect, mock_conf,
                                            mock_bm):
        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm
        mock_bm.baremetal.nodes.side_effect = [
            iter([self.fake_baremetal_node]),
            iter([self.fake_baremetal_node])]
        argslist = ['--all-manageable', '--instance-boot-option', 'netboot']
        verifylist = [('instance_boot_option', 'netboot')]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    def test_configure_root_device(self, mock_conn,
                                   mock_connect, mock_conf,
                                   mock_bm):
        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm
        mock_bm.baremetal_introspection = mock_bm

        introspector_client = mock_bm.baremetal_introspection
        introspector_client.get_introspection_data = mock_bm
        introspector_client.get_introspection_data.return_value = {
            'inventory': {'disks': self.disks}
        }
        mock_bm.baremetal.nodes.side_effect = [
            iter([self.fake_baremetal_node]),
            iter([self.fake_baremetal_node])]
        argslist = ['--all-manageable',
                    '--root-device', 'smallest',
                    '--root-device-minimum-size', '2',
                    '--overwrite-root-device-hints']
        verifylist = [('root_device', 'smallest'),
                      ('root_device_minimum_size', 2),
                      ('overwrite_root_device_hints', True)]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    @mock.patch('tripleoclient.workflows.baremetal.'
                '_apply_root_device_strategy')
    def test_configure_specified_node_with_all_arguments(
            self, mock_root_device, mock_conn,
            mock_connect, mock_conf,
            mock_bm):
        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm
        mock_bm.baremetal_introspection = mock_bm

        introspector_client = mock_bm.baremetal_introspection
        introspector_client.get_introspection_data = mock_bm
        introspector_client.get_introspection_data.return_value = {
            'inventory': {'disks': self.disks}
        }

        mock_bm.baremetal.nodes.side_effect = [
            iter([self.fake_baremetal_node]),
            iter([self.fake_baremetal_node])]

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


@mock.patch.object(openstack.baremetal.v1._proxy, 'Proxy', autospec=True,
                   name="mock_bm")
@mock.patch('openstack.config', autospec=True, name='mock_conf')
@mock.patch('openstack.connect', autospec=True, name='mock_connect')
@mock.patch.object(openstack.connection, 'Connection', autospec=True)
@mock.patch('tripleo_common.utils.nodes._populate_node_mapping',
            name='mock_nodemap')
@mock.patch('tripleo_common.utils.nodes.register_all_nodes',
            name='mock_tcnode')
@mock.patch('oslo_concurrency.processutils.execute',
            name="mock_subproc")
class TestDiscoverNode(fakes.TestOvercloudNode):

    def setUp(self):
        super(TestDiscoverNode, self).setUp()

        self.cmd = overcloud_node.DiscoverNode(self.app, None)

        self.gcn = mock.patch(
            'tripleoclient.workflows.baremetal._get_candidate_nodes',
            autospec=True
        )
        self.gcn.start()
        self.addCleanup(self.gcn.stop)

        self.http_boot = '/var/lib/ironic/httpboot'
        self.fake_baremetal_node = fakes.make_fake_machine(
            machine_name='node1',
            machine_id='4e540e11-1366-4b57-85d5-319d168d98a1'
        )
        self.fake_baremetal_node2 = fakes.make_fake_machine(
            machine_name='node2',
            machine_id='9070e42d-1ad7-4bd0-b868-5418bc9c7176'
        )

    def test_with_ip_range(self, mock_subproc, mock_tcnode,
                           mock_nodemap, mock_conn,
                           mock_connect, mock_conf,
                           mock_bm):
        argslist = ['--range', '10.0.0.0/24',
                    '--credentials', 'admin:password']
        verifylist = [('ip_addresses', '10.0.0.0/24'),
                      ('credentials', ['admin:password'])]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    def test_with_address_list(self, mock_subproc, mock_tcnode,
                               mock_nodemap, mock_conn,
                               mock_connect, mock_conf,
                               mock_bm):
        argslist = ['--ip', '10.0.0.1', '--ip', '10.0.0.2',
                    '--credentials', 'admin:password']
        verifylist = [('ip_addresses', ['10.0.0.1', '10.0.0.2']),
                      ('credentials', ['admin:password'])]

        parsed_args = self.check_parser(self.cmd, argslist, verifylist)
        self.cmd.take_action(parsed_args)

    def test_with_all_options(self, mock_subproc, mock_tcnode,
                              mock_nodemap, mock_conn,
                              mock_connect, mock_conf,
                              mock_bm):
        mock_conn.return_value = mock_bm
        mock_bm.baremetal = mock_bm
        mock_bm.baremetal.get_node.side_effect = [
            self.fake_baremetal_node,
            self.fake_baremetal_node2,
            self.fake_baremetal_node,
            self.fake_baremetal_node2
        ]
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

        self.network = mock.Mock()
        self.app.client_manager.network = self.network

        self.cmd = overcloud_node.ExtractProvisionedNode(self.app, None)

        roles_data = [
            {'name': 'Controller',
             'default_route_networks': ['External'],
             'networks_skip_config': ['Tenant']},
            {'name': 'Compute'}
        ]

        self.stack_dict = {
            'parameters': {
                'ComputeHostnameFormat': '%stackname%-novacompute-%index%',
                'ControllerHostnameFormat': '%stackname%-controller-%index%',
                'ControllerNetworkConfigTemplate': 'templates/controller.j2'
            },
            'outputs': [{
                'output_key': 'TripleoHeatTemplatesJinja2RenderingDataSources',
                'output_value': {
                    'roles_data': roles_data,
                    'networks_data': {}
                }
            }, {
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
            }, {
                'output_key': 'RoleNetIpMap',
                'output_value': {
                    'Compute': {
                        'ctlplane': ['192.168.26.11'],
                        'internal_api': ['172.17.1.23'],
                    },
                    'Controller': {
                        'ctlplane': ['192.168.25.21',
                                     '192.168.25.25',
                                     '192.168.25.28'],
                        'external': ['10.0.0.199',
                                     '10.0.0.197',
                                     '10.0.0.191'],
                        'internal_api': ['172.17.0.37',
                                         '172.17.0.33',
                                         '172.17.0.39'],
                    }
                }
            }]
        }

        self.nodes = [
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
            mock.Mock()
        ]
        self.nodes[0].name = 'bm-0'
        self.nodes[0].id = 'bm-0-uuid'
        self.nodes[0].resource_class = 'controller'
        self.nodes[1].name = 'bm-1'
        self.nodes[1].id = 'bm-1-uuid'
        self.nodes[1].resource_class = 'controller'
        self.nodes[2].name = 'bm-2'
        self.nodes[2].id = 'bm-2-uuid'
        self.nodes[2].resource_class = None
        self.nodes[3].name = 'bm-3'
        self.nodes[3].id = 'bm-3-uuid'
        self.nodes[3].resource_class = 'compute'

        self.nodes[0].instance_info = {
            'display_name': 'overcloud-controller-0'}
        self.nodes[1].instance_info = {
            'display_name': 'overcloud-controller-1'}
        self.nodes[2].instance_info = {
            'display_name': 'overcloud-controller-2'}
        self.nodes[3].instance_info = {
            'display_name': 'overcloud-novacompute-0'}

        self.networks = [
            mock.Mock(),  # ctlplane
            mock.Mock(),  # external
            mock.Mock(),  # internal_api
        ]
        self.ctlplane_net = self.networks[0]
        self.external_net = self.networks[1]
        self.internal_api_net = self.networks[2]

        self.ctlplane_net.id = 'ctlplane_id'
        self.ctlplane_net.name = 'ctlplane'
        self.ctlplane_net.subnet_ids = ['ctlplane_a_id',
                                        'ctlplane_b_id']
        self.external_net.id = 'external_id'
        self.external_net.name = 'external'
        self.external_net.subnet_ids = ['external_a_id']
        self.internal_api_net.id = 'internal_api_id'
        self.internal_api_net.name = 'internal_api'
        self.internal_api_net.subnet_ids = ['internal_api_a_id',
                                            'internal_api_b_id']

        self.subnets = [
            mock.Mock(),  # ctlplane_a
            mock.Mock(),  # ctlplane_b
            mock.Mock(),  # external_a
            mock.Mock(),  # internal_api_a
            mock.Mock(),  # internal_api_b
        ]
        self.ctlplane_a = self.subnets[0]
        self.ctlplane_b = self.subnets[1]
        self.external_a = self.subnets[2]
        self.int_api_a = self.subnets[3]
        self.int_api_b = self.subnets[4]

        self.ctlplane_a.id = 'ctlplane_a_id'
        self.ctlplane_a.name = 'ctlplane_a'
        self.ctlplane_a.cidr = '192.168.25.0/24'
        self.ctlplane_b.id = 'ctlplane_b_id'
        self.ctlplane_b.name = 'ctlplane_b'
        self.ctlplane_b.cidr = '192.168.26.0/24'

        self.external_a.id = 'external_a_id'
        self.external_a.name = 'external_a'
        self.external_a.cidr = '10.0.0.0/24'

        self.int_api_a.id = 'internal_api_a_id'
        self.int_api_a.name = 'internal_api_a'
        self.int_api_a.cidr = '172.17.0.0/24'
        self.int_api_b.id = 'internal_api_b_id'
        self.int_api_b.name = 'internal_api_b'
        self.int_api_b.cidr = '172.17.1.0/24'

        self.network.find_network.side_effect = [
            # compute-0
            self.ctlplane_net, self.internal_api_net,
            # controller-0
            self.ctlplane_net, self.external_net, self.internal_api_net,
            # controller-1
            self.ctlplane_net, self.external_net, self.internal_api_net,
            # controller-2
            self.ctlplane_net, self.external_net, self.internal_api_net,
        ]
        self.network.get_subnet.side_effect = [
            # compute-0
            self.ctlplane_a, self.ctlplane_b, self.int_api_a, self.int_api_b,
            # controller-0
            self.ctlplane_a, self.external_a, self.int_api_a,
            # controller-1
            self.ctlplane_a, self.external_a, self.int_api_a,
            # controller-2
            self.ctlplane_a, self.external_a, self.int_api_a,
        ]

        self.extract_file = tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.yaml')
        self.extract_file.close()

        self.roles_file = tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.yaml')
        self.roles_file.write(yaml.safe_dump(roles_data))
        self.roles_file.close()
        self.addCleanup(os.unlink, self.extract_file.name)
        self.addCleanup(os.unlink, self.roles_file.name)

    def test_extract(self):
        stack = mock.Mock()
        stack.to_dict.return_value = self.stack_dict
        stack.environment.return_value = {}
        self.orchestration.stacks.get.return_value = stack

        self.baremetal.node.list.return_value = self.nodes
        argslist = ['--output', self.extract_file.name,
                    '--yes']
        self.app.command_options = argslist
        verifylist = [('output', self.extract_file.name),
                      ('yes', True)]

        parsed_args = self.check_parser(self.cmd,
                                        argslist, verifylist)
        self.cmd.take_action(parsed_args)

        result = self.cmd.app.stdout.make_string()
        self.assertEqual([{
            'name': 'Compute',
            'count': 1,
            'hostname_format': '%stackname%-novacompute-%index%',
            'defaults': {
                'network_config': {'network_config_update': False,
                                   'physical_bridge_name': 'br-ex',
                                   'public_interface_name': 'nic1',
                                   'template': None},
                'networks': [{'network': 'ctlplane',
                              'vif': True},
                             {'network': 'internal_api',
                              'subnet': 'internal_api_b'}]
            },
            'instances': [{
                'hostname': 'overcloud-novacompute-0',
                'name': 'bm-3-uuid',
                'resource_class': 'compute',
            }],
        }, {
            'name': 'Controller',
            'count': 3,
            'hostname_format': '%stackname%-controller-%index%',
            'defaults': {
                'network_config': {'default_route_network': ['External'],
                                   'network_config_update': False,
                                   'networks_skip_config': ['Tenant'],
                                   'physical_bridge_name': 'br-ex',
                                   'public_interface_name': 'nic1',
                                   'template': 'templates/controller.j2'},
                'networks': [{'network': 'ctlplane',
                              'vif': True},
                             {'network': 'external',
                              'subnet': 'external_a'},
                             {'network': 'internal_api',
                              'subnet': 'internal_api_a'}]
            },
            'instances': [{
                'hostname': 'overcloud-controller-0',
                'name': 'bm-0-uuid',
                'resource_class': 'controller',
            }, {
                'hostname': 'overcloud-controller-1',
                'name': 'bm-1-uuid',
                'resource_class': 'controller',
            }, {
                'hostname': 'overcloud-controller-2',
                'name': 'bm-2-uuid',
            }],
        }], yaml.safe_load(result))

        with open(self.extract_file.name) as f:
            file_content = f.read()
        self.assertEqual(yaml.safe_load(result), yaml.safe_load(file_content))
        self.assertIn('# WARNING: No network config found for role Compute. '
                      'Please edit the file and set the path to the correct '
                      'network config template.\n', file_content)

    def test_extract_ips_from_pool(self):
        stack = mock.Mock()
        stack.to_dict.return_value = self.stack_dict
        stack.environment.return_value = {
            'parameter_defaults': {
                'ComputeIPs':
                    self.stack_dict['outputs'][1]['output_value']['Compute'],
                'ControllerIPs':
                    self.stack_dict['outputs'][1]['output_value']['Controller']
            }
        }
        self.orchestration.stacks.get.return_value = stack

        self.baremetal.node.list.return_value = self.nodes
        argslist = ['--roles-file', self.roles_file.name,
                    '--output', self.extract_file.name,
                    '--yes']
        self.app.command_options = argslist
        verifylist = [('roles_file', self.roles_file.name),
                      ('output', self.extract_file.name),
                      ('yes', True)]

        parsed_args = self.check_parser(self.cmd,
                                        argslist, verifylist)
        self.cmd.take_action(parsed_args)

        result = self.cmd.app.stdout.make_string()
        self.assertEqual([{
            'name': 'Compute',
            'count': 1,
            'hostname_format': '%stackname%-novacompute-%index%',
            'defaults': {
                'network_config': {'network_config_update': False,
                                   'physical_bridge_name': 'br-ex',
                                   'public_interface_name': 'nic1',
                                   'template': None},
                'networks': [{'network': 'ctlplane',
                              'vif': True},
                             {'network': 'internal_api',
                              'subnet': 'internal_api_b'}]
            },
            'instances': [{
                'hostname': 'overcloud-novacompute-0',
                'name': 'bm-3-uuid',
                'resource_class': 'compute',
                'networks': [{'fixed_ip': '192.168.26.11',
                              'network': 'ctlplane',
                              'vif': True},
                             {'fixed_ip': '172.17.1.23',
                              'network': 'internal_api',
                              'subnet': 'internal_api_b'}],
            }],
        }, {
            'name': 'Controller',
            'count': 3,
            'hostname_format': '%stackname%-controller-%index%',
            'defaults': {
                'network_config': {'default_route_network': ['External'],
                                   'network_config_update': False,
                                   'networks_skip_config': ['Tenant'],
                                   'physical_bridge_name': 'br-ex',
                                   'public_interface_name': 'nic1',
                                   'template': 'templates/controller.j2'},
                'networks': [{'network': 'ctlplane',
                              'vif': True},
                             {'network': 'external',
                              'subnet': 'external_a'},
                             {'network': 'internal_api',
                              'subnet': 'internal_api_a'}],
            },
            'instances': [{
                'hostname': 'overcloud-controller-0',
                'name': 'bm-0-uuid',
                'resource_class': 'controller',
                'networks': [{'fixed_ip': '192.168.25.21',
                              'network': 'ctlplane',
                              'vif': True},
                             {'fixed_ip': '10.0.0.199',
                              'network': 'external',
                              'subnet': 'external_a'},
                             {'fixed_ip': '172.17.0.37',
                              'network': 'internal_api',
                              'subnet': 'internal_api_a'}],
            }, {
                'hostname': 'overcloud-controller-1',
                'name': 'bm-1-uuid',
                'resource_class': 'controller',
                'networks': [{'fixed_ip': '192.168.25.25',
                              'network': 'ctlplane',
                              'vif': True},
                             {'fixed_ip': '10.0.0.197',
                              'network': 'external',
                              'subnet': 'external_a'},
                             {'fixed_ip': '172.17.0.33',
                              'network': 'internal_api',
                              'subnet': 'internal_api_a'}],
            }, {
                'hostname': 'overcloud-controller-2',
                'name': 'bm-2-uuid',
                'networks': [{'fixed_ip': '192.168.25.28',
                              'network': 'ctlplane',
                              'vif': True},
                             {'fixed_ip': '10.0.0.191',
                              'network': 'external',
                              'subnet': 'external_a'},
                             {'fixed_ip': '172.17.0.39',
                              'network': 'internal_api',
                              'subnet': 'internal_api_a'}],
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

        argslist = ['--roles-file', self.roles_file.name]
        self.app.command_options = argslist
        verifylist = [('roles_file', self.roles_file.name)]

        parsed_args = self.check_parser(self.cmd,
                                        argslist, verifylist)
        self.cmd.take_action(parsed_args)
        result = self.cmd.app.stdout.make_string()
        self.assertIsNone(yaml.safe_load(result))
