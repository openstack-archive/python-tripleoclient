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

import json
import mock
import os

from jinja2 import Template

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture

from tripleoclient.tests.v1.test_plugin import TestPluginV1

# Load the plugin init module for the plugin list and show commands
from tripleoclient.v1 import undercloud


class FakePluginV1Client(object):
    def __init__(self, **kwargs):
        self.auth_token = kwargs['token']
        self.management_url = kwargs['endpoint']


class TestUndercloudInstall(TestPluginV1):

    def setUp(self):
        super(TestUndercloudInstall, self).setUp()

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        self.conf.config(container_images_file='/home/stack/foo.yaml')
        self.conf.set_default('output_dir', '/home/stack')
        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = undercloud.InstallUndercloud(self.app, app_args)

    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('six.moves.builtins.open')
    @mock.patch('shutil.copy')
    @mock.patch('os.mkdir')
    @mock.patch('tripleoclient.utils.write_env_file', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_install_default(self, mock_subprocess,
                                        mock_wr,
                                        mock_os, mock_copy,
                                        mock_open, mock_user):
        arglist = ['--no-validations']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        self.cmd.take_action(parsed_args)

        mock_subprocess.assert_called_with(
            ['sudo', 'openstack', 'tripleo', 'deploy', '--standalone',
             '--standalone-role', 'Undercloud', '--stack', 'undercloud',
             '--local-domain=localdomain',
             '--local-ip=192.168.24.1/24',
             '--templates=/usr/share/openstack-tripleo-heat-templates/',
             '--heat-native', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'docker.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'undercloud.yaml', '-e', '/home/stack/foo.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic.yaml',
             '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic-inspector.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/mistral.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/zaqar.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tripleo-ui.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tempest.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'public-tls-undercloud.yaml',
             '--public-virtual-ip', '192.168.24.2',
             '--control-virtual-ip', '192.168.24.3', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'ssl/tls-endpoints-public-ip.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'use-dns-for-vips.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-haproxy.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-keepalived.yaml',
             # TODO(cjeanner) drop once we have proper oslo.privsep
             '--deployment-user', 'stack',
             '--output-dir=/home/stack', '--cleanup',
             '-e', '/home/stack/tripleo-config-generated-env-files/'
             'undercloud_parameters.yaml',
             '--log-file=install-undercloud.log', '-e',
             '/usr/share/openstack-tripleo-heat-templates/'
             'undercloud-stack-vstate-dropin.yaml'])

    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_install_with_heat_disabled(self, mock_subprocess):
        arglist = ['--use-heat=False']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        self.cmd.take_action(parsed_args)

        mock_subprocess.assert_called_with(['instack-install-undercloud'])

    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('shutil.copy')
    @mock.patch('os.mkdir')
    @mock.patch('tripleoclient.utils.write_env_file', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_install_with_heat_customized(self, mock_subprocess,
                                                     mock_wr, mock_os,
                                                     mock_copy, mock_user):
        self.conf.config(output_dir='/foo')
        self.conf.config(templates='/usertht')
        self.conf.config(roles_file='foo/roles.yaml')
        arglist = ['--use-heat', '--no-validations', '--force-stack-update']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        self.cmd.take_action(parsed_args)

        mock_os.assert_has_calls(
            [
                mock.call('/foo/tripleo-config-generated-env-files'),
                mock.call('/foo')
            ])
        mock_subprocess.assert_called_with(
            ['sudo', 'openstack', 'tripleo', 'deploy', '--standalone',
             '--standalone-role', 'Undercloud', '--stack', 'undercloud',
             '--local-domain=localdomain',
             '--local-ip=192.168.24.1/24',
             '--templates=/usertht',
             '--roles-file=foo/roles.yaml',
             '--heat-native', '-e',
             '/usertht/environments/docker.yaml', '-e',
             '/usertht/environments/undercloud.yaml', '-e',
             '/home/stack/foo.yaml', '-e',
             '/usertht/environments/services/ironic.yaml', '-e',
             '/usertht/environments/services/ironic-inspector.yaml', '-e',
             '/usertht/environments/services/mistral.yaml', '-e',
             '/usertht/environments/services/zaqar.yaml', '-e',
             '/usertht/environments/services/tripleo-ui.yaml', '-e',
             '/usertht/environments/services/tempest.yaml', '-e',
             '/usertht/environments/public-tls-undercloud.yaml',
             '--public-virtual-ip', '192.168.24.2',
             '--control-virtual-ip', '192.168.24.3', '-e',
             '/usertht/environments/ssl/tls-endpoints-public-ip.yaml', '-e',
             '/usertht/environments/use-dns-for-vips.yaml', '-e',
             '/usertht/environments/services/undercloud-haproxy.yaml', '-e',
             '/usertht/environments/services/undercloud-keepalived.yaml',
             # TODO(cjeanner) drop once we have proper oslo.privsep
             '--deployment-user', 'stack',
             '--output-dir=/foo', '--cleanup', '-e',
             '/foo/tripleo-config-generated-env-files/'
             'undercloud_parameters.yaml',
             '--log-file=install-undercloud.log', '-e',
             '/usertht/undercloud-stack-vstate-dropin.yaml',
             '--force-stack-update'])

    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('shutil.copy')
    @mock.patch('os.mkdir')
    @mock.patch('tripleoclient.utils.write_env_file', autospec=True)
    @mock.patch('tripleoclient.v1.undercloud_config.'
                '_generate_masquerade_networks', autospec=True)
    @mock.patch('tripleoclient.v1.undercloud_config.'
                '_generate_subnets_static_routes', autospec=True)
    @mock.patch('tripleoclient.v1.undercloud_config.'
                '_get_jinja_env_source', autospec=True)
    @mock.patch('tripleoclient.v1.undercloud_config.'
                '_get_unknown_instack_tags', return_value=None, autospec=True)
    @mock.patch('jinja2.meta.find_undeclared_variables', return_value={},
                autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_install_with_heat_net_conf_over(self, mock_subprocess,
                                                        mock_j2_meta,
                                                        mock_get_unknown_tags,
                                                        mock_get_j2,
                                                        mock_sroutes,
                                                        mock_masq,
                                                        mock_wr, mock_os,
                                                        mock_copy, mock_user):
        self.conf.config(net_config_override='/foo/net-config.json')
        self.conf.config(local_interface='ethX')
        self.conf.config(undercloud_public_host='4.3.2.1')
        self.conf.config(local_mtu='1234')
        self.conf.config(undercloud_nameservers=['8.8.8.8', '8.8.4.4'])
        self.conf.config(subnets='foo')
        mock_masq.return_value = {'1.1.1.1/11': ['2.2.2.2/22']}
        mock_sroutes.return_value = {'ip_netmask': '1.1.1.1/11',
                                     'next_hop': '1.1.1.1'}
        instack_net_conf = """
        "network_config": [
         {
          "type": "ovs_bridge",
          "name": "br-ctlplane",
          "ovs_extra": [
           "br-set-external-id br-ctlplane bridge-id br-ctlplane"
          ],
          "members": [
           {
            "type": "interface",
            "name": "{{LOCAL_INTERFACE}}",
            "primary": "true",
            "mtu": {{LOCAL_MTU}},
            "dns_servers": {{UNDERCLOUD_NAMESERVERS}}
           }
          ],
          "addresses": [
            {
              "ip_netmask": "{{PUBLIC_INTERFACE_IP}}"
            }
          ],
          "routes": {{SUBNETS_STATIC_ROUTES}},
          "mtu": {{LOCAL_MTU}}
        }
        ]
        """
        expected_net_conf = json.loads(
            """
            {"network_config": [
             {
              "type": "ovs_bridge",
              "name": "br-ctlplane",
              "ovs_extra": [
               "br-set-external-id br-ctlplane bridge-id br-ctlplane"
              ],
              "members": [
               {
                "type": "interface",
                "name": "ethX",
                "primary": "true",
                "mtu": 1234,
                "dns_servers": ["8.8.8.8", "8.8.4.4"]
               }
              ],
              "addresses": [
                {
                  "ip_netmask": "4.3.2.1"
                }
              ],
              "routes": {"next_hop": "1.1.1.1", "ip_netmask": "1.1.1.1/11"},
              "mtu": 1234
            }
            ]}
            """
        )
        env = mock.Mock()
        env.get_template = mock.Mock(return_value=Template(instack_net_conf))
        mock_get_j2.return_value = (env, None)
        arglist = ['--use-heat', '--no-validations']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        os_orig = os.path.exists
        with mock.patch('os.path.exists') as mock_exists:

            def fcheck(*args, **kwargs):
                if '/foo/net-config.json' in args:
                    return True
                return os_orig(*args, **kwargs)

            mock_exists.side_effect = fcheck
            self.cmd.take_action(parsed_args)

        # unpack the write env file call to verify if the produced net config
        # override JSON matches our expectations
        found_net_conf_override = False
        for call in mock_wr.call_args_list:
            args, kwargs = call
            for a in args:
                if 'UndercloudNetConfigOverride' in a:
                    found_net_conf_override = True
                    self.assertTrue(
                        a['UndercloudNetConfigOverride'] == expected_net_conf)
        self.assertTrue(found_net_conf_override)

        mock_subprocess.assert_called_with(
            ['sudo', 'openstack', 'tripleo', 'deploy', '--standalone',
             '--standalone-role', 'Undercloud', '--stack', 'undercloud',
             '--local-domain=localdomain',
             '--local-ip=192.168.24.1/24',
             '--templates=/usr/share/openstack-tripleo-heat-templates/',
             '--heat-native', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'docker.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'undercloud.yaml', '-e', '/home/stack/foo.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/'
             'environments/services/masquerade-networks.yaml',
             '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic.yaml',
             '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic-inspector.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/mistral.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/zaqar.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tripleo-ui.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tempest.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'public-tls-undercloud.yaml',
             '--public-virtual-ip', '4.3.2.1',
             '--control-virtual-ip', '192.168.24.3', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'ssl/tls-endpoints-public-ip.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'use-dns-for-vips.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-haproxy.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-keepalived.yaml',
             # TODO(cjeanner) drop once we have proper oslo.privsep
             '--deployment-user', 'stack',
             '--output-dir=/home/stack',
             '--cleanup', '-e',
             '/home/stack/tripleo-config-generated-env-files/'
             'undercloud_parameters.yaml',
             '--log-file=install-undercloud.log', '-e',
             '/usr/share/openstack-tripleo-heat-templates/'
             'undercloud-stack-vstate-dropin.yaml'])

    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('six.moves.builtins.open')
    @mock.patch('shutil.copy')
    @mock.patch('os.mkdir')
    @mock.patch('tripleoclient.utils.write_env_file', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_install_with_heat_and_debug(self, mock_subprocess,
                                                    mock_wr,
                                                    mock_os, mock_copy,
                                                    mock_open, mock_user):
        self.conf.config(undercloud_log_file='/foo/bar')
        arglist = ['--use-heat', '--no-validations']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        old_verbose = self.cmd.app_args.verbose_level
        self.cmd.app_args.verbose_level = 2
        self.cmd.take_action(parsed_args)
        self.cmd.app_args.verbose_level = old_verbose

        mock_subprocess.assert_called_with(
            ['sudo', 'openstack', 'tripleo', 'deploy', '--standalone',
             '--standalone-role', 'Undercloud', '--stack', 'undercloud',
             '--local-domain=localdomain',
             '--local-ip=192.168.24.1/24',
             '--templates=/usr/share/openstack-tripleo-heat-templates/',
             '--heat-native', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'docker.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'undercloud.yaml', '-e', '/home/stack/foo.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic.yaml',
             '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic-inspector.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/mistral.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/zaqar.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tripleo-ui.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tempest.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'public-tls-undercloud.yaml',
             '--public-virtual-ip', '192.168.24.2',
             '--control-virtual-ip', '192.168.24.3', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'ssl/tls-endpoints-public-ip.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'use-dns-for-vips.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-haproxy.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-keepalived.yaml',
             # TODO(cjeanner) drop once we have proper oslo.privsep
             '--deployment-user', 'stack',
             '--output-dir=/home/stack', '--cleanup',
             '-e', '/home/stack/tripleo-config-generated-env-files/'
             'undercloud_parameters.yaml',
             '--debug', '--log-file=/foo/bar', '-e',
             '/usr/share/openstack-tripleo-heat-templates/'
             'undercloud-stack-vstate-dropin.yaml'])

    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('six.moves.builtins.open')
    @mock.patch('shutil.copy')
    @mock.patch('os.mkdir')
    @mock.patch('tripleoclient.utils.write_env_file', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_install_with_heat_true(self, mock_subprocess,
                                               mock_wr,
                                               mock_os, mock_copy,
                                               mock_open, mock_user):
        self.conf.config(undercloud_log_file='/foo/bar')
        arglist = ['--use-heat=True', '--no-validations']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        self.cmd.take_action(parsed_args)

        mock_subprocess.assert_called_with(
            ['sudo', 'openstack', 'tripleo', 'deploy', '--standalone',
             '--standalone-role', 'Undercloud', '--stack', 'undercloud',
             '--local-domain=localdomain',
             '--local-ip=192.168.24.1/24',
             '--templates=/usr/share/openstack-tripleo-heat-templates/',
             '--heat-native', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'docker.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'undercloud.yaml', '-e', '/home/stack/foo.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic.yaml',
             '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic-inspector.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/mistral.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/zaqar.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tripleo-ui.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tempest.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'public-tls-undercloud.yaml',
             '--public-virtual-ip', '192.168.24.2',
             '--control-virtual-ip', '192.168.24.3', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'ssl/tls-endpoints-public-ip.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'use-dns-for-vips.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-haproxy.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-keepalived.yaml',
             # TODO(cjeanner) drop once we have proper oslo.privsep
             '--deployment-user', 'stack',
             '--output-dir=/home/stack', '--cleanup',
             '-e', '/home/stack/tripleo-config-generated-env-files/'
             'undercloud_parameters.yaml', '--log-file=/foo/bar', '-e',
             '/usr/share/openstack-tripleo-heat-templates/'
             'undercloud-stack-vstate-dropin.yaml'])

    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('shutil.copy')
    @mock.patch('os.mkdir')
    @mock.patch('tripleoclient.utils.write_env_file', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_install_with_swift_encryption(self, mock_subprocess,
                                                      mock_wr, mock_os,
                                                      mock_copy, mock_user):
        arglist = ['--use-heat', '--no-validations']
        verifylist = []
        self.conf.set_default('enable_swift_encryption', True)
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        self.cmd.take_action(parsed_args)

        mock_subprocess.assert_called_with(
            ['sudo', 'openstack', 'tripleo', 'deploy', '--standalone',
             '--standalone-role', 'Undercloud', '--stack', 'undercloud',
             '--local-domain=localdomain',
             '--local-ip=192.168.24.1/24',
             '--templates=/usr/share/openstack-tripleo-heat-templates/',
             '--heat-native', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'docker.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'undercloud.yaml', '-e', '/home/stack/foo.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic.yaml',
             '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic-inspector.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/mistral.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/zaqar.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tripleo-ui.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tempest.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/barbican.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'barbican-backend-simple-crypto.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'public-tls-undercloud.yaml',
             '--public-virtual-ip', '192.168.24.2',
             '--control-virtual-ip', '192.168.24.3', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'ssl/tls-endpoints-public-ip.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'use-dns-for-vips.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-haproxy.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-keepalived.yaml',
             '--deployment-user', 'stack',
             '--output-dir=/home/stack', '--cleanup',
             '-e', '/home/stack/tripleo-config-generated-env-files/'
             'undercloud_parameters.yaml',
             '--log-file=install-undercloud.log', '-e',
             '/usr/share/openstack-tripleo-heat-templates/'
             'undercloud-stack-vstate-dropin.yaml'])


class TestUndercloudUpgrade(TestPluginV1):
    def setUp(self):
        super(TestUndercloudUpgrade, self).setUp()

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        self.conf.config(container_images_file='/home/stack/foo.yaml')
        self.conf.set_default('output_dir', '/home/stack')
        # Get the command object to test
        app_args = mock.Mock()
        app_args.verbose_level = 1
        self.cmd = undercloud.UpgradeUndercloud(self.app, app_args)

    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('shutil.copy')
    @mock.patch('os.mkdir')
    @mock.patch('tripleoclient.utils.write_env_file', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_upgrade_default(self, mock_subprocess,
                                        mock_wr,
                                        mock_os, mock_copy, mock_user):
        arglist = ['--no-validations']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        self.cmd.take_action(parsed_args)

        mock_subprocess.assert_called_with(
            ['sudo', 'openstack', 'tripleo', 'deploy', '--standalone',
             '--standalone-role', 'Undercloud', '--stack', 'undercloud',
             '--local-domain=localdomain',
             '--local-ip=192.168.24.1/24',
             '--templates=/usr/share/openstack-tripleo-heat-templates/',
             '--upgrade', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'lifecycle/undercloud-upgrade-prepare.yaml',
             '--heat-native', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'docker.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'undercloud.yaml', '-e', '/home/stack/foo.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic.yaml',
             '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic-inspector.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/mistral.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/zaqar.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tripleo-ui.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tempest.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'public-tls-undercloud.yaml',
             '--public-virtual-ip', '192.168.24.2',
             '--control-virtual-ip', '192.168.24.3', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'ssl/tls-endpoints-public-ip.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'use-dns-for-vips.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-haproxy.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-keepalived.yaml',
             # TODO(cjeanner) drop once we have proper oslo.privsep
             '--deployment-user', 'stack',
             '--output-dir=/home/stack', '--cleanup',
             '-e', '/home/stack/tripleo-config-generated-env-files/'
             'undercloud_parameters.yaml',
             '--log-file=install-undercloud.log', '-e',
             '/usr/share/openstack-tripleo-heat-templates/'
             'undercloud-stack-vstate-dropin.yaml'])

    @mock.patch('os.mkdir')
    @mock.patch('tripleoclient.utils.write_env_file', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_upgrade_with_heat_disabled(self, mock_subprocess,
                                                   mock_wr, mock_os):
        arglist = ['--use-heat=False']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        self.cmd.take_action(parsed_args)

        mock_subprocess.assert_has_calls(
            [
                mock.call(['sudo', 'yum', 'update', '-y',
                           'instack-undercloud']),
                mock.call('instack-pre-upgrade-undercloud'),
                mock.call('instack-upgrade-undercloud'),
                mock.call(['sudo', 'systemctl', 'restart',
                          'openstack-nova-api'])
            ]
        )

    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('shutil.copy')
    @mock.patch('os.mkdir')
    @mock.patch('tripleoclient.utils.write_env_file', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_upgrade_with_heat_enabled(self, mock_subprocess,
                                                  mock_wr, mock_os,
                                                  mock_copy, mock_user):
        arglist = ['--use-heat', '--no-validations']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        self.cmd.take_action(parsed_args)

        mock_subprocess.assert_called_with(
            ['sudo', 'openstack', 'tripleo', 'deploy', '--standalone',
             '--standalone-role', 'Undercloud', '--stack', 'undercloud',
             '--local-domain=localdomain',
             '--local-ip=192.168.24.1/24',
             '--templates=/usr/share/openstack-tripleo-heat-templates/',
             '--upgrade', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'lifecycle/undercloud-upgrade-prepare.yaml',
             '--heat-native', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'docker.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'undercloud.yaml', '-e', '/home/stack/foo.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic.yaml',
             '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic-inspector.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/mistral.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/zaqar.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tripleo-ui.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tempest.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'public-tls-undercloud.yaml',
             '--public-virtual-ip', '192.168.24.2',
             '--control-virtual-ip', '192.168.24.3', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'ssl/tls-endpoints-public-ip.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'use-dns-for-vips.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-haproxy.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-keepalived.yaml',
             '--deployment-user', 'stack',
             '--output-dir=/home/stack', '--cleanup',
             '-e', '/home/stack/tripleo-config-generated-env-files/'
             'undercloud_parameters.yaml',
             '--log-file=install-undercloud.log', '-e',
             '/usr/share/openstack-tripleo-heat-templates/'
             'undercloud-stack-vstate-dropin.yaml'])

    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('shutil.copy')
    @mock.patch('os.mkdir')
    @mock.patch('tripleoclient.utils.write_env_file', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_upgrade_with_heat_true(self, mock_subprocess,
                                               mock_wr, mock_os,
                                               mock_copy, mock_user):
        arglist = ['--use-heat=True', '--no-validations']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        self.cmd.take_action(parsed_args)

        mock_subprocess.assert_called_with(
            ['sudo', 'openstack', 'tripleo', 'deploy', '--standalone',
             '--standalone-role', 'Undercloud', '--stack', 'undercloud',
             '--local-domain=localdomain',
             '--local-ip=192.168.24.1/24',
             '--templates=/usr/share/openstack-tripleo-heat-templates/',
             '--upgrade', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'lifecycle/undercloud-upgrade-prepare.yaml',
             '--heat-native', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'docker.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'undercloud.yaml', '-e', '/home/stack/foo.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic.yaml',
             '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic-inspector.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/mistral.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/zaqar.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tripleo-ui.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tempest.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'public-tls-undercloud.yaml',
             '--public-virtual-ip', '192.168.24.2',
             '--control-virtual-ip', '192.168.24.3', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'ssl/tls-endpoints-public-ip.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'use-dns-for-vips.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-haproxy.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-keepalived.yaml',
             # TODO(cjeanner) drop once we have proper oslo.privsep
             '--deployment-user', 'stack',
             '--output-dir=/home/stack', '--cleanup',
             '-e', '/home/stack/tripleo-config-generated-env-files/'
             'undercloud_parameters.yaml',
             '--log-file=install-undercloud.log', '-e',
             '/usr/share/openstack-tripleo-heat-templates/'
             'undercloud-stack-vstate-dropin.yaml'])

    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('shutil.copy')
    @mock.patch('os.mkdir')
    @mock.patch('tripleoclient.utils.write_env_file', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_upgrade_with_heat_and_yes(self, mock_subprocess,
                                                  mock_wr, mock_os,
                                                  mock_user, mock_copy):
        arglist = ['--use-heat', '--no-validations', '-y']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        self.cmd.take_action(parsed_args)

        mock_subprocess.assert_called_with(
            ['sudo', 'openstack', 'tripleo', 'deploy', '--standalone',
             '--standalone-role', 'Undercloud', '--stack', 'undercloud',
             '--local-domain=localdomain',
             '--local-ip=192.168.24.1/24',
             '--templates=/usr/share/openstack-tripleo-heat-templates/',
             '-y', '--upgrade', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'lifecycle/undercloud-upgrade-prepare.yaml',
             '--heat-native', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'docker.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'undercloud.yaml', '-e', '/home/stack/foo.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic.yaml',
             '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic-inspector.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/mistral.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/zaqar.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tripleo-ui.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tempest.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'public-tls-undercloud.yaml',
             '--public-virtual-ip', '192.168.24.2',
             '--control-virtual-ip', '192.168.24.3', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'ssl/tls-endpoints-public-ip.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'use-dns-for-vips.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-haproxy.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-keepalived.yaml',
             # TODO(cjeanner) drop once we have proper oslo.privsep
             '--deployment-user', 'stack',
             '--output-dir=/home/stack', '--cleanup',
             '-e', '/home/stack/tripleo-config-generated-env-files/'
             'undercloud_parameters.yaml',
             '--log-file=install-undercloud.log', '-e',
             '/usr/share/openstack-tripleo-heat-templates/'
             'undercloud-stack-vstate-dropin.yaml'])

    # TODO(cjeanner) drop once we have proper oslo.privsep
    @mock.patch('getpass.getuser', return_value='stack')
    @mock.patch('shutil.copy')
    @mock.patch('os.mkdir')
    @mock.patch('tripleoclient.utils.write_env_file', autospec=True)
    @mock.patch('subprocess.check_call', autospec=True)
    def test_undercloud_upgrade_with_heat_and_debug(self, mock_subprocess,
                                                    mock_wr, mock_os,
                                                    mock_copy, mock_user):
        arglist = ['--use-heat', '--no-validations']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        # DisplayCommandBase.take_action() returns two tuples
        old_verbose = self.cmd.app_args.verbose_level
        self.cmd.app_args.verbose_level = 2
        self.cmd.take_action(parsed_args)
        self.cmd.app_args.verbose_level = old_verbose

        mock_subprocess.assert_called_with(
            ['sudo', 'openstack', 'tripleo', 'deploy', '--standalone',
             '--standalone-role', 'Undercloud', '--stack', 'undercloud',
             '--local-domain=localdomain',
             '--local-ip=192.168.24.1/24',
             '--templates=/usr/share/openstack-tripleo-heat-templates/',
             '--upgrade', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'lifecycle/undercloud-upgrade-prepare.yaml',
             '--heat-native', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'docker.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'undercloud.yaml', '-e', '/home/stack/foo.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic.yaml',
             '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/ironic-inspector.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/mistral.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/zaqar.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tripleo-ui.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/tempest.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'public-tls-undercloud.yaml',
             '--public-virtual-ip', '192.168.24.2',
             '--control-virtual-ip', '192.168.24.3', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'ssl/tls-endpoints-public-ip.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'use-dns-for-vips.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-haproxy.yaml', '-e',
             '/usr/share/openstack-tripleo-heat-templates/environments/'
             'services/undercloud-keepalived.yaml',
             '--deployment-user', 'stack',
             '--output-dir=/home/stack', '--cleanup',
             '-e', '/home/stack/tripleo-config-generated-env-files/'
             'undercloud_parameters.yaml',
             '--debug', '--log-file=install-undercloud.log', '-e',
             '/usr/share/openstack-tripleo-heat-templates/'
             'undercloud-stack-vstate-dropin.yaml'])
