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

import copy

from osc_lib.i18n import _
from oslo_config import cfg

from tripleoclient import constants

from tripleoclient.config.standalone import StandaloneConfig

CONF = cfg.CONF


class MinionConfig(StandaloneConfig):
    def get_minion_service_opts(self, heat_engine=True,
                                ironic_conductor=False):
        _opts = [
            cfg.BoolOpt('enable_heat_engine',
                        default=heat_engine,
                        help=_(
                            'Whether to install the Heat Engine service.')),
            cfg.BoolOpt('enable_ironic_conductor',
                        default=ironic_conductor,
                        help=_(
                            'Whether to install the Ironic Conductor service. '
                            'This is currently disabled by default.')),
        ]
        return self.sort_opts(_opts)

    def get_base_opts(self):
        _base_opts = super(MinionConfig, self).get_base_opts()
        _opts = [
            cfg.StrOpt('minion_log_file',
                       default=constants.MINION_LOG_FILE,
                       help=_(
                           'The path to a log file to store the '
                           'install/upgrade logs.'),
                       ),
            cfg.StrOpt('minion_hostname',
                       help=_(
                           'Fully qualified hostname (including domain) to '
                           'set on the Undercloud Minion. If left unset, the '
                           'current hostname will be used, but the user is '
                           'responsible for configuring all system hostname '
                           'settings appropriately.  If set, the Undercloud '
                           'Minion install will configure all system hostname '
                           'settings.'),
                       ),
            cfg.StrOpt('minion_local_ip',
                       default='192.168.24.50/24',
                       help=_(
                           'IP information for the interface on the '
                           'Undercloud Minion.  The IP portion '
                           'of the value will be assigned to the network '
                           'interface defined by local_interface, with the '
                           'netmask defined by the prefix portion of the '
                           'value.')
                       ),
            cfg.ListOpt('minion_nameservers',
                        default=[],
                        help=_(
                            'DNS nameserver(s) to configure on the Undercloud '
                            'Minion.')
                        ),
            cfg.ListOpt('minion_ntp_servers',
                        default=['0.pool.ntp.org', '1.pool.ntp.org',
                                 '2.pool.ntp.org', '3.pool.ntp.org'],
                        help=_('List of ntp servers to use.')),
            cfg.StrOpt('minion_timezone', default=None,
                       help=_('Host timezone to be used. If no timezone is '
                              'specified, the existing timezone configuration '
                              'is used.')),
            cfg.StrOpt('minion_service_certificate',
                       default='',
                       help=_(
                           'TODO: '
                           'Certificate file to use for OpenStack service SSL '
                           'connections.  Setting this enables SSL for the '
                           'OpenStack API endpoints, leaving it unset '
                           'disables SSL.')
                       ),
            cfg.StrOpt('minion_password_file',
                       default='tripleo-undercloud-passwords.yaml',
                       help=_(
                           'The name of the file to look for the passwords '
                           'used to connect to the Undercloud. We assume '
                           'this file is in the folder where the command '
                           'is executed if a fully qualified path is not '
                           'provided.')
                       ),
            cfg.StrOpt('minion_undercloud_output_file',
                       default='tripleo-undercloud-outputs.yaml',
                       help=_(
                           'The name of the file to look for the Undercloud '
                           'output file that contains configuration '
                           'information. We assume this file is in the folder '
                           'where the command is executed if a fully '
                           'qualified path is not provided.')
                       ),

            cfg.StrOpt('minion_local_interface',
                       default='eth1',
                       help=_('Network interface on the Undercloud Minion '
                              'that will be used for the services.')
                       ),
            cfg.IntOpt('minion_local_mtu',
                       default=1500,
                       help=_('MTU to use for the local_interface.')
                       ),
            cfg.BoolOpt('minion_debug',
                        default=True,
                        help=_(
                            'Whether to enable the debug log level for '
                            'OpenStack services and Container Image Prepare '
                            'step.')
                        ),
            cfg.BoolOpt('minion_enable_selinux',
                        default=True,
                        help=_('Enable or disable SELinux during the '
                               'deployment.')),
            cfg.BoolOpt('minion_enable_validations',
                        default=True,
                        help=_(
                            'Run pre-flight checks when installing or '
                            'upgrading.')
                        ),

        ]
        return self.sort_opts(_base_opts + _opts)

    def get_opts(self):
        _base_opts = self.get_base_opts()
        _service_opts = self.get_minion_service_opts()
        return self.sort_opts(_base_opts + _service_opts)


def list_opts():
    """List config opts for oslo config generator"""
    return [(None, copy.deepcopy(MinionConfig().get_opts()))]


def load_global_config():
    """Register MinionConfig options into global config"""
    _opts = MinionConfig().get_opts()
    CONF.register_opts(_opts)
