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

import copy

from osc_lib.i18n import _
from oslo_config import cfg
from tripleoclient.config.base import BaseConfig
from tripleoclient.constants import DEFAULT_HEAT_CONTAINER

NETCONFIG_TAGS_EXAMPLE = """
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


class StandaloneConfig(BaseConfig):

    def get_enable_service_opts(self, cinder=False, frr=False, ironic=False,
                                ironic_inspector=False,
                                nova=False, novajoin=False, swift=False,
                                telemetry=False, validations=False,
                                neutron=False, heat=False, keystone=True):
        _opts = [
            # service enablement
            cfg.BoolOpt('enable_cinder',
                        default=cinder,
                        deprecated_for_removal=True,
                        deprecated_reason=_('Cinder can no longer be enabled '
                                            'via the config settings.'),
                        help=_('Whether to install the cinder service.')),
            cfg.BoolOpt('enable_frr',
                        default=frr,
                        help=_('Whether to enable the frr service.')),
            cfg.BoolOpt('enable_ironic',
                        default=ironic,
                        help=_('Whether to enable the ironic service.')),
            cfg.BoolOpt('enable_ironic_inspector',
                        default=ironic_inspector,
                        help=_('Whether to enable the ironic inspector '
                               'service.')
                        ),
            cfg.BoolOpt('enable_nova',
                        default=nova,
                        deprecated_for_removal=True,
                        deprecated_reason=_('Nova can no longer be enabled '
                                            'via the config settings.'),
                        help=_('Whether to enable the nova service.')),
            cfg.BoolOpt('enable_novajoin',
                        default=novajoin,
                        deprecated_for_removal=True,
                        deprecated_reason=('Support for the novajoin metadata '
                                           'service has been deprecated.'),
                        help=_('Whether to install the novajoin metadata '
                               'service')
                        ),
            cfg.BoolOpt('enable_swift',
                        default=swift,
                        deprecated_for_removal=True,
                        deprecated_reason=_('Swift can no longer be enabled '
                                            'via the config settings.'),
                        help=_('Whether to install the swift services')
                        ),
            cfg.BoolOpt('enable_telemetry',
                        default=telemetry,
                        deprecated_for_removal=True,
                        deprecated_reason=_('Telemetry can no longer be '
                                            'enabled via the config '
                                            'settings.'),
                        help=_('Whether to install Telemetry services '
                               '(ceilometer, gnocchi, aodh).')
                        ),
            cfg.BoolOpt('enable_validations',
                        default=validations,
                        help=_(
                            'Whether to install requirements to run the '
                            'TripleO validations.')
                        ),
            cfg.BoolOpt('enable_neutron',
                        default=neutron,
                        help=_('Whether to enable the neutron service.')),
            cfg.BoolOpt('enable_heat',
                        default=heat,
                        deprecated_for_removal=True,
                        deprecated_reason=('Heat has been replaced by the '
                                           'heat-ephemeral service and this '
                                           'option has been deprecated.'),
                        help=_('Whether to enable the heat service.')),
            cfg.BoolOpt('enable_keystone',
                        default=keystone,
                        deprecated_for_removal=True,
                        deprecated_reason=_('Keystone can no longer be '
                                            'enabled via the config '
                                            'settings.'),
                        help=_('Whether to enable the keystone service.')),

        ]
        return self.sort_opts(_opts)

    def get_base_opts(self):
        _base_opts = super(StandaloneConfig, self).get_base_opts()
        _opts = [
            # deployment options
            cfg.StrOpt('deployment_user',
                       help=_(
                           'User used to run openstack undercloud install '
                           'command.')
                       ),
            cfg.StrOpt('hieradata_override',
                       help=_(
                           'Path to hieradata override file. Relative paths '
                           'get computed inside of $HOME. When it points to a '
                           'heat env file, it is passed in '
                           'tripleo-heat-templates via "-e <file>", as is. '
                           'When the file contains legacy instack data, it is '
                           'wrapped with UndercloudExtraConfig and also '
                           'passed in for tripleo-heat-templates as a temp '
                           'file created in output_dir. Note, instack '
                           'hieradata may be incompatible with '
                           'tripleo-heat-templates and will highly likely '
                           'require a manual revision.')
                       ),
            cfg.StrOpt('net_config_override',
                       help=_(
                           'Path to network config override template. '
                           'Relative paths get computed inside of $HOME. '
                           'Must be in the json or yaml format. '
                           'Its content overrides anything in '
                           '<role>NetConfigOverride. The processed '
                           'template is then passed in Heat via the '
                           'generated parameters file created in '
                           'output_dir and used to configure the networking '
                           'via run-os-net-config. If you wish to disable '
                           'you can set this location to an empty file. '
                           'Templated for instack j2 tags '
                           'may be used, '
                           'for example:\n%s ') % NETCONFIG_TAGS_EXAMPLE
                       ),
            cfg.StrOpt('templates',
                       help=_('The tripleo-heat-templates directory to '
                              'override')
                       ),
            cfg.StrOpt('roles_file',
                       help=_('Roles file to override for heat. May be an '
                              'absolute path or the path relative to the '
                              'tripleo-heat-templates directory used for '
                              'deployment')
                       ),
            cfg.StrOpt('networks_file',
                       help=_('Networks file to override for heat. May be an '
                              'absolute path or the path relative to the '
                              'tripleo-heat-templates directory used for '
                              'deployment')
                       ),
            cfg.BoolOpt('heat_native',
                        default=True,
                        help=_('Execute the heat-all process natively on this '
                               'host. This option requires that the heat-all '
                               'binaries be installed locally on this machine.'
                               ' This option is enabled by default which means'
                               ' heat-all is executed on the host OS '
                               ' directly If this is set to false, a '
                               'containerized version of heat-all is used.')),
            cfg.StrOpt('heat_container_image',
                       help=_('Custom URL for the heat-all container image to '
                              'use as part of the undercloud deployment. If '
                              'not specified, the default "%s" is used. '
                              'If this location requires authentication, '
                              'run podman login prior to running the '
                              'undercloud install.' % DEFAULT_HEAT_CONTAINER)
                       ),
            cfg.StrOpt('container_images_file',
                       required=False,
                       help=_(
                           'REQUIRED if authentication is needed to fetch '
                           'containers. This file should contain values for '
                           '"ContainerImagePrepare" and '
                           '"ContainerImageRegistryCredentials" that will be '
                           'used to fetch the containers for the undercloud '
                           'installation. `openstack tripleo container image '
                           'prepare default` can be used to provide a sample '
                           '"ContainerImagePrepare" value. Alternatively this '
                           'file can contain all the required Heat parameters '
                           'for the containers for advanced configurations.')),
            cfg.ListOpt('custom_env_files',
                        default=[],
                        help=_('List of any custom environment yaml files to '
                               'use. These are applied after any other '
                               'configuration and can be used to override '
                               'any derived values. This should be used '
                               'only by advanced users.')),
            # container config bits
            cfg.StrOpt('container_registry_mirror',
                       help=_(
                           'An optional container registry mirror that will '
                           'be used.')
                       ),
            cfg.ListOpt('container_insecure_registries',
                        default=[],
                        help=_('Used to add custom insecure registries for '
                               'containers.')
                        ),
            cfg.StrOpt('container_cli',
                       default='podman',
                       choices=('podman',),
                       help=_('Container CLI used for deployment; '
                              'Only podman is allowed.')),
            cfg.BoolOpt('container_healthcheck_disabled',
                        default=False,
                        help=_(
                            'Whether or not we disable the container '
                            'healthchecks.')),
        ]
        return self.sort_opts(_base_opts + _opts)

    def get_opts(self):
        return self.sort_opts(self.get_base_opts() +
                              self.get_enable_service_opts())


# this is needed for the oslo config generator
def list_opts():
    return [(None, copy.deepcopy(StandaloneConfig().get_opts()))]
