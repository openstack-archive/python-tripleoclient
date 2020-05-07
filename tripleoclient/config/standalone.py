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

    def get_enable_service_opts(self, cinder=False, ironic=False,
                                ironic_inspector=False, mistral=False,
                                nova=False, novajoin=False, tempest=False,
                                telemetry=False, tripleo_ui=False,
                                validations=False, zaqar=False):
        _opts = [
            # service enablement
            cfg.BoolOpt('enable_cinder',
                        default=cinder,
                        help=_(
                            'Whether to install the Volume service. It is not '
                            'currently used in the undercloud.')),
            cfg.BoolOpt('enable_ironic',
                        default=ironic,
                        help=_('Whether to enable the ironic service.')),
            cfg.BoolOpt('enable_ironic_inspector',
                        default=ironic_inspector,
                        help=_(
                            'Whether to enable the ironic inspector service.')
                        ),
            cfg.BoolOpt('enable_mistral',
                        default=mistral,
                        help=_('Whether to enable the mistral service.')),
            cfg.BoolOpt('enable_nova',
                        default=nova,
                        help=_('Whether to enable the nova service.')),
            cfg.BoolOpt('enable_novajoin',
                        default=novajoin,
                        help=_('Whether to install novajoin metadata service '
                               'in the Undercloud.')
                        ),
            cfg.BoolOpt('enable_tempest',
                        default=tempest,
                        help=_('Whether to install Tempest in the Undercloud.'
                               'This is a no-op for containerized undercloud.')
                        ),
            cfg.BoolOpt('enable_telemetry',
                        default=telemetry,
                        help=_('Whether to install Telemetry services '
                               '(ceilometer, gnocchi, aodh) in the '
                               'Undercloud.')
                        ),
            cfg.BoolOpt('enable_validations',
                        default=validations,
                        help=_(
                            'Whether to install requirements to run the '
                            'TripleO validations.')
                        ),
            cfg.BoolOpt('enable_zaqar',
                        default=zaqar,
                        help=_('Whether to enable the zaqar service.')),
        ]
        return self.sort_opts(_opts)

    def get_base_opts(self):
        _base_opts = super(StandaloneConfig, self).get_base_opts()
        _opts = [
            # deployment options
            cfg.StrOpt('deployment_user',
                       help=_(
                           'User used to run openstack undercloud install '
                           'command which will be used to add the user to the '
                           'docker group, required to upload containers'),
                       ),
            cfg.StrOpt('hieradata_override',
                       default='',
                       help=_(
                           'Path to hieradata override file. Relative paths '
                           'get computed inside of $HOME. When it points to a '
                           'heat env file, it is passed in t-h-t via "-e '
                           '<file>", as is. When the file contains legacy '
                           'instack data, it is wrapped with '
                           'UndercloudExtraConfig and also passed in for '
                           't-h-t as a temp file created in output_dir. Note, '
                           'instack hiera data may be not t-h-t compatible '
                           'and will highly likely require a manual revision.')
                       ),
            cfg.StrOpt('net_config_override',
                       default='',
                       help=_(
                           'Path to network config override template. '
                           'Relative paths get computed inside of $HOME. '
                           'Must be in the json format. '
                           'Its content overrides anything in t-h-t '
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
                       default='',
                       help=_('heat templates file to override.')
                       ),
            cfg.StrOpt('roles_file',
                       default=None,
                       help=_('Roles file to override for heat. May be an '
                              'absolute path or the path relative to the '
                              't-h-t templates directory used for deployment')
                       ),
            cfg.StrOpt('networks_file',
                       default=None,
                       help=_('Networks file to override for heat. May be an '
                              'absolute path or the path relative to the '
                              't-h-t templates directory used for deployment')
                       ),
            cfg.BoolOpt('heat_native',
                        default=True,
                        help=_('Execute the heat-all process natively on this '
                               'host. This option requires that the heat-all '
                               'binaries be installed locally on this machine.'
                               ' This option is enabled by default which means'
                               ' heat-all is executed on the host OS '
                               ' directly.')),
            cfg.StrOpt('heat_container_image',
                       default='',
                       help=_('URL for the heat container image to use.')
                       ),
            cfg.StrOpt('container_images_file',
                       default='',
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
            # docker config bits
            cfg.StrOpt('container_registry_mirror',
                       deprecated_name='docker_registry_mirror',
                       default='',
                       help=_(
                           'An optional container registry mirror that will '
                           'be used.')
                       ),
            cfg.ListOpt('container_insecure_registries',
                        deprecated_name='docker_insecure_registries',
                        default=[],
                        help=_('Used to add custom insecure registries for '
                               'containers.')
                        ),
            cfg.StrOpt('container_cli',
                       default='podman',
                       help=_('Container CLI used for deployment; '
                              'Can be docker or podman.')),
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
