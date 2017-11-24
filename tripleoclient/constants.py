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

SERVICE_LIST = {
    'aodh': {'password_field': 'AodhPassword'},
    'ceilometer': {'password_field': 'CeilometerPassword'},
    'cinder': {'password_field': 'CinderPassword'},
    'cinderv2': {'password_field': 'CinderPassword'},
    'glance': {'password_field': 'GlancePassword'},
    'gnocchi': {'password_field': 'GnocchiPassword'},
    'heat': {'password_field': 'HeatPassword'},
    'heatcfn': {},
    'ironic': {'password_field': 'IronicPassword'},
    'neutron': {'password_field': 'NeutronPassword'},
    'nova': {'password_field': 'NovaPassword'},
    'panko': {'password_field': 'PankoPassword'},
    'swift': {'password_field': 'SwiftPassword'},
    'sahara': {'password_field': 'SaharaPassword'},
    'trove': {'password_field': 'TrovePassword'},
}

TRIPLEO_HEAT_TEMPLATES = "/usr/share/openstack-tripleo-heat-templates/"
OVERCLOUD_YAML_NAME = "overcloud.yaml"
OVERCLOUD_ROLES_FILE = "roles_data.yaml"
OVERCLOUD_NETWORKS_FILE = "network_data.yaml"
RHEL_REGISTRATION_EXTRACONFIG_NAME = (
    "extraconfig/pre_deploy/rhel-registration/")

# The name of the file which holds the plan environment contents
PLAN_ENVIRONMENT = 'plan-environment.yaml'

TRIPLEO_PUPPET_MODULES = "/usr/share/openstack-puppet/modules/"
PUPPET_MODULES = "/etc/puppet/modules/"
PUPPET_BASE = "/etc/puppet/"
# Update Queue
UPDATE_QUEUE = 'update'
STACK_TIMEOUT = 240
