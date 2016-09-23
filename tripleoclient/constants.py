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
    'aodh': {'password_field': 'OVERCLOUD_AODH_PASSWORD'},
    'ceilometer': {'password_field': 'OVERCLOUD_CEILOMETER_PASSWORD'},
    'cinder': {'password_field': 'OVERCLOUD_CINDER_PASSWORD'},
    'cinderv2': {'password_field': 'OVERCLOUD_CINDER_PASSWORD'},
    'glance': {'password_field': 'OVERCLOUD_GLANCE_PASSWORD'},
    'gnocchi': {'password_field': 'OVERCLOUD_GNOCCHI_PASSWORD'},
    'heat': {'password_field': 'OVERCLOUD_HEAT_PASSWORD'},
    'heatcfn': {},
    'ironic': {'password_field': 'OVERCLOUD_IRONIC_PASSWORD'},
    'neutron': {'password_field': 'OVERCLOUD_NEUTRON_PASSWORD'},
    'nova': {'password_field': 'OVERCLOUD_NOVA_PASSWORD'},
    'swift': {'password_field': 'OVERCLOUD_SWIFT_PASSWORD'},
    'sahara': {'password_field': 'OVERCLOUD_SAHARA_PASSWORD'},
    'trove': {'password_field': 'OVERCLOUD_TROVE_PASSWORD'},
}

TRIPLEO_HEAT_TEMPLATES = "/usr/share/openstack-tripleo-heat-templates/"
OVERCLOUD_YAML_NAME = "overcloud.yaml"
OVERCLOUD_ROLES_FILE = "roles_data.yaml"
RESOURCE_REGISTRY_NAME = "overcloud-resource-registry-puppet.yaml"
RHEL_REGISTRATION_EXTRACONFIG_NAME = (
    "extraconfig/pre_deploy/rhel-registration/")
