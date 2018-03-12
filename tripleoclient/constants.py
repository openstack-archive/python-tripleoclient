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

TRIPLEO_HEAT_TEMPLATES = "/usr/share/openstack-tripleo-heat-templates/"
OVERCLOUD_YAML_NAME = "overcloud.yaml"
OVERCLOUD_ROLES_FILE = "roles_data.yaml"
UNDERCLOUD_ROLES_FILE = "roles_data_undercloud.yaml"
OVERCLOUD_NETWORKS_FILE = "network_data.yaml"
RHEL_REGISTRATION_EXTRACONFIG_NAME = (
    "extraconfig/pre_deploy/rhel-registration/")

# The name of the file which holds the plan environment contents
PLAN_ENVIRONMENT = 'plan-environment.yaml'
USER_ENVIRONMENT = 'user-environment.yaml'
USER_PARAMETERS = 'user-environments/tripleoclient-parameters.yaml'

# This directory may contain additional environments to use during deploy
DEFAULT_ENV_DIRECTORY = "~/.tripleo/environments"

TRIPLEO_PUPPET_MODULES = "/usr/share/openstack-puppet/modules/"
UPGRADE_CONVERGE_FILE = "major-upgrade-converge-docker.yaml"
PUPPET_MODULES = "/etc/puppet/modules/"
PUPPET_BASE = "/etc/puppet/"
# Update Queue
UPDATE_QUEUE = 'update'
UPGRADE_QUEUE = 'upgrade'
STACK_TIMEOUT = 240

# The default minor update ansible playbooks generated from heat stack output
MINOR_UPDATE_PLAYBOOKS = ['update_steps_playbook.yaml',
                          'deploy_steps_playbook.yaml']
# The default major upgrade ansible playbooks generated from heat stack output
MAJOR_UPGRADE_PLAYBOOKS = ["upgrade_steps_playbook.yaml",
                           "deploy_steps_playbook.yaml",
                           "post_upgrade_steps_playbook.yaml"]
MAJOR_UPGRADE_SKIP_TAGS = ['validation', 'pre-upgrade']
