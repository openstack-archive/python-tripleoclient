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

import os

TRIPLEO_HEAT_TEMPLATES = "/usr/share/openstack-tripleo-heat-templates/"
OVERCLOUD_YAML_NAME = "overcloud.yaml"
OVERCLOUD_ROLES_FILE = "roles_data.yaml"
UNDERCLOUD_ROLES_FILE = "roles_data_undercloud.yaml"
UNDERCLOUD_OUTPUT_DIR = os.path.join(os.environ.get('HOME', '~/'))
STANDALONE_EPHEMERAL_STACK_VSTATE = '/var/lib/tripleo-heat-installer'
UNDERCLOUD_LOG_FILE = "install-undercloud.log"
UNDERCLOUD_CONF_PATH = os.path.join(UNDERCLOUD_OUTPUT_DIR, "undercloud.conf")
OVERCLOUD_NETWORKS_FILE = "network_data.yaml"
STANDALONE_NETWORKS_FILE = "/dev/null"
UNDERCLOUD_NETWORKS_FILE = "network_data_undercloud.yaml"
RHEL_REGISTRATION_EXTRACONFIG_NAME = (
    "extraconfig/pre_deploy/rhel-registration/")

# The name of the file which holds the plan environment contents
PLAN_ENVIRONMENT = 'plan-environment.yaml'
USER_ENVIRONMENT = 'user-environment.yaml'
USER_PARAMETERS = 'user-environments/tripleoclient-parameters.yaml'

# This directory may contain additional environments to use during deploy
DEFAULT_ENV_DIRECTORY = os.path.join(os.environ.get('HOME', '~/'),
                                     '.tripleo', 'environments')

TRIPLEO_PUPPET_MODULES = "/usr/share/openstack-puppet/modules/"
PUPPET_MODULES = "/etc/puppet/modules/"
PUPPET_BASE = "/etc/puppet/"

STACK_TIMEOUT = 240

IRONIC_HTTP_BOOT_BIND_MOUNT = '/var/lib/ironic/httpboot'

# The default ffwd upgrade ansible playbooks generated from heat stack output
FFWD_UPGRADE_PLAYBOOK = "fast_forward_upgrade_playbook.yaml"
# The default minor update ansible playbooks generated from heat stack output
MINOR_UPDATE_PLAYBOOKS = ['update_steps_playbook.yaml']
# The default major upgrade ansible playbooks generated from heat stack output
MAJOR_UPGRADE_PLAYBOOKS = ["upgrade_steps_playbook.yaml",
                           "deploy_steps_playbook.yaml",
                           "post_upgrade_steps_playbook.yaml"]
MAJOR_UPGRADE_SKIP_TAGS = ['validation', 'pre-upgrade']
EXTERNAL_UPDATE_PLAYBOOKS = ['external_update_steps_playbook.yaml']
EXTERNAL_UPGRADE_PLAYBOOKS = ['external_upgrade_steps_playbook.yaml']
# upgrade environment files expected by the client in the --templates
# tripleo-heat-templates default above $TRIPLEO_HEAT_TEMPLATES
UPDATE_PREPARE_ENV = "environments/lifecycle/update-prepare.yaml"
UPDATE_CONVERGE_ENV = "environments/lifecycle/update-converge.yaml"
UPGRADE_PREPARE_ENV = "environments/lifecycle/upgrade-prepare.yaml"
UPGRADE_CONVERGE_ENV = "environments/lifecycle/upgrade-converge.yaml"
FFWD_UPGRADE_PREPARE_ENV = "environments/lifecycle/ffwd-upgrade-prepare.yaml"
FFWD_UPGRADE_CONVERGE_ENV = "environments/lifecycle/ffwd-upgrade-converge.yaml"
FFWD_UPGRADE_PREPARE_SCRIPT = ("#!/bin/bash \n"
                               "rm -f /usr/libexec/os-apply-config/templates/"
                               "etc/os-net-config/config.json || true \n")

ENABLE_SSH_ADMIN_TIMEOUT = 600
ENABLE_SSH_ADMIN_STATUS_INTERVAL = 5
ENABLE_SSH_ADMIN_SSH_PORT_TIMEOUT = 300

ADDITIONAL_ARCHITECTURES = ['ppc64le']

DEFAULT_VALIDATIONS_BASEDIR = '/usr/share/openstack-tripleo-validations'

ANSIBLE_VALIDATION_DIR = \
    '/usr/share/openstack-tripleo-validations/playbooks'

VALIDATION_GROUPS = ['openshift-on-openstack',
                     'prep',
                     'pre-introspection',
                     'pre-deployment',
                     'post-deployment',
                     'pre-upgrade',
                     'post-upgrade']


# ctlplane network defaults
CTLPLANE_CIDR_DEFAULT = '192.168.24.0/24'
CTLPLANE_DHCP_START_DEFAULT = ['192.168.24.5']
CTLPLANE_DHCP_END_DEFAULT = ['192.168.24.24']
CTLPLANE_INSPECTION_IPRANGE_DEFAULT = '192.168.24.100,192.168.24.120'
CTLPLANE_GATEWAY_DEFAULT = '192.168.24.1'

# Ansible parameters used for the actions being
# executed during tripleo deploy/upgrade.
DEPLOY_ANSIBLE_ACTIONS = {
    'deploy': 'deploy_steps_playbook.yaml',
    'upgrade': 'upgrade_steps_playbook.yaml --skip-tags '
               'validation',
    'post-upgrade': 'post_upgrade_steps_playbook.yaml '
                    '--skip-tags validation',
    'online-upgrade': 'external_upgrade_steps_playbook.yaml '
                      '--tags online_upgrade',
}

# Key-value pair of deprecated service and its warning message
DEPRECATED_SERVICES = {"OS::TripleO::Services::OpenDaylightApi":
                       "You are using OpenDaylight as your networking"
                       " driver for OpenStack. OpenDaylight is deprecated"
                       " starting from Rocky and removed since Stein and "
                       "there is no upgrade or migration path from "
                       "OpenDaylight to another networking backend. We "
                       "recommend you understand other networking "
                       "alternatives such as OVS or OVN. "}
