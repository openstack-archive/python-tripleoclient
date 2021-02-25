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

from osc_lib.i18n import _

# NOTE(cloudnull): Condition imports and exceptions to support PY2, When we
#                  drop py2 this should be simplified.
try:
    import configparser as cfgp
except ImportError:
    import ConfigParser as cfgp
try:
    FileNotFoundError = FileNotFoundError
except NameError:
    FileNotFoundError = IOError


TRIPLEO_HEAT_TEMPLATES = "/usr/share/openstack-tripleo-heat-templates/"
OVERCLOUD_YAML_NAME = "overcloud.yaml"
OVERCLOUD_ROLES_FILE = "roles_data.yaml"
MINION_ROLES_FILE = "roles/UndercloudMinion.yaml"
MINION_OUTPUT_DIR = os.path.join(os.environ.get('HOME', '~/'))
MINION_CONF_PATH = os.path.join(MINION_OUTPUT_DIR, "minion.conf")
MINION_LOG_FILE = "install-minion.log"
UNDERCLOUD_ROLES_FILE = "roles_data_undercloud.yaml"
STANDALONE_EPHEMERAL_STACK_VSTATE = '/var/lib/tripleo-heat-installer'
UNDERCLOUD_LOG_FILE = "install-undercloud.log"
OVERCLOUD_NETWORKS_FILE = "network_data.yaml"
STANDALONE_NETWORKS_FILE = "/dev/null"
UNDERCLOUD_NETWORKS_FILE = "network_data_undercloud.yaml"
ANSIBLE_HOSTS_FILENAME = "hosts.yaml"
ANSIBLE_CWL = "tripleo_dense,tripleo_profile_tasks,tripleo_states"

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
IRONIC_LOCAL_IMAGE_PATH = '/var/lib/ironic/images'

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
UPGRADE_CONVERGE_FORBIDDEN_PARAMS = ["ceph3_namespace",
                                     "ceph3_tag",
                                     "ceph3_image",
                                     "name_prefix_stein",
                                     "name_suffix_stein",
                                     "namespace_stein",
                                     "tag_stein",
                                     ]

ENABLE_SSH_ADMIN_TIMEOUT = 600
ENABLE_SSH_ADMIN_STATUS_INTERVAL = 5
ENABLE_SSH_ADMIN_SSH_PORT_TIMEOUT = 600

ADDITIONAL_ARCHITECTURES = ['ppc64le']

DEFAULT_VALIDATIONS_BASEDIR = "/usr/share/ansible"
DEFAULT_VALIDATIONS_LEGACY_BASEDIR = "/usr/share/openstack-tripleo-validations"

VALIDATIONS_LOG_BASEDIR = '/var/log/validations'

DEFAULT_WORK_DIR = os.path.join(os.environ.get('HOME', '~/'),
                                'config-download')

TRIPLEO_STATIC_INVENTORY = 'tripleo-ansible-inventory.yaml'

ANSIBLE_INVENTORY = os.path.join(DEFAULT_WORK_DIR,
                                 '{}/', TRIPLEO_STATIC_INVENTORY)
ANSIBLE_VALIDATION_DIR = (
    os.path.join(DEFAULT_VALIDATIONS_LEGACY_BASEDIR, 'playbooks')
    if os.path.exists(os.path.join(DEFAULT_VALIDATIONS_LEGACY_BASEDIR,
                                   'playbooks'))
    else "/usr/share/ansible/validation-playbooks"
    )

ANSIBLE_TRIPLEO_PLAYBOOKS = \
    '/usr/share/ansible/tripleo-playbooks'

VALIDATION_GROUPS_INFO = (
        '/usr/share/ansible/groups.yaml'
        if os.path.exists('/usr/share/ansible/groups.yaml')
        else os.path.join(DEFAULT_VALIDATIONS_LEGACY_BASEDIR, 'groups.yaml')
        )

# ctlplane network defaults
CTLPLANE_CIDR_DEFAULT = '192.168.24.0/24'
CTLPLANE_DHCP_START_DEFAULT = ['192.168.24.5']
CTLPLANE_DHCP_END_DEFAULT = ['192.168.24.24']
CTLPLANE_INSPECTION_IPRANGE_DEFAULT = '192.168.24.100,192.168.24.120'
CTLPLANE_GATEWAY_DEFAULT = '192.168.24.1'
CTLPLANE_DNS_NAMESERVERS_DEFAULT = []

# Ansible parameters used for the actions being executed during tripleo
# deploy/upgrade. Used as kwargs in the `utils.run_ansible_playbook`
# function. A playbook entry is either a string representing the name of
# one the playbook or a list of playbooks to execute. The lookup
# will search for the playbook in the work directory path.
DEPLOY_ANSIBLE_ACTIONS = {
    'deploy': {
        'playbook': 'deploy_steps_playbook.yaml'
    },
    'upgrade': {
        'playbook': 'upgrade_steps_playbook.yaml',
        'skip_tags': 'validation'
    },
    'post-upgrade': {
        'playbook': 'post_upgrade_steps_playbook.yaml',
        'skip_tags': 'validation'
    },
    'online-upgrade': {
        'playbook': 'external_upgrade_steps_playbook.yaml',
        'tags': 'online_upgrade'
    },
    'preflight-deploy': {
        'playbook': 'undercloud-disk-space.yaml'
    },
    'preflight-upgrade': {
        'playbook': 'undercloud-disk-space-pre-upgrade.yaml'
    },
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

# clouds_yaml related constants
CLOUD_HOME_DIR = os.path.expanduser('~' + os.environ.get('SUDO_USER', ''))
CLOUDS_YAML_DIR = os.path.join('.config', 'openstack')

# Undercloud config and output
UNDERCLOUD_CONF_PATH = os.path.join(CLOUD_HOME_DIR, "undercloud.conf")
try:
    if os.path.exists(UNDERCLOUD_CONF_PATH):
        config = cfgp.ConfigParser()
        config.read(UNDERCLOUD_CONF_PATH)
        UNDERCLOUD_OUTPUT_DIR = config.get('DEFAULT', 'output_dir')
    else:
        raise FileNotFoundError
except (cfgp.NoOptionError, FileNotFoundError):
    UNDERCLOUD_OUTPUT_DIR = CLOUD_HOME_DIR

# regex patterns to exclude when looking for unused params
# - exclude *Image params as they may be unused because the service is not
#   enabled
# - exclude SwiftFetchDir*Tempurl because it's used by ceph and generated by us
# - exclude PythonInterpreter because it's generated by us and only used
#   in some custom scripts
UNUSED_PARAMETER_EXCLUDES_RE = ['^(Docker|Container).*Image$',
                                '^SwiftFetchDir(Get|Put)Tempurl$',
                                '^PythonInterpreter$']

EXPORT_PASSWORD_EXCLUDE_PATTERNS = [
    'ceph.*'
]

# Package that need to be to the latest before undercloud
# update/update
UNDERCLOUD_EXTRA_PACKAGES = [
    "openstack-tripleo-common",
    "openstack-tripleo-heat-templates",
    "openstack-tripleo-validations",
    "tripleo-ansible"
]

UPGRADE_PROMPT = _('You are about to run a UPGRADE command. '
                   'It is strongly recommended to perform a backup '
                   'before the upgrade. Are you sure you want to '
                   'upgrade [y/N]?')
UPGRADE_NO = _('User did not confirm upgrade, so exiting. '
               'Consider using the --yes/-y parameter if you '
               'prefer to skip this warning in the future')
UPDATE_PROMPT = _('You are about to run a UPDATE command. '
                  'It is strongly recommended to perform a backup '
                  'before the update. Are you sure you want to '
                  'update [y/N]?')
UPDATE_NO = _('User did not confirm update, so exiting. '
              'Consider using the --yes/-y parameter if you '
              'prefer to skip this warning in the future')
