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

import configparser
import os
import sys

from osc_lib.i18n import _
from tripleo_common.image import kolla_builder

TRIPLEO_ARCHIVE_DIR = "/var/lib/tripleo/archive"
TRIPLEO_HEAT_TEMPLATES = "/usr/share/openstack-tripleo-heat-templates/"
OVERCLOUD_YAML_NAME = "overcloud.yaml"
OVERCLOUD_ROLES_FILE = "roles_data.yaml"
UNDERCLOUD_ROLES_FILE = "roles_data_undercloud.yaml"
STANDALONE_ROLES_FILE = "roles_data_standalone.yaml"
STANDALONE_EPHEMERAL_STACK_VSTATE = '/var/lib/tripleo-heat-installer'
UNDERCLOUD_LOG_FILE = "install-undercloud.log"
OVERCLOUD_NETWORKS_FILE = "network_data_default.yaml"
OVERCLOUD_VIP_FILE = "vip_data_default.yaml"
STANDALONE_NETWORKS_FILE = "/dev/null"
UNDERCLOUD_NETWORKS_FILE = "network_data_undercloud.yaml"
ANSIBLE_HOSTS_FILENAME = "hosts.yaml"
EPHEMERAL_HEAT_POD_NAME = "ephemeral-heat"
ANSIBLE_CWL = "tripleo_dense,tripleo_profile_tasks,tripleo_states"
CONTAINER_IMAGE_PREPARE_LOG_FILE = "container_image_prepare.log"
DEFAULT_CONTAINER_REGISTRY = "quay.io"
DEFAULT_CONTAINER_NAMESPACE = "tripleomastercentos9"
DEFAULT_CONTAINER_NAME_PREFIX = "openstack-"
DEFAULT_CONTAINER_TAG = "current-tripleo"
DEFAULT_RESOURCE_REGISTRY = 'overcloud-resource-registry-puppet.yaml'

if os.path.isfile(kolla_builder.DEFAULT_PREPARE_FILE):
    kolla_builder.init_prepare_defaults(kolla_builder.DEFAULT_PREPARE_FILE)
    DEFAULT_CONTAINER_IMAGE_PARAMS = kolla_builder.CONTAINER_IMAGES_DEFAULTS
else:
    DEFAULT_CONTAINER_IMAGE_PARAMS = {
        'namespace': '{}/{}'.format(
            DEFAULT_CONTAINER_REGISTRY,
            DEFAULT_CONTAINER_NAMESPACE
        ),
        'name_prefix': DEFAULT_CONTAINER_NAME_PREFIX,
        'tag': DEFAULT_CONTAINER_TAG
    }
DEFAULT_HEAT_CONTAINER = ('{}/{}heat-all:{}'.format(
    DEFAULT_CONTAINER_IMAGE_PARAMS['namespace'],
    DEFAULT_CONTAINER_IMAGE_PARAMS['name_prefix'],
    DEFAULT_CONTAINER_IMAGE_PARAMS['tag']))
DEFAULT_HEAT_API_CONTAINER = ('{}/{}heat-api:{}'.format(
    DEFAULT_CONTAINER_IMAGE_PARAMS['namespace'],
    DEFAULT_CONTAINER_IMAGE_PARAMS['name_prefix'],
    DEFAULT_CONTAINER_IMAGE_PARAMS['tag']))
DEFAULT_HEAT_ENGINE_CONTAINER = ('{}/{}heat-engine:{}'.format(
    DEFAULT_CONTAINER_IMAGE_PARAMS['namespace'],
    DEFAULT_CONTAINER_IMAGE_PARAMS['name_prefix'],
    DEFAULT_CONTAINER_IMAGE_PARAMS['tag']))
DEFAULT_EPHEMERAL_HEAT_CONTAINER = \
    'localhost/tripleo/openstack-heat-all:ephemeral'
DEFAULT_EPHEMERAL_HEAT_API_CONTAINER = \
    'localhost/tripleo/openstack-heat-api:ephemeral'
DEFAULT_EPHEMERAL_HEAT_ENGINE_CONTAINER = \
    'localhost/tripleo/openstack-heat-engine:ephemeral'


USER_PARAMETERS = 'user-environments/tripleoclient-parameters.yaml'
PASSWORDS_ENV_FORMAT = '{}-passwords.yaml'

# This directory may contain additional environments to use during deploy
DEFAULT_ENV_DIRECTORY = os.path.join(os.environ.get('HOME', '~/'),
                                     '.tripleo', 'environments')
TRIPLEO_PUPPET_MODULES = "/usr/share/openstack-puppet/modules/"
PUPPET_MODULES = "/etc/puppet/modules/"
PUPPET_BASE = "/etc/puppet/"

STACK_TIMEOUT = 60
STACK_OUTPUTS = ['BlacklistedHostnames',
                 'RoleNetIpMap',
                 'BlacklistedIpAddresses',
                 'RoleNetHostnameMap',
                 'KeystoneAdminVip',
                 'KeystoneRegion',
                 'KeystoneURL',
                 'EndpointMap',
                 'VipMap',
                 'EnabledServices',
                 'HostsEntry',
                 'AdminPassword',
                 'GlobalConfig']

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
UPGRADE_PREPARE_ENV = "environments/lifecycle/upgrade-prepare.yaml"
ENABLE_SSH_ADMIN_TIMEOUT = 600
ENABLE_SSH_ADMIN_STATUS_INTERVAL = 5
ENABLE_SSH_ADMIN_SSH_PORT_TIMEOUT = 600

ADDITIONAL_ARCHITECTURES = ['ppc64le']

DEFAULT_VALIDATIONS_BASEDIR = "/usr/share/ansible"

VALIDATIONS_LOG_BASEDIR = '/var/log/validations'

DEFAULT_WORK_DIR = os.path.join(os.environ.get('HOME', '~/'),
                                'config-download')

DEFAULT_TEMPLATES_DIR = "/usr/share/python-tripleoclient/templates"

TRIPLEO_STATIC_INVENTORY = 'tripleo-ansible-inventory.yaml'
ANSIBLE_INVENTORY = os.path.join(DEFAULT_WORK_DIR,
                                 '{}/', TRIPLEO_STATIC_INVENTORY)
ANSIBLE_VALIDATION_DIR = "/usr/share/ansible/validation-playbooks"

# NOTE(mwhahaha): So if we pip install tripleoclient, we need to also
# honor pulling some other files from a venv (e.g. cli playbooks,
# and container image yaml for building). This logic will create a
# constant for a venv share path which we can use to check to see if things
# like tripleo-common or tripleo-ansible have also been pip installed.
SHARE_BASE_PATH = os.path.join(sys.prefix, 'share')
if sys.prefix != '/usr' and not os.path.isdir(SHARE_BASE_PATH):
    SHARE_BASE_PATH = os.path.join('/usr', 'share')

ANSIBLE_TRIPLEO_PLAYBOOKS = os.path.join(
    SHARE_BASE_PATH, 'ansible', 'tripleo-playbooks'
)
if sys.prefix != '/usr' and not os.path.isdir(ANSIBLE_TRIPLEO_PLAYBOOKS):
    ANSIBLE_TRIPLEO_PLAYBOOKS = os.path.join(
        '/usr', 'share', 'ansible', 'tripleo-playbooks'
    )
CONTAINER_IMAGES_BASE_PATH = os.path.join(
    SHARE_BASE_PATH, "tripleo-common", "container-images"
)
if sys.prefix != "/usr" and not os.path.isdir(CONTAINER_IMAGES_BASE_PATH):
    CONTAINER_IMAGES_BASE_PATH = os.path.join(
        "/usr", "share", "tripleo-common", "container-images"
    )

VALIDATION_GROUPS_INFO = "{}/groups.yaml".format(DEFAULT_VALIDATIONS_BASEDIR)

# ctlplane network defaults
CTLPLANE_NET_NAME = 'ctlplane'
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
        'playbooks': ['undercloud-disk-space.yaml',
                      'undercloud-disabled-services.yaml']
    },
    'preflight-upgrade': {
        'playbooks': ['undercloud-disk-space-pre-upgrade.yaml',
                      'undercloud-disabled-services.yaml']
    },
}

# Key-value pair of deprecated service and its warning message
DEPRECATED_SERVICES = {}

# clouds_yaml related constants
CLOUD_HOME_DIR = os.path.expanduser('~' + os.environ.get('SUDO_USER', ''))
CLOUDS_YAML_DIR = os.path.join('.config', 'openstack')

# Undercloud config and output
UNDERCLOUD_CONF_PATH = os.path.join(CLOUD_HOME_DIR, "undercloud.conf")
try:
    if os.path.exists(UNDERCLOUD_CONF_PATH):
        config = configparser.ConfigParser()
        config.read(UNDERCLOUD_CONF_PATH)
        UNDERCLOUD_OUTPUT_DIR = config.get('DEFAULT', 'output_dir')
    else:
        raise FileNotFoundError
except (configparser.NoOptionError, FileNotFoundError):
    UNDERCLOUD_OUTPUT_DIR = CLOUD_HOME_DIR

# regex patterns to exclude when looking for unused params
# - exclude *Image params as they may be unused because the service is not
#   enabled
# - exclude PythonInterpreter because it's generated by us and only used
#   in some custom scripts
UNUSED_PARAMETER_EXCLUDES_RE = ['^(Docker|Container).*Image$',
                                '^PythonInterpreter$']

EXPORT_PASSWORD_EXCLUDE_PATTERNS = [
    'ceph.*'
]

EXPORT_DATA = {
        "EndpointMap": {
            "parameter": "EndpointMapOverride",
        },
        "HostsEntry": {
            "parameter": "ExtraHostFileEntries",
        },
        "GlobalConfig": {
            "parameter": "GlobalConfigExtraMapData",
        },
        "AllNodesConfig": {
            "file": "group_vars/overcloud.json",
            "parameter": "AllNodesExtraMapData",
            "filter": ["oslo_messaging_notify_short_bootstrap_node_name",
                       "oslo_messaging_notify_node_names",
                       "oslo_messaging_rpc_node_names",
                       "memcached_node_ips",
                       "ovn_dbs_vip",
                       "ovn_dbs_node_ips",
                       "redis_vip"]},
    }

# Package that need to be to the latest before undercloud
# update/update
UNDERCLOUD_EXTRA_PACKAGES = [
    "python3-tripleoclient",
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

DEFAULT_PARTITION_IMAGE = 'overcloud-full.qcow2'
DEFAULT_WHOLE_DISK_IMAGE = 'overcloud-hardened-uefi-full.qcow2'

FIPS_COMPLIANT_HASHES = {'sha1', 'sha224', 'sha256', 'sha384', 'sha512'}

# Work-Dir default file names
WD_DEFAULT_ROLES_FILE_NAME = 'tripleo-{}-roles-data.yaml'
WD_DEFAULT_NETWORKS_FILE_NAME = 'tripleo-{}-network-data.yaml'
WD_DEFAULT_VIP_FILE_NAME = 'tripleo-{}-virtual-ips.yaml'
WD_DEFAULT_BAREMETAL_FILE_NAME = 'tripleo-{}-baremetal-deployment.yaml'
KIND_TEMPLATES = {'roles': WD_DEFAULT_ROLES_FILE_NAME,
                  'networks': WD_DEFAULT_NETWORKS_FILE_NAME,
                  'baremetal': WD_DEFAULT_BAREMETAL_FILE_NAME,
                  'vips': WD_DEFAULT_VIP_FILE_NAME}

STACK_ENV_FILE_NAME = 'tripleo-{}-environment.yaml'
# Disk usage percentages to check as related to deploy backups
DEPLOY_BACKUPS_USAGE_PERCENT = 50
DISK_USAGE_PERCENT = 80
