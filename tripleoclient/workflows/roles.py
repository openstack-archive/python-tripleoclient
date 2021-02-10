# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging

import yaml

from tripleoclient import utils

LOG = logging.getLogger(__name__)


def get_roles_data(roles_file, tht_root):
    abs_roles_file = utils.get_roles_file_path(
        roles_file, tht_root)
    roles_data = None
    with open(abs_roles_file, 'r') as fp:
        roles_data = yaml.safe_load(fp)
    return roles_data


def get_roles(clients, roles_file, tht_root,
              stack_name,
              template,
              files,
              env_files,
              detail=False, valid=False):
    roles_data = get_roles_data(roles_file, tht_root)

    if detail:
        return roles_data

    role_names = [role['name'] for role in roles_data]

    if not valid:
        return role_names

    stack_data = utils.build_stack_data(
        clients, stack_name, template,
        files, env_files)

    valid_roles = []
    for name in role_names:
        role_count = stack_data['heat_resource_tree'][
            'parameters'].get(name + 'Count', {}).get(
                'default', 0)
        if role_count > 0:
            valid_roles.append(name)

    return valid_roles
