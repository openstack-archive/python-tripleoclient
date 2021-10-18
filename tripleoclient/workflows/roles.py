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

from tripleoclient import utils

LOG = logging.getLogger(__name__)


def get_roles(clients,
              stack_name,
              template,
              files,
              env_files,
              working_dir,
              detail=False, valid=False):
    roles_data = utils.get_roles_data(working_dir, stack_name)

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
