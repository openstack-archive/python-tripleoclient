# Copyright 2016 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import collections
import shutil
import tempfile

from tripleoclient import constants
from tripleoclient import utils


def get_group_resources_after_delete(groupname, res_to_delete, resources):
    group = next(res for res in resources if
                 res.resource_name == groupname and
                 res.resource_type == 'OS::Heat::ResourceGroup')
    members = []
    for res in resources:
        stack_name, stack_id = next(
            x['href'] for x in res.links if
            x['rel'] == 'stack').rsplit('/', 2)[1:]
        # desired new count of nodes after delete operation should be
        # count of all existing nodes in ResourceGroup which are not
        # in set of nodes being deleted. Also nodes in any delete state
        # from a previous failed update operation are not included in
        # overall count (if such nodes exist)
        if (stack_id == group.physical_resource_id and
            res not in res_to_delete and
                not res.resource_status.startswith('DELETE')):

            members.append(res)

    return members


def _get_removal_params_from_heat(resources_by_role, resources):
    stack_params = {}
    for role, role_resources in resources_by_role.items():
        param_name = "{0}Count".format(role)

        # get real count of nodes for each role. *Count stack parameters
        # can not be used because stack parameters return parameters
        # passed by user no matter if previous update operation succeeded
        # or not
        group_members = get_group_resources_after_delete(
            role, role_resources, resources)
        stack_params[param_name] = str(len(group_members))

        # add instance resource names into removal_policies
        # so heat knows which instances should be removed
        removal_param = "{0}RemovalPolicies".format(role)
        stack_params[removal_param] = [{
            'resource_list': [r.resource_name for r in role_resources]
        }]

        # force reset the removal_policies_mode to 'append'
        # as 'update' can lead to deletion of unintended nodes.
        removal_mode = "{0}RemovalPoliciesMode".format(role)
        stack_params[removal_mode] = 'append'

    return stack_params


def _match_hostname(heatclient, instance_list, res, stack_name):
    type_patterns = ['DeployedServer', 'Server']
    if any(res.resource_type.endswith(x) for x in type_patterns):
        res_details = heatclient.resources.get(
            stack_name, res.resource_name)
        if 'name' in res_details.attributes:
            try:
                instance_list.remove(res_details.attributes['name'])
                return True
            except ValueError:
                return False
    return False


def remove_node_from_stack(clients, stack, nodes, timeout):
    heat = clients.orchestration
    resources = heat.resources.list(stack.stack_name,
                                    nested_depth=5)
    resources_by_role = collections.defaultdict(list)
    instance_list = list(nodes)

    for res in resources:
        stack_name, stack_id = next(
            x['href'] for x in res.links if
            x['rel'] == 'stack').rsplit('/', 2)[1:]

        try:
            instance_list.remove(res.physical_resource_id)
        except ValueError:
            if not _match_hostname(heat, instance_list,
                                   res, stack_name):
                continue

        # get resource to remove from resource group (it's parent resource
        # of nova server)
        role_resource = next(x for x in resources if
                             x.physical_resource_id == stack_id)
        # get the role name which is parent resource name in Heat
        role = role_resource.parent_resource
        resources_by_role[role].append(role_resource)

    resources_by_role = dict(resources_by_role)

    if instance_list:
        raise ValueError(
            "Couldn't find following instances in stack %s: %s" %
            (stack, ','.join(instance_list)))

    # decrease count for each role (or resource group) and set removal
    # policy for each resource group
    stack_params = _get_removal_params_from_heat(
        resources_by_role, resources)
    try:
        tht_tmp = tempfile.mkdtemp(prefix='tripleoclient-')
        tht_root = "%s/tripleo-heat-templates" % tht_tmp

        created_env_files = []
        env_path = utils.create_breakpoint_cleanup_env(
            tht_root, stack.stack_name)
        created_env_files.extend(env_path)
        param_env_path = utils.create_parameters_env(
            stack_params, tht_root, stack.stack_name,
            'scale-down-parameters.yaml')
        created_env_files.extend(param_env_path)
        env_files_tracker = []
        env_files, _ = utils.process_multiple_environments(
            created_env_files, tht_root,
            constants.TRIPLEO_HEAT_TEMPLATES,
            env_files_tracker=env_files_tracker)

        stack_args = {
            'stack_name': stack.stack_name,
            'environment_files': env_files_tracker,
            'files': env_files,
            'timeout_mins': timeout,
            'existing': True,
            'clear_parameters': list(stack_params.keys())}

        heat.stacks.update(stack.id, **stack_args)
    finally:
        shutil.rmtree(tht_tmp)
