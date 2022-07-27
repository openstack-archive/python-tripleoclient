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
import os
import re
import yaml

from tripleo_common.utils import stack_parameters as stk_parameters

from tripleoclient.constants import UNUSED_PARAMETER_EXCLUDES_RE
from tripleoclient import exceptions
from tripleoclient import utils
from tripleoclient.workflows import roles


LOG = logging.getLogger(__name__)


def check_deprecated_parameters(clients, stack_name, template, files,
                                env_files_tracker, working_dir):
    """Checks for deprecated parameters and adds warning if present.

    :param clients: application client object.
    :type clients: Object
    :param stack_neme: Heat stack name
    :type stack_name: String
    :param template:
    :type template: String
    :param files:
    :type files:
    :param env_files_tracker:
    :type env_files_tracker:
    :param working_dir: Tripleo working directory
    :type working_dir: String
    """

    # Get role list
    role_list = roles.get_roles(clients, stack_name, template, files,
                                env_files_tracker, working_dir,
                                detail=False,
                                valid=True)

    # Build stack_data
    stack_data = utils.build_stack_data(
        clients, stack_name, template,
        files, env_files_tracker)
    user_params = stack_data.get('environment_parameters', {})
    heat_resource_tree = stack_data.get('heat_resource_tree', {})
    heat_resource_tree_params = heat_resource_tree.get('parameters', {})
    heat_resource_tree_resources = heat_resource_tree.get('resources', {})
    all_params = heat_resource_tree_params.keys()
    parameter_groups = [
        i.get('parameter_groups')
        for i in heat_resource_tree_resources.values()
        if i.get('parameter_groups')
    ]
    params_role_specific_tag = [
        i.get('name')
        for i in heat_resource_tree_params.values()
        if 'tags' in i and 'role_specific' in i['tags']
    ]

    r = re.compile(".*Count")
    filtered_names = list(filter(r.match, all_params))
    valid_role_name_list = list()
    for name in filtered_names:
        default = heat_resource_tree_params[name].get('default', 0)
        if default and int(default) > 0:
            role_name = name.rstrip('Count')
            if [i for i in role_list if i == role_name]:
                valid_role_name_list.append(role_name)

    deprecated_params = [
        i[0] for i in parameter_groups
        if i[0].get('label') == 'deprecated'
    ]
    # We are setting a frozenset here because python 3 complains that dict is
    # a unhashable type.
    # On user_defined, we check if the size is higher than 0 because an empty
    # frozenset still is a subset of a frozenset, so we can't use issubset
    # here.
    user_params_keys = frozenset(user_params.keys())
    deprecated_result = [
        {
            'parameter': i,
            'deprecated': True,
            'user_defined': len(
                [x for x in frozenset(i) if x in user_params_keys]) > 0
        }
        for i in deprecated_params
    ]
    unused_params = [i for i in user_params.keys() if i not in all_params]
    user_provided_role_specific = [
        v for i in role_list
        for k, v in user_params.items()
        if k in i
    ]
    invalid_role_specific_params = [
        i for i in user_provided_role_specific
        if i in params_role_specific_tag
    ]
    deprecated_parameters = [
        param['parameter'] for param in deprecated_result
        if param.get('user_defined')
    ]

    if deprecated_parameters:
        deprecated_join = ', '.join(deprecated_parameters)
        LOG.warning(
            'WARNING: Following parameter(s) are deprecated and still '
            'defined. Deprecated parameters will be removed soon!'
            ' {deprecated_join}'.format(
                deprecated_join=deprecated_join
            )
        )

    # exclude our known params that may not be used
    ignore_re = re.compile('|'.join(UNUSED_PARAMETER_EXCLUDES_RE))
    unused_params = [p for p in unused_params if not ignore_re.search(p)]

    if unused_params:
        unused_join = ', '.join(unused_params)
        LOG.warning(
            'WARNING: Following parameter(s) are defined but not '
            'currently used. These parameters '
            'may be valid but not in use due to the service or '
            'deployment configuration.'
            ' {unused_join}'.format(
                unused_join=unused_join
            )
        )

    if invalid_role_specific_params:
        invalid_join = ', '.join(invalid_role_specific_params)
        LOG.warning(
            'WARNING: Following parameter(s) are not supported as '
            'role-specific inputs. {invalid_join}'.format(
                invalid_join=invalid_join
            )
        )


def generate_fencing_parameters(nodes_json, delay, ipmi_level,
                                ipmi_cipher, ipmi_lanplus):
    """Generate and return fencing parameters.

    :param nodes_json: list of nodes & attributes in json format
    :type nodes_json: List

    :param delay: time to wait before taking fencing action
    :type delay: Integer

    :param ipmi_level: IPMI user level to use
    :type ipmi_level: String

    :param ipmi_cipher: IPMI cipher suite to use
    :type ipmi_cipher: String

    :param ipmi_lanplus: whether to use IPMIv2.0
    :type ipmi_lanplus: Boolean

    :returns: Dictionary
    """
    return stk_parameters.generate_fencing_parameters(
        nodes_json=nodes_json,
        delay=delay,
        ipmi_level=ipmi_level,
        ipmi_cipher=ipmi_cipher,
        ipmi_lanplus=ipmi_lanplus)


def check_forbidden_params(log, env_files, forbidden):
    """Looks for undesired parameters in the environment files.

    Each of the environment files pass in env_files will be parsed
    and if the parameters_default key is found, then all the keys
    from the nested dictionary found under will be converted into
    a list, for example:

    parameters_default:
        key1: value1
        key2: value2
        key3:
          - value3
          - key31:
              key311: value311
              key312: value312
            key32: value32

    Will be converted by get_all_keys into:
    [key1, key2, key3, key31, key311, key312, key32]

    This list provides us with all the parameters used in the environment
    file, without the values, in the format of a list. So we can use sets
    to find occurrences of the forbbiden paramenters.

    The variable matched_params will get all the ocurrences of forbidden
    parameters stored, so we can parse all the environment files and show
    all the parameters which should get removed from the environment files
    at once (saving the user to run the command, modify a template, run it
    again, modify another, etc...). If matched_params list is not empty,
    an exception will be raised, stopping the execution of the command and
    displaying the commands which need to be removed.

    :param log: logging object passed from the calling method
    :type log: Logging object
    :param env_files: list of the environment files passed in the command
    :type env_files: list of strings
    :param forbidden: list of the undesired parameters
    :type forbidden: list of strings

    :returns exception if some of the forbidden parameters are found in
    the environment files.
    """

    # Iterates over a nested dict and returns all the
    # keys from the dict in a list
    # example:
    #   * input: {'a': '1', 'b': ['c': '2', 'd': {'e': '3'}]}
    #   * output: ['a', 'b', 'c', 'd', 'e']
    def get_all_keys(obj, keys_list):
        if isinstance(obj, dict):
            keys_list += obj.keys()
            for value in obj.values():
                get_all_keys(value, keys_list)
        elif isinstance(obj, list):
            for value in obj:
                get_all_keys(value, keys_list)

    matched_params = []

    for file in env_files:
        if os.path.exists(file):
            with open(file, 'r') as env_file:
                contents = yaml.safe_load(env_file)
                pd = contents.get('parameter_defaults', {})
                if pd:
                    # Intersection of values and forbidden params
                    list_of_keys = []
                    get_all_keys(pd, list_of_keys)
                    found_in_pd = list(set(list_of_keys) & set(forbidden))

                    # Combine them without duplicates
                    matched_params = list(set(matched_params + found_in_pd))

    if matched_params:
        raise exceptions.BannedParameters("The following parameters should be "
                                          "removed from the environment files:"
                                          "\n{}\n"
                                          .format('\n'.join(matched_params)))
