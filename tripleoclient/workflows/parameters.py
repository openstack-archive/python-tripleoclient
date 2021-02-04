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
import yaml

from heatclient.common import template_utils
from tripleo_common.utils import stack_parameters as stk_parameters

from tripleoclient.constants import ANSIBLE_TRIPLEO_PLAYBOOKS
from tripleoclient.constants import OVERCLOUD_YAML_NAME
from tripleoclient import exceptions
from tripleoclient import utils
from tripleoclient.workflows import roles


LOG = logging.getLogger(__name__)


def invoke_plan_env_workflows(clients, stack_name, plan_env_file,
                              stack_data, role_list,
                              derived_environment_path,
                              verbosity=0):
    """Invokes the workflows in plan environment file"""

    try:
        with open(plan_env_file) as pf:
            plan_env_data = yaml.safe_load(pf.read())
    except IOError as exc:
        raise exceptions.PlanEnvWorkflowError('File (%s) is not found: '
                                              '%s' % (plan_env_file, exc))

    static_inventory = utils.get_tripleo_ansible_inventory(
        ssh_user='heat-admin',
        stack=stack_name,
        undercloud_connection='local',
        return_inventory_file_path=True
    )
    with utils.TempDirs() as tmp:
        for pb, pb_vars in plan_env_data["playbook_parameters"].items():
            print(
                'Invoking playbook ({}) specified in'
                ' plan-environment file'.format(pb)
            )
            LOG.debug(
                'Running playbook "{}" with the'
                ' following options {}.'.format(
                    pb,
                    pb_vars
                )
            )
            pb_vars['tripleo_get_flatten_params'] = {'stack_data': stack_data}
            pb_vars['tripleo_role_list'] = role_list
            pb_vars['derived_environment_path'] = derived_environment_path
            playbook_dir = os.path.dirname(pb)
            if not playbook_dir:
                playbook_dir = ANSIBLE_TRIPLEO_PLAYBOOKS

            utils.run_ansible_playbook(
                playbook=os.path.basename(pb),
                inventory=static_inventory,
                workdir=tmp,
                playbook_dir=playbook_dir,
                verbosity=verbosity,
                extra_vars=pb_vars
            )


def build_derived_params_environment(clients, stack_name,
                                     tht_root, env_files,
                                     env_files_tracker,
                                     roles_file,
                                     plan_env_file,
                                     derived_env_file,
                                     verbosity):
    template_path = os.path.join(tht_root, OVERCLOUD_YAML_NAME)
    template_files, template = template_utils.get_template_contents(
        template_file=template_path)
    files = dict(list(template_files.items()) + list(
        env_files.items()))
    # Build stack_data
    stack_data = utils.build_stack_data(
        clients, stack_name, template,
        files, env_files_tracker)

    # Get role list
    role_list = roles.get_roles(
        clients, roles_file, template, files,
        env_files_tracker, detail=False, valid=True)

    invoke_plan_env_workflows(
            clients,
            stack_name,
            plan_env_file,
            stack_data=stack_data,
            role_list=role_list,
            derived_environment_path=derived_env_file,
            verbosity=verbosity
        )


def generate_fencing_parameters(clients, nodes_json, delay, ipmi_level,
                                ipmi_cipher, ipmi_lanplus):
    """Generate and return fencing parameters.

    :param clients: application client object.
    :type clients: Object

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
        clients.baremetal,
        clients.compute,
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
