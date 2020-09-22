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
import tempfile
import yaml

from swiftclient import exceptions as swift_exc
from tripleo_common.actions import plan
from tripleo_common.utils import plan as plan_utils
from tripleo_common.utils import swift as swiftutils
from tripleo_common.utils import tarball

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils

LOG = logging.getLogger(__name__)
# Plan management workflows should generally be quick. However, the creation
# of the default plan in instack has demonstrated that sometimes it can take
# several minutes. The previous timeout of 6 minutes from Instack does not
# seem to be sufficient anymore. Bumping this to 20 minutes. It doesn't mean
# that it will take 20 minutes, but just that the listen for completion will
# timeout after 20 minutes. If it takes longer than that, something is really
# wrong.
_WORKFLOW_TIMEOUT = 20 * 60  # 20 minutes * 60 seconds


def _upload_templates(swift_client, container_name, tht_root, roles_file=None,
                      plan_env_file=None, networks_file=None):
    """tarball up a given directory and upload it to Swift to be extracted"""

    with tempfile.NamedTemporaryFile() as tmp_tarball:
        tarball.create_tarball(tht_root, tmp_tarball.name)
        tarball.tarball_extract_to_swift_container(
            swift_client, tmp_tarball.name, container_name)

    # Optional override of the roles_data.yaml file
    if roles_file:
        _upload_file(swift_client, container_name,
                     constants.OVERCLOUD_ROLES_FILE,
                     utils.rel_or_abs_path(roles_file, tht_root))

    # Optional override of the network_data.yaml file
    if networks_file:
        _upload_file(swift_client, container_name,
                     constants.OVERCLOUD_NETWORKS_FILE, networks_file)

    # Optional override of the plan-environment.yaml file
    if plan_env_file:
        # TODO(jpalanis): Instead of overriding default file,
        # merging the user override plan-environment with default
        # plan-environment file will avoid explict merging issues.
        _upload_file(swift_client, container_name,
                     constants.PLAN_ENVIRONMENT, plan_env_file)


def create_deployment_plan(container, generate_passwords,
                           use_default_templates=False, source_url=None,
                           validate_stack=True, verbosity_level=0,
                           plan_env_file=None,
                           disable_image_params_prepare=False):
    extra_vars = {
        "container": container,
        "validate": validate_stack,
        "generate_passwords": generate_passwords,
        "disable_image_params_prepare": disable_image_params_prepare
    }

    if plan_env_file:
        extra_vars['plan_environment'] = plan_env_file

    with utils.TempDirs() as tmp:
        utils.run_ansible_playbook(
            "cli-create-deployment-plan.yaml",
            'undercloud,',
            workdir=tmp,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars=extra_vars,
            verbosity=verbosity_level
        )

    print("Success.")


def delete_deployment_plan(clients, container):
    """Delete a deployment plan.

    :param clients: Application client object.
    :type clients: Object

    :param container: Container name to pull from.
    :type container: String
    """

    context = clients.tripleoclient.create_mistral_context()
    result = plan.DeletePlanAction(container=container).run(context=context)
    # The action returns None if there are no errors.
    if result:
        raise RuntimeError(result)


def update_deployment_plan(clients, verbosity_level=0,
                           disable_image_params_prepare=False,
                           **workflow_input):
    with utils.TempDirs() as tmp:
        utils.run_ansible_playbook(
            "cli-update-deployment-plan.yaml",
            'undercloud,',
            workdir=tmp,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                "container": workflow_input['container'],
                "validate": workflow_input['validate_stack'],
                "generate_passwords": workflow_input["generate_passwords"],
                "disable_image_params_prepare": disable_image_params_prepare
            },
            verbosity=verbosity_level
        )

    print("Success.")


def list_deployment_plans(clients):
    mistral_context = clients.tripleoclient.create_mistral_context()
    return plan.ListPlansAction().run(mistral_context)


def create_plan_from_templates(clients, name, tht_root, roles_file=None,
                               generate_passwords=True, plan_env_file=None,
                               networks_file=None, validate_stack=True,
                               verbosity_level=0,
                               disable_image_params_prepare=False):
    swift_client = clients.tripleoclient.object_store

    print("Creating Swift container to store the plan")
    plan_utils.create_plan_container(swift_client, name)

    print("Creating plan from template files in: {}".format(tht_root))
    _upload_templates(swift_client, name, tht_root,
                      utils.rel_or_abs_path(roles_file, tht_root),
                      plan_env_file, networks_file)

    try:
        create_deployment_plan(
            container=name,
            generate_passwords=generate_passwords,
            plan_env_file=plan_env_file,
            validate_stack=validate_stack,
            verbosity_level=verbosity_level,
            disable_image_params_prepare=disable_image_params_prepare)
    except exceptions.WorkflowServiceError:
        swiftutils.delete_container(swift_client, name)
        raise


def update_plan_from_templates(clients, name, tht_root, roles_file=None,
                               generate_passwords=True, plan_env_file=None,
                               networks_file=None, keep_env=False,
                               validate_stack=True, verbosity_level=1,
                               disable_image_params_prepare=False):
    swift_client = clients.tripleoclient.object_store
    passwords = None
    keep_file_contents = {}
    roles_file = utils.rel_or_abs_path(roles_file, tht_root)

    if keep_env:
        # Dict items are (remote_name, local_name). local_name may be
        # None in which case we only try to load from Swift (remote).
        keep_map = {
            constants.PLAN_ENVIRONMENT: plan_env_file,
            constants.USER_ENVIRONMENT: None,
            constants.OVERCLOUD_ROLES_FILE: roles_file,
            constants.OVERCLOUD_NETWORKS_FILE: networks_file,
        }
        # Also try to fetch any files under 'user-files/'
        # dir. local_name is always None for these
        keep_map.update(dict(map(
            lambda path: (path, None),
            _list_user_files(swift_client, name))))
        keep_file_contents = _load_content_or_file(
            swift_client, name, keep_map)
    else:
        passwords = _load_passwords(swift_client, name)

    # TODO(dmatthews): Removing the existing plan files should probably be
    #                  a Mistral action.
    print("Removing the current plan files")
    swiftutils.empty_container(swift_client, name)

    # Until we have a well defined plan update workflow in
    # tripleo-common we need to manually reset the environments and
    # parameter_defaults here. This is to ensure that no environments
    # are in the plan environment but not actually in swift.
    # See bug: https://bugs.launchpad.net/tripleo/+bug/1623431
    #
    # Currently this is being done incidentally because we overwrite
    # the existing plan-environment.yaml with the skeleton one in THT
    # when updating the templates. Once LP#1623431 is resolved we may
    # need to special-case plan-environment.yaml to avoid this.

    print("Uploading new plan files")
    if keep_env:
        _upload_templates(swift_client, name, tht_root)
        for filename in keep_file_contents:
            _upload_file_content(swift_client, name, filename,
                                 keep_file_contents[filename])
    else:
        _upload_templates(swift_client, name, tht_root, roles_file,
                          plan_env_file, networks_file)
        _update_passwords(swift_client, name, passwords)

    update_deployment_plan(
        clients, container=name,
        generate_passwords=generate_passwords,
        source_url=None,
        validate_stack=validate_stack,
        verbosity_level=verbosity_level,
        disable_image_params_prepare=disable_image_params_prepare)


def _load_content_or_file(swift_client, container, remote_and_local_map):
    # mapping (remote_name, content)
    file_contents = {}

    plan_files = _list_plan_files(swift_client, container)

    for remote_name in remote_and_local_map:
        LOG.debug("Attempting to load {0}".format(remote_name))
        local_name = remote_and_local_map[remote_name]
        # it's possible that the file doesn't exist in Swift and isn't
        # passed on filesystem, in which case we won't do anything
        content = None
        # local override takes priority
        if local_name:
            LOG.debug("Using provided file {0}".format(local_name))
            with open(os.path.abspath(local_name)) as local_content:
                content = local_content.read()
        elif remote_name in plan_files:
            LOG.debug("Preserving plan file {0}".format(remote_name))
            content = swift_client.get_object(container, remote_name)[1]

        if content:
            file_contents[remote_name] = content

    return file_contents


def _list_user_files(swift_client, container):
    return list(filter(lambda path: path.startswith('user-files/'),
                       _list_plan_files(swift_client, container)))


def _list_plan_files(swift_client, container):
    return list(map(lambda i: i['name'],
                    swift_client.get_container(
                        container, full_listing=True)[1]))


def _upload_file(swift_client, container, filename, local_filename):
    with open(local_filename, 'rb') as file_content:
        swift_client.put_object(container, filename, file_content)


# short function, just alias for interface parity with _upload_plan_file
def _upload_file_content(swift_client, container, filename, content):
    LOG.debug("Uploading {0} to plan".format(filename))
    swift_client.put_object(container, filename, content)


def _load_passwords(swift_client, name):
    plan_env = yaml.safe_load(swift_client.get_object(
        name, constants.PLAN_ENVIRONMENT)[1])

    if "passwords" in plan_env:
        return plan_env['passwords']
    else:
        LOG.warn("No passwords found in existing plan {}. "
                 "Updating plan with passwords.".format(name))


def _update_passwords(swift_client, name, passwords):
    # Update the plan environment with the generated passwords. This
    # will be solved more elegantly once passwords are saved in a
    # separate environment (https://review.opendev.org/#/c/467909/)
    if passwords:
        try:
            env = yaml.safe_load(swift_client.get_object(
                name, constants.PLAN_ENVIRONMENT)[1])
            env['passwords'] = passwords
            swift_client.put_object(name,
                                    constants.PLAN_ENVIRONMENT,
                                    yaml.safe_dump(env,
                                                   default_flow_style=False))
        except swift_exc.ClientException:
            # The plan likely has not been migrated to using Swift yet.
            LOG.debug("Could not find plan environment %s in %s",
                      constants.PLAN_ENVIRONMENT, name)


def export_deployment_plan(clients, plan_name):

    export_container = "plan-exports"
    delete_after = 3600

    mistral_context = clients.tripleoclient.create_mistral_context()
    action = plan.ExportPlanAction(plan_name, delete_after=delete_after,
                                   exports_container=export_container)
    result = action.run(mistral_context)
    if result:
        raise exceptions.WorkflowServiceError(
            'Exception exporting plan: {}'.format(result.error))

    url = swiftutils.get_temp_url(clients.tripleoclient.object_store,
                                  container=export_container,
                                  object_name="{}.tar.gz".format(plan_name))
    print(url)
    return url
