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

import copy
import getpass
import os
import shutil
import yaml

from heatclient.common import event_utils
from heatclient import exc as heat_exc
from openstackclient import shell
from tripleo_common.utils import heat as tc_heat_utils
from tripleo_common.utils import overcloudrc as rc_utils
from tripleo_common.utils.safe_import import git

from tripleoclient.constants import ANSIBLE_TRIPLEO_PLAYBOOKS
from tripleoclient.constants import CLOUD_HOME_DIR
from tripleoclient.constants import DEFAULT_WORK_DIR
from tripleoclient import exceptions
from tripleoclient import utils


_WORKFLOW_TIMEOUT = 360  # 6 * 60 seconds


def create_overcloudrc(stack, rc_params, no_proxy='',
                       output_dir=CLOUD_HOME_DIR):
    overcloudrcs = rc_utils._create_overcloudrc(
        stack, no_proxy,
        rc_params['password'],
        rc_params['region'])
    rcpath = os.path.join(output_dir, '%src' % stack.stack_name)
    with open(rcpath, 'w') as rcfile:
        rcfile.write(overcloudrcs['overcloudrc'])
    os.chmod(rcpath, 0o600)
    return os.path.abspath(rcpath)


def deploy_without_plan(clients, stack, stack_name, template,
                        files, env_files,
                        log,
                        working_dir):
    orchestration_client = clients.orchestration
    if stack is None:
        log.info("Performing Heat stack create")
        action = 'CREATE'
        marker = None
    else:
        log.info("Performing Heat stack update")
        # Make sure existing parameters for stack are reused
        # Find the last top-level event to use for the first marker
        events = event_utils.get_events(orchestration_client,
                                        stack_id=stack_name,
                                        event_args={'sort_dir': 'desc',
                                                    'limit': 1})
        marker = events[0].id if events else None
        action = 'UPDATE'

    set_deployment_status(stack_name,
                          status='DEPLOYING',
                          working_dir=working_dir)
    stack_args = {
        'stack_name': stack_name,
        'template': template,
        'environment_files': env_files,
        'files': files}
    try:
        if stack:
            stack_args['existing'] = True
            orchestration_client.stacks.update(stack.id, **stack_args)
        else:
            stack = orchestration_client.stacks.create(**stack_args)

        print("Success.")
    except Exception:
        set_deployment_status(stack_name,
                              status='DEPLOY_FAILED',
                              working_dir=working_dir)
        raise

    create_result = utils.wait_for_stack_ready(
        orchestration_client, stack_name, marker, action)
    if not create_result:
        shell.OpenStackShell().run(["stack", "failures", "list", stack_name])
        set_deployment_status(
            stack_name,
            status='DEPLOY_FAILED',
            working_dir=working_dir
        )
        if stack is None:
            raise exceptions.DeploymentError("Heat Stack create failed.")
        else:
            raise exceptions.DeploymentError("Heat Stack update failed.")


def get_overcloud_hosts(stack, ssh_network):
    ips = []
    role_net_ip_map = utils.get_role_net_ip_map(stack)
    blacklisted_ips = utils.get_blacklisted_ip_addresses(stack)
    if not role_net_ip_map:
        raise exceptions.DeploymentError(
            'No overcloud hosts were found in the current stack.'
            ' Check the stack name and try again.'
        )
    for net_ip_map in role_net_ip_map.values():
        # get a copy of the lists of ssh_network and ctlplane ips
        # as blacklisted_ips will only be the ctlplane ips, we need
        # both lists to determine which to actually blacklist
        net_ips = copy.copy(net_ip_map.get(ssh_network, []))
        ctlplane_ips = copy.copy(net_ip_map.get('ctlplane', []))

        blacklisted_ctlplane_ips = \
            [ip for ip in ctlplane_ips if ip in blacklisted_ips]

        # for each blacklisted ctlplane ip, remove the corresponding
        # ssh_network ip at that same index in the net_ips list
        for bcip in blacklisted_ctlplane_ips:
            if not bcip:
                continue
            index = ctlplane_ips.index(bcip)
            ctlplane_ips.pop(index)
            net_ips.pop(index)

        ips.extend(net_ips)

    return ips


def get_hosts_and_enable_ssh_admin(stack, overcloud_ssh_network,
                                   overcloud_ssh_user, overcloud_ssh_key,
                                   overcloud_ssh_port_timeout,
                                   verbosity=0, heat_type='installed'):
    """Enable ssh admin access.

    Get a list of hosts from a given stack and enable admin ssh across all of
    them.

    :param stack: Stack data.
    :type stack: Object

    :param overcloud_ssh_network: Network id.
    :type overcloud_ssh_network: String

    :param overcloud_ssh_user: SSH access username.
    :type overcloud_ssh_user: String

    :param overcloud_ssh_key: SSH access key.
    :type overcloud_ssh_key: String

    :param overcloud_ssh_port_timeout: Ansible connection timeout in seconds
    :type overcloud_ssh_port_timeout: Int

    :param verbosity: Verbosity level
    :type verbosity: Integer
    """

    hosts = get_overcloud_hosts(stack, overcloud_ssh_network)
    if [host for host in hosts if host]:
        enable_ssh_admin(
            stack,
            hosts,
            overcloud_ssh_user,
            overcloud_ssh_key,
            overcloud_ssh_port_timeout,
            verbosity=verbosity,
            heat_type=heat_type
        )
    else:
        raise exceptions.DeploymentError(
            'Cannot find any hosts on "{}" in network "{}"'.format(
                stack.stack_name,
                overcloud_ssh_network
            )
        )


def enable_ssh_admin(stack, hosts, ssh_user, ssh_key, timeout,
                     verbosity=0, heat_type='installed'):
    """Run enable ssh admin access playbook.

    :param stack: Stack data.
    :type stack: Object

    :param hosts: Machines to connect to.
    :type hosts: List

    :param ssh_user: SSH access username.
    :type ssh_user: String

    :param ssh_key: SSH access key.
    :type ssh_key: String

    :param timeout: Ansible connection timeout in seconds
    :type timeout: int

    :param verbosity: Verbosity level
    :type verbosity: Integer
    """

    print(
        'Enabling ssh admin (tripleo-admin) for hosts: {}.'
        '\nUsing ssh user "{}" for initial connection.'
        '\nUsing ssh key at "{}" for initial connection.'
        '\n\nStarting ssh admin enablement playbook'.format(
            hosts,
            ssh_user,
            ssh_key
        )
    )
    try:
        if heat_type != 'installed' and tc_heat_utils.heatclient:
            tc_heat_utils.heatclient.save_environment()
        with utils.TempDirs() as tmp:
            utils.run_ansible_playbook(
                playbook='cli-enable-ssh-admin.yaml',
                inventory=','.join(hosts),
                workdir=tmp,
                playbook_dir=ANSIBLE_TRIPLEO_PLAYBOOKS,
                key=ssh_key,
                ssh_user=ssh_user,
                verbosity=verbosity,
                extra_vars={
                    "ssh_user": ssh_user,
                    "ssh_servers": hosts,
                    'tripleo_cloud_name': stack.stack_name
                },
                ansible_timeout=timeout
            )
    finally:
        if heat_type != 'installed' and tc_heat_utils.heatclient:
            tc_heat_utils.heatclient.restore_environment()
    print("Enabling ssh admin - COMPLETE.")


def config_download(log, clients, stack, ssh_network='ctlplane',
                    output_dir=None, override_ansible_cfg=None,
                    timeout=600, verbosity=0, deployment_options=None,
                    in_flight_validations=False,
                    ansible_playbook_name='deploy_steps_playbook.yaml',
                    limit_hosts=None, extra_vars=None, inventory_path=None,
                    ssh_user='tripleo-admin', tags=None, skip_tags=None,
                    deployment_timeout=None, forks=None, setup_only=False,
                    working_dir=None):
    """Run config download.

    :param log: Logging object
    :type log: Object

    :param clients: openstack clients
    :type clients: Object

    :param stack: Heat Stack object
    :type stack: Object

    :param ssh_network: Network named used to access the overcloud.
    :type ssh_network: String

    :param output_dir: Path to the output directory.
    :type output_dir: String

    :param override_ansible_cfg: Ansible configuration file location.
    :type override_ansible_cfg: String

    :param timeout: Ansible connection timeout in seconds.
    :type timeout: Integer

    :param verbosity: Ansible verbosity level.
    :type verbosity: Integer

    :param deployment_options: Additional deployment options.
    :type deployment_options: Dictionary

    :param in_flight_validations: Enable or Disable inflight validations.
    :type in_flight_validations: Boolean

    :param ansible_playbook_name: Name of the playbook to execute.
    :type ansible_playbook_name: String

    :param limit_hosts: String of hosts to limit the current playbook to.
    :type limit_hosts: String

    :param extra_vars: Set additional variables as a Dict or the absolute
                       path of a JSON or YAML file type.
    :type extra_vars: Either a Dict or the absolute path of JSON or YAML

    :param inventory_path: Inventory file or path, if None is provided this
                           function will perform a lookup
    :type inventory_path: String

    :param ssh_user: SSH user, defaults to tripleo-admin.
    :type ssh_user: String

    :param tags: Ansible inclusion tags.
    :type tags: String

    :param skip_tags: Ansible exclusion tags.
    :type skip_tags: String

    :param deployment_timeout: Deployment timeout in minutes.
    :type deployment_timeout: Integer

    :param setup_only: Only generates the config-download directory
                       without executing the actual playbooks.
    :type setup_only: Boolean

    :param working_dir: Consistent working directory used for generated
                        ansible files.
    :type working_dir: String
    """

    def _log_and_print(message, logger, level='info', print_msg=True):
        """Print and log a given message.

        :param message: Message to print and log.
        :type message: String

        :param log: Logging object
        :type log: Object

        :param level: Log level.
        :type level: String

        :param print_msg: Print messages to stdout.
        :type print_msg: Boolean
        """

        if print_msg:
            print(message)

        log = getattr(logger, level)
        log(message)

    if not output_dir:
        output_dir = DEFAULT_WORK_DIR

    if not working_dir:
        working_dir = utils.get_default_working_dir(stack.stack_name)

    if not deployment_options:
        deployment_options = dict()

    if not in_flight_validations:
        if skip_tags:
            skip_tags = 'opendev-validation,{}'.format(skip_tags)
        else:
            skip_tags = 'opendev-validation'

    with utils.TempDirs() as tmp:
        utils.run_ansible_playbook(
            playbook='cli-grant-local-access.yaml',
            inventory='localhost,',
            workdir=tmp,
            playbook_dir=ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=verbosity,
            extra_vars={
                'access_path': output_dir,
                'execution_user': getpass.getuser()
            }
        )

    _log_and_print(
        message='Checking for blacklisted hosts from stack: {}'.format(
            stack.stack_name
        ),
        logger=log,
        print_msg=(verbosity == 0)
    )
    if not limit_hosts:
        blacklist_show = stack.output_show('BlacklistedHostnames')
        blacklist_stack_output = blacklist_show.get('output', dict())
        blacklist_stack_output_value = blacklist_stack_output.get(
            'output_value')
        if blacklist_stack_output_value:
            limit_hosts = (
                ':'.join(['!{}'.format(i) for i in blacklist_stack_output_value
                          if i]))

    key_file = utils.get_key(stack.stack_name)
    python_interpreter = deployment_options.get('ansible_python_interpreter')

    playbook = 'cli-config-download.yaml'
    ansible_work_dir = os.path.join(
        working_dir, os.path.splitext(playbook)[0])
    utils.run_ansible_playbook(
        playbook='cli-config-download.yaml',
        inventory='localhost,',
        workdir=ansible_work_dir,
        playbook_dir=ANSIBLE_TRIPLEO_PLAYBOOKS,
        verbosity=verbosity,
        reproduce_command=True,
        extra_vars={
            'plan': stack.stack_name,
            'output_dir': output_dir,
            'ansible_ssh_user': ssh_user,
            'ansible_ssh_private_key_file': key_file,
            'ssh_network': ssh_network,
            'python_interpreter': python_interpreter,
            'inventory_path': inventory_path
        }
    )

    # If we only want to generate config-download directory, we can quit here.
    if setup_only:
        _log_and_print(
            message='Overcloud configuration generated for stack: {}'.format(
                stack.stack_name
            ),
            logger=log,
            print_msg=(verbosity == 0)
        )
        return

    _log_and_print(
        message='Executing deployment playbook for stack: {}'.format(
            stack.stack_name
        ),
        logger=log,
        print_msg=(verbosity == 0)
    )

    stack_work_dir = os.path.join(output_dir, stack.stack_name)
    if not inventory_path:
        inventory_path = os.path.join(stack_work_dir,
                                      'tripleo-ansible-inventory.yaml')

    if isinstance(ansible_playbook_name, list):
        playbooks = [os.path.join(stack_work_dir, p)
                     for p in ansible_playbook_name]
    else:
        playbooks = os.path.join(stack_work_dir, ansible_playbook_name)

    utils.run_ansible_playbook(
        playbook=playbooks,
        inventory=inventory_path,
        workdir=output_dir,
        playbook_dir=stack_work_dir,
        skip_tags=skip_tags,
        tags=tags,
        ansible_cfg=override_ansible_cfg,
        verbosity=verbosity,
        ssh_user=ssh_user,
        key=key_file,
        limit_hosts=limit_hosts,
        ansible_timeout=timeout,
        reproduce_command=True,
        extra_env_variables={
            'ANSIBLE_BECOME': True,
        },
        extra_vars=extra_vars,
        timeout=deployment_timeout,
        forks=forks
    )

    _log_and_print(
        message='Overcloud configuration completed for stack: {}'.format(
            stack.stack_name
        ),
        logger=log,
        print_msg=(verbosity == 0)
    )

    if os.path.exists(stack_work_dir):
        # Object to the git repository
        repo = git.Repo(stack_work_dir)

        # Configure git user.name and user.email
        git_config_user = "mistral"
        git_config_email = git_config_user + '@' + os.uname().nodename.strip()
        repo.config_writer().set_value(
            "user", "name", git_config_user
        ).release()
        repo.config_writer().set_value(
            "user", "email", git_config_email
        ).release()

        # Add and commit all files to the git repository
        repo.git.add(".")
        repo.git.commit("--amend", "--no-edit")


def get_horizon_url(stack, verbosity=0,
                    heat_type='installed',
                    working_dir=None):
    """Return horizon URL string.

    :params stack: Stack name
    :type stack: string
    :returns: string
    """

    try:
        if heat_type != 'installed' and tc_heat_utils.heatclient:
            tc_heat_utils.heatclient.save_environment()
        playbook = 'cli-undercloud-get-horizon-url.yaml'
        ansible_work_dir = os.path.join(
            working_dir, os.path.splitext(playbook)[0])
        horizon_file = os.path.join(ansible_work_dir, 'horizon_url')
        utils.run_ansible_playbook(
            playbook=playbook,
            inventory='localhost,',
            workdir=ansible_work_dir,
            playbook_dir=ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=verbosity,
            reproduce_command=True,
            extra_vars={
                'stack_name': stack,
                'horizon_url_output_file': horizon_file
            }
        )
    finally:
        if heat_type != 'installed' and tc_heat_utils.heatclient:
            tc_heat_utils.heatclient.restore_environment()

    with open(horizon_file) as f:
        return f.read().strip()


def get_deployment_status(clients, stack_name, working_dir):
    """Return current deployment status."""

    try:
        clients.orchestration.stacks.get(stack_name)
    except heat_exc.HTTPNotFound:
        return None

    try:
        status_yaml = utils.get_status_yaml(stack_name, working_dir)
        with open(status_yaml, 'r') as status_stream:
            return yaml.safe_load(status_stream)['deployment_status']
    except Exception:
        return None


def set_deployment_status(stack_name, status, working_dir):
    utils.update_deployment_status(
        stack_name=stack_name,
        status=status,
        working_dir=working_dir)


def make_config_download_dir(config_download_dir, stack):
    utils.makedirs(config_download_dir)
    utils.makedirs(DEFAULT_WORK_DIR)
    # Symlink for the previous default config-download dir to the
    # new consistent location.
    # This will create the following symlink:
    # ~/config-download/<stack> ->
    # ~/overcloud-deploy/<stack>/config-download/<stack>
    old_config_download_stack_dir = \
        os.path.join(DEFAULT_WORK_DIR, stack)
    new_config_download_stack_dir = \
        os.path.join(config_download_dir, stack)

    if os.path.islink(old_config_download_stack_dir):
        return

    # Migrate the old directory to the new, if the new does not yet exist
    if (os.path.isdir(old_config_download_stack_dir) and
            not os.path.exists(new_config_download_stack_dir)):
        shutil.move(old_config_download_stack_dir,
                    new_config_download_stack_dir)

    # Remove everything at the old path
    if os.path.exists(old_config_download_stack_dir):
        shutil.rmtree(old_config_download_stack_dir,
                      ignore_errors=True)

    # Symlink the old path to the new tree for backwards compatibility
    os.symlink(new_config_download_stack_dir,
               old_config_download_stack_dir)
