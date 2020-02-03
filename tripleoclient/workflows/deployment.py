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
from __future__ import print_function

import copy
import os
import pprint
import time
import yaml

from heatclient.common import event_utils
from openstackclient import shell
from tripleo_common.actions import deployment

from tripleoclient.constants import ANSIBLE_TRIPLEO_PLAYBOOKS
from tripleoclient import exceptions
from tripleoclient import utils

from tripleoclient.workflows import base


_WORKFLOW_TIMEOUT = 360  # 6 * 60 seconds


def deploy(log, clients, **workflow_input):

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient
    wf_name = 'tripleo.deployment.v1.deploy_plan'

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            wf_name,
            workflow_input=workflow_input
        )

        # The deploy workflow ends once the Heat create/update starts. This
        # means that is shouldn't take very long. Wait for 10 minutes for
        # messages from the workflow.
        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              600):
            status = payload.get('status', 'RUNNING')
            message = payload.get('message')
            if message and status == "RUNNING":
                print(message)

        if payload['status'] != "SUCCESS":
            log.info(pprint.pformat(payload))
            print(payload['message'])
            raise ValueError("Unexpected status %s for %s"
                             % (payload['status'], wf_name))


def deploy_and_wait(log, clients, stack, plan_name, verbose_level,
                    timeout=None, run_validations=False,
                    skip_deploy_identifier=False, deployment_options={}):
    """Start the deploy and wait for it to finish"""

    workflow_input = {
        "container": plan_name,
        "run_validations": run_validations,
        "skip_deploy_identifier": skip_deploy_identifier,
        "deployment_options": deployment_options,
    }

    if timeout is not None:
        workflow_input['timeout'] = timeout

    deploy(log, clients, **workflow_input)

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
                                        stack_id=plan_name,
                                        event_args={'sort_dir': 'desc',
                                                    'limit': 1})
        marker = events[0].id if events else None
        action = 'UPDATE'

    time.sleep(10)
    verbose_events = verbose_level >= 1
    create_result = utils.wait_for_stack_ready(
        orchestration_client, plan_name, marker, action, verbose_events)
    if not create_result:
        shell.OpenStackShell().run(["stack", "failures", "list", plan_name])
        set_deployment_status(clients, 'failed', plan=plan_name)
        if stack is None:
            raise exceptions.DeploymentError("Heat Stack create failed.")
        else:
            raise exceptions.DeploymentError("Heat Stack update failed.")


def create_overcloudrc(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.deployment.v1.create_overcloudrc',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            # the workflow will return the overcloudrc data, an error message
            # or blank.
            if payload.get('status') == 'SUCCESS':
                return payload.get('message')
            else:
                raise exceptions.WorkflowServiceError(
                    'Exception creating overcloudrc: {}'.format(
                        payload.get('message')))


def get_overcloud_hosts(stack, ssh_network):
    ips = []
    role_net_ip_map = utils.get_role_net_ip_map(stack)
    blacklisted_ips = utils.get_blacklisted_ip_addresses(stack)
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
            index = ctlplane_ips.index(bcip)
            ctlplane_ips.pop(index)
            net_ips.pop(index)

        ips.extend(net_ips)

    return ips


def get_hosts_and_enable_ssh_admin(stack, overcloud_ssh_network,
                                   overcloud_ssh_user, overcloud_ssh_key,
                                   overcloud_ssh_port_timeout):
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

    :param overcloud_ssh_port_timeout: Ansible connection timeout
    :type overcloud_ssh_port_timeout: Int
    """

    hosts = get_overcloud_hosts(stack, overcloud_ssh_network)
    if [host for host in hosts if host]:
        enable_ssh_admin(
            stack,
            hosts,
            overcloud_ssh_user,
            overcloud_ssh_key,
            overcloud_ssh_port_timeout
        )
    else:
        raise exceptions.DeploymentError(
            'Cannot find any hosts on "{}" in network "{}"'.format(
                stack.stack_name,
                overcloud_ssh_network
            )
        )


def enable_ssh_admin(stack, hosts, ssh_user, ssh_key, timeout):
    """Run enable ssh admin access playbook.

    :param stack: Stack data.
    :type stack: Object

    :param hosts: Machines to connect to.
    :type hosts: List

    :param ssh_user: SSH access username.
    :type ssh_user: String

    :param ssh_key: SSH access key.
    :type ssh_key: String

    :param timeout: Ansible connection timeout
    :type timeout: int
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
    with utils.TempDirs() as tmp:
        utils.run_ansible_playbook(
            playbook='cli-enable-ssh-admin.yaml',
            inventory=','.join(hosts),
            workdir=tmp,
            playbook_dir=ANSIBLE_TRIPLEO_PLAYBOOKS,
            key=ssh_key,
            ssh_user=ssh_user,
            extra_vars={
                "ssh_user": ssh_user,
                "ssh_servers": hosts,
                'tripleo_cloud_name': stack.stack_name
            },
            ansible_timeout=timeout
        )
    print("Enabling ssh admin - COMPLETE.")


def config_download(log, clients, stack, templates,
                    ssh_user, ssh_key, ssh_network,
                    output_dir, override_ansible_cfg, timeout, verbosity=0,
                    deployment_options={},
                    in_flight_validations=False):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    if in_flight_validations:
        skip_tags = ''
    else:
        skip_tags = 'opendev-validation'

    workflow_input = {
        'verbosity': verbosity,
        'plan_name': stack.stack_name,
        'ssh_network': ssh_network,
        'config_download_timeout': timeout,
        'deployment_options': deployment_options,
        'skip_tags': skip_tags
    }
    if output_dir:
        workflow_input.update(dict(work_dir=output_dir))
    if override_ansible_cfg:
        with open(override_ansible_cfg) as cfg:
            override_ansible_cfg_contents = cfg.read()
        workflow_input.update(
            dict(override_ansible_cfg=override_ansible_cfg_contents))

    workflow_name = 'tripleo.deployment.v1.config_download_deploy'

    # Check to see if any existing executions for the same stack are already in
    # progress.
    log.info("Checking for existing executions of config_download for "
             "%s" % stack.stack_name)
    for execution in workflow_client.executions.find(
            workflow_name=workflow_name,
            state='RUNNING'):

        try:
            exec_input = yaml.safe_load(execution.input)
        except yaml.YAMLError as ye:
            log.error("YAML error loading input for execution %s: %s" %
                      (execution.id, str(ye)))
            raise

        if exec_input.get('plan_name', 'overcloud') == stack.stack_name:
            raise exceptions.ConfigDownloadInProgress(execution.id,
                                                      stack.stack_name)

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            workflow_name,
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution):
            print(payload['message'])

    if payload['status'] == 'SUCCESS':
        print("Overcloud configuration completed.")
    else:
        raise exceptions.DeploymentError("Overcloud configuration failed.")


def config_download_export(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.deployment.v1.config_download_export',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              _WORKFLOW_TIMEOUT):
            message = payload.get('message')
            if message:
                print(message)

    if payload['status'] == 'SUCCESS':
        return payload['tempurl']
    else:
        raise exceptions.WorkflowServiceError(
            'Exception exporting config-download: {}'.format(
                payload['message']))


def get_horizon_url(stack):
    """Return horizon URL string.

    :params stack: Stack name
    :type stack: string
    :returns: string
    """

    with utils.TempDirs() as tmp:
        horizon_tmp_file = os.path.join(tmp, 'horizon_url')
        utils.run_ansible_playbook(
            playbook='cli-undercloud-get-horizon-url.yaml',
            inventory='localhost,',
            workdir=tmp,
            playbook_dir=ANSIBLE_TRIPLEO_PLAYBOOKS,
            extra_vars={
                'stack_name': stack,
                'horizon_url_output_file': horizon_tmp_file
            }
        )

        with open(horizon_tmp_file) as f:
            return f.read().strip()


def get_deployment_status(clients, plan):
    """Return current deployment status.

    :param clients: application client object.
    :type clients: Object

    :param plan: Plan name.
    :type plan: String

    :returns: string
    """

    context = clients.tripleoclient.create_mistral_context()
    get_deployment_status = deployment.DeploymentStatusAction(plan=plan)
    status = get_deployment_status.run(context=context)
    status_update = status.get('status_update')
    deployment_status = status.get('deployment_status')
    if status_update:
        utils.update_deployment_status(
            clients=clients,
            plan=plan,
            status=status
        )
        return status_update, plan
    else:
        return deployment_status, plan


def set_deployment_status(clients, status='success', **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    if status == 'success':
        workflow = 'tripleo.deployment.v1.set_deployment_status_success'
    elif status == 'failed':
        workflow = 'tripleo.deployment.v1.set_deployment_status_failed'
    elif status == 'deploying':
        workflow = 'tripleo.deployment.v1.set_deployment_status_deploying'
    else:
        raise Exception("Can't set unknown deployment status: %s" % status)

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            workflow,
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              _WORKFLOW_TIMEOUT):
            # Just continue until workflow is done
            continue

    if payload['status'] != 'SUCCESS':
        raise exceptions.WorkflowServiceError(
            'Exception setting deployment status: {}'.format(
                payload.get('message', '')))


def get_deployment_failures(clients, **workflow_input):
    workflow_client = clients.workflow_engine

    result = base.call_action(
        workflow_client,
        'tripleo.deployment.get_deployment_failures',
        **workflow_input
    )

    message = result.get('message')
    if message:
        print(message)

    return result['failures']
