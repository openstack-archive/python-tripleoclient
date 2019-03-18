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
import shutil
import socket
import subprocess
import tempfile
import time

from heatclient.common import event_utils
from openstackclient import shell

from tripleoclient import constants
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


def wait_for_ssh_port(host):
    start = int(time.time())
    while True:
        now = int(time.time())
        if (now - start) > constants.ENABLE_SSH_ADMIN_SSH_PORT_TIMEOUT:
            raise exceptions.DeploymentError(
                "Timed out waiting for port 22 from %s" % host)
        # first check ipv4 then check ipv6
        try:
            socket.socket().connect((host, 22))
            return
        except socket.error:
            try:
                socket.socket(socket.AF_INET6).connect((host, 22))
                return
            except socket.error:
                pass

        time.sleep(1)


def get_hosts_and_enable_ssh_admin(log, clients, stack, overcloud_ssh_network,
                                   overcloud_ssh_user, overcloud_ssh_key):
    hosts = get_overcloud_hosts(stack, overcloud_ssh_network)
    if [host for host in hosts if host]:

        try:
            enable_ssh_admin(log, clients, stack.stack_name, hosts,
                             overcloud_ssh_user, overcloud_ssh_key)
        except subprocess.CalledProcessError as e:
            if e.returncode == 255:
                log.error("Couldn't not import keys to one of {}. "
                          "Check if the user/ip are corrects.\n".format(hosts))
            else:
                log.error("Unknown error. "
                          "Original message is:\n{}".format(hosts, e.message))

    else:
        raise exceptions.DeploymentError("Cannot find any hosts on '{}'"
                                         " in network '{}'"
                                         .format(stack.stack_name,
                                                 overcloud_ssh_network))


def enable_ssh_admin(log, clients, plan_name, hosts, ssh_user, ssh_key):
    print("Enabling ssh admin (tripleo-admin) for hosts:")
    print(" ".join(hosts))
    print("Using ssh user %s for initial connection." % ssh_user)
    print("Using ssh key at %s for initial connection." % ssh_key)

    ssh_options = ("-o ConnectionAttempts=6 "
                   "-o ConnectTimeout=30 "
                   "-o StrictHostKeyChecking=no "
                   "-o PasswordAuthentication=no "
                   "-o UserKnownHostsFile=/dev/null")
    tmp_key_dir = tempfile.mkdtemp()
    tmp_key_private = os.path.join(tmp_key_dir, 'id_rsa')
    tmp_key_public = os.path.join(tmp_key_dir, 'id_rsa.pub')
    tmp_key_comment = "TripleO split stack short term key"

    try:
        tmp_key_command = ["ssh-keygen", "-N", "", "-t", "rsa", "-b", "4096",
                           "-f", tmp_key_private, "-C", tmp_key_comment]
        subprocess.check_call(tmp_key_command, stderr=subprocess.STDOUT)
        tmp_key_public_contents = open(tmp_key_public).read()

        for host in hosts:
            wait_for_ssh_port(host)
            copy_tmp_key_command = ["ssh"] + ssh_options.split()
            copy_tmp_key_command += \
                ["-o", "StrictHostKeyChecking=no",
                 "-i", ssh_key, "-l", ssh_user, host,
                 "echo -e '\n%s' >> $HOME/.ssh/authorized_keys" %
                 tmp_key_public_contents]
            print("Inserting TripleO short term key for %s" % host)
            subprocess.check_call(copy_tmp_key_command,
                                  stderr=subprocess.STDOUT)

        print("Starting ssh admin enablement workflow")

        workflow_client = clients.workflow_engine

        workflow_input = {
            "ssh_user": ssh_user,
            "ssh_servers": hosts,
            "ssh_private_key": open(tmp_key_private).read(),
            "plan_name": plan_name
        }

        execution = base.start_workflow(
            workflow_client,
            'tripleo.access.v1.enable_ssh_admin',
            workflow_input=workflow_input
        )

        start = int(time.time())
        while True:
            now = int(time.time())
            if (now - start) > constants.ENABLE_SSH_ADMIN_TIMEOUT:
                raise exceptions.DeploymentError(
                    "ssh admin enablement workflow - TIMED OUT.")

            time.sleep(1)
            execution = workflow_client.executions.get(execution.id)
            state = execution.state

            if state == 'RUNNING':
                if (now - start) % constants.ENABLE_SSH_ADMIN_STATUS_INTERVAL\
                        == 0:
                    print("ssh admin enablement workflow - RUNNING.")
                continue
            elif state == 'SUCCESS':
                print("ssh admin enablement workflow - COMPLETE.")
                break
            elif state in ('FAILED', 'ERROR'):
                error = "ssh admin enablement workflow - FAILED.\n"
                error += execution.to_dict()['state_info']
                raise exceptions.DeploymentError(error)

        for host in hosts:
            rm_tmp_key_command = ["ssh"] + ssh_options.split()
            rm_tmp_key_command += \
                ["-i", ssh_key, "-l", ssh_user, host,
                 "sed -i -e '/%s/d' $HOME/.ssh/authorized_keys" %
                 tmp_key_comment]
            print("Removing TripleO short term key from %s" % host)
            subprocess.check_call(rm_tmp_key_command, stderr=subprocess.STDOUT)
    finally:
        print("Removing short term keys locally")
        shutil.rmtree(tmp_key_dir)

    print("Enabling ssh admin - COMPLETE.")


def config_download(log, clients, stack, templates,
                    ssh_user, ssh_key, ssh_network,
                    output_dir, override_ansible_cfg, timeout, verbosity=1):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    workflow_input = {
        'verbosity': verbosity or 1,
        'plan_name': stack.stack_name,
        'ssh_network': ssh_network,
        'config_download_timeout': timeout
    }
    if output_dir:
        workflow_input.update(dict(work_dir=output_dir))
    if override_ansible_cfg:
        override_ansible_cfg_contents = open(override_ansible_cfg).read()
        workflow_input.update(
            dict(override_ansible_cfg=override_ansible_cfg_contents))

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.deployment.v1.config_download_deploy',
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


def get_horizon_url(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.deployment.v1.get_horizon_url',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              360):
            assert payload['status'] == "SUCCESS"

            return payload['horizon_url']


def get_deployment_status(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.deployment.v1.get_deployment_status',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              _WORKFLOW_TIMEOUT):
            message = payload.get('message')
            if message:
                print(message)

    if payload['status'] == 'SUCCESS':
        return payload['deployment_status']
    else:
        raise exceptions.WorkflowServiceError(
            'Exception getting deployment status: {}'.format(
                payload.get('message', '')))


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
