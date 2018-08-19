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
        # means that is shouldn't take very long. Wait for six minutes for
        # messages from the workflow.
        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              360):
            status = payload.get('status', 'RUNNING')
            if 'message' in payload and status == "RUNNING":
                print(payload['message'])

        if payload['status'] != "SUCCESS":
            log.info(pprint.pformat(payload))
            print(payload['message'])
            raise ValueError("Unexpected status %s for %s"
                             % (payload['status'], wf_name))


def deploy_and_wait(log, clients, stack, plan_name, verbose_level,
                    timeout=None, run_validations=False,
                    skip_deploy_identifier=False):
    """Start the deploy and wait for it to finish"""

    workflow_input = {
        "container": plan_name,
        "run_validations": run_validations,
        "skip_deploy_identifier": skip_deploy_identifier
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
        if stack is None:
            raise exceptions.DeploymentError("Heat Stack create failed.")
        else:
            raise exceptions.DeploymentError("Heat Stack update failed.")


def create_overcloudrc(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    execution = base.start_workflow(
        workflow_client,
        'tripleo.deployment.v1.create_overcloudrc',
        workflow_input=workflow_input
    )

    with tripleoclients.messaging_websocket() as ws:
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
    for net_ip_map in role_net_ip_map.values():
        ips.extend(net_ip_map.get(ssh_network, []))

    return ips


def wait_for_ssh_port(host):
    start = int(time.time())
    while True:
        now = int(time.time())
        if (now - start) > constants.ENABLE_SSH_ADMIN_SSH_PORT_TIMEOUT:
            raise exceptions.DeploymentError(
                "Timed out waiting for port 22 from %s" % host)

        try:
            socket.socket().connect((host, 22))
            return
        except socket.error:
            pass

        time.sleep(1)


def enable_ssh_admin(log, clients, hosts, ssh_user, ssh_key):
    print("Enabling ssh admin (tripleo-admin) for hosts:")
    print(" ".join(hosts))
    print("Using ssh user %s for initial connection." % ssh_user)
    print("Using ssh key at %s for initial connection." % ssh_key)

    ssh_options = ("-o ConnectionAttempts=6 "
                   "-o ConnectTimeout=30 "
                   "-o StrictHostKeyChecking=no "
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
                    ssh_user, ssh_key, ssh_network, output_dir, verbosity=1):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    workflow_input = {
        'verbosity': verbosity or 1,
        'plan_name': stack.stack_name,
        'ssh_network': ssh_network
    }
    if output_dir:
        workflow_input.update(dict(work_dir=output_dir))

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.deployment.v1.config_download_deploy',
            workflow_input=workflow_input
        )

        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              3600):
            print(payload['message'])

    if payload['status'] == 'SUCCESS':
        print("Overcloud configuration completed.")
    else:
        raise exceptions.DeploymentError("Overcloud configuration failed.")


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

    execution = base.start_workflow(
        workflow_client,
        'tripleo.deployment.v1.get_deployment_status',
        workflow_input=workflow_input
    )

    with tripleoclients.messaging_websocket() as ws:
        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              _WORKFLOW_TIMEOUT):
            if 'message' in payload:
                print(payload['message'])

    if payload['status'] == 'SUCCESS':
        return payload['deployment_status']
    else:
        raise exceptions.WorkflowServiceError(
            'Exception getting deployment status: {}'.format(
                payload.get('message', '')))


def get_deployment_failures(clients, **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    execution = base.start_workflow(
        workflow_client,
        'tripleo.deployment.v1.get_deployment_failures',
        workflow_input=workflow_input
    )

    with tripleoclients.messaging_websocket() as ws:
        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              _WORKFLOW_TIMEOUT):
            if 'message' in payload:
                print(payload['message'])

    if payload['status'] == 'SUCCESS':
        return payload['deployment_failures']['failures']
    else:
        raise exceptions.WorkflowServiceError(
            'Exception getting deployment failures: {}'.format(
                payload.get('message', '')))
