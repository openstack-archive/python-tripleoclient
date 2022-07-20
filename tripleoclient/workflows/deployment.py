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
import yaml

from heatclient.common import event_utils
from mistralclient.api import base as mistralclient_exc
from openstackclient import shell
import six
import tenacity

from tripleoclient.constants import ENABLE_SSH_ADMIN_SSH_PORT_TIMEOUT
from tripleoclient.constants import ENABLE_SSH_ADMIN_STATUS_INTERVAL
from tripleoclient.constants import ENABLE_SSH_ADMIN_TIMEOUT
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
        # means that is shouldn't take very long. Wait 20 minutes for
        # complection because this also includes some container image prepare
        # generation which may reach out to an external resource.
        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              1200):
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
    working_dir = utils.get_default_working_dir(plan_name)
    if not create_result:
        shell.OpenStackShell().run(["stack", "failures", "list", plan_name])
        set_deployment_status(clients, 'DEPLOY_FAILED',
                              working_dir=working_dir,
                              plan=plan_name)
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


def wait_for_ssh_port(host, timeout=ENABLE_SSH_ADMIN_SSH_PORT_TIMEOUT):
    start = int(time.time())
    while True:
        now = int(time.time())
        if (now - start) > timeout:
            raise exceptions.DeploymentError(
                "Timed out waiting for port 22 from %s" % host)
        # first check ipv4 then check ipv6
        try:
            sock = socket.socket()
            sock.connect((host, 22))
            sock.close()
            return
        except socket.error:
            try:
                # close previous socket before creating a new one
                sock.close()
                sock = socket.socket(socket.AF_INET6)
                sock.connect((host, 22))
                sock.close()
                return
            except socket.error:
                sock.close()

        time.sleep(1)


def get_hosts_and_enable_ssh_admin(
        log, clients, stack, overcloud_ssh_network, overcloud_ssh_user,
        overcloud_ssh_key, enable_ssh_timeout=ENABLE_SSH_ADMIN_TIMEOUT,
        enable_ssh_port_timeout=ENABLE_SSH_ADMIN_SSH_PORT_TIMEOUT):
    hosts = get_overcloud_hosts(stack, overcloud_ssh_network)
    mc = clients.workflow_engine
    key = utils.get_key(stack=stack.stack_name, needs_pair=True)
    if key:
        with open('{}.pub'.format(key), 'rt') as fp:
            pub_ssh_key = fp.read()
        with open('{}'.format(key), 'rt') as fp:
            priv_ssh_key = fp.read()
        try:
            mc.environments.get('ssh_keys').variables
            mc.environments.update(name='ssh_keys',
                                   variables={'public_key': pub_ssh_key,
                                              'private_key': priv_ssh_key})
        except mistralclient_exc.APIException:
            mc.environments.create(name='ssh_keys',
                                   variables={'public_key': pub_ssh_key,
                                              'private_key': priv_ssh_key})
    if [host for host in hosts if host]:
        try:
            enable_ssh_admin(log, clients, stack.stack_name, hosts,
                             overcloud_ssh_user, overcloud_ssh_key,
                             enable_ssh_timeout, enable_ssh_port_timeout)
        except (subprocess.CalledProcessError,
                tenacity.RetryError) as e:
            log.error("Could not import keys to one of {}. "
                      "Original error message: {}\n".format(
                          hosts, six.text_type(e)))
            raise

    else:
        raise exceptions.DeploymentError("Cannot find any hosts on '{}'"
                                         " in network '{}'"
                                         .format(stack.stack_name,
                                                 overcloud_ssh_network))


@tenacity.retry(
    retry=tenacity.retry_if_exception_message(match="^.*exit status 255.*$"),
    wait=tenacity.wait_exponential(multiplier=1, max=60),
    stop=tenacity.stop_after_attempt(10))
def copy_temp_key(command):
    subprocess.check_call(command, stderr=subprocess.STDOUT)


def enable_ssh_admin(log, clients, plan_name, hosts, ssh_user, ssh_key,
                     enable_ssh_timeout=ENABLE_SSH_ADMIN_TIMEOUT,
                     enable_ssh_port_timeout=ENABLE_SSH_ADMIN_SSH_PORT_TIMEOUT
                     ):
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
        DEVNULL = open(os.devnull, 'w')
        try:
            subprocess.check_call(tmp_key_command, stdout=DEVNULL,
                                  stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            log.error("ssh-keygen has failed with return code {0}".
                      format(exc.returncode))
        else:
            log.info("ssh-keygen has been run successfully")
        DEVNULL.close()

        with open(tmp_key_public) as pubkey:
            tmp_key_public_contents = pubkey.read()
        with open(tmp_key_private) as privkey:
            tmp_key_private_contents = privkey.read()

        for host in hosts:
            wait_for_ssh_port(host, enable_ssh_port_timeout)
            copy_tmp_key_command = ["ssh"] + ssh_options.split()
            copy_tmp_key_command += \
                ["-o", "StrictHostKeyChecking=no",
                 "-i", ssh_key, "-l", ssh_user, host,
                 "echo -e '\n%s' >> $HOME/.ssh/authorized_keys" %
                 tmp_key_public_contents]
            print("Inserting TripleO short term key for %s" % host)
            copy_temp_key(copy_tmp_key_command)

        print("Starting ssh admin enablement workflow")

        workflow_client = clients.workflow_engine

        workflow_input = {
            "ssh_user": ssh_user,
            "ssh_servers": hosts,
            "ssh_private_key": tmp_key_private_contents,
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
            if (now - start) > enable_ssh_timeout:
                raise exceptions.DeploymentError(
                    "ssh admin enablement workflow - TIMED OUT.")

            time.sleep(1)
            execution = workflow_client.executions.get(execution.id)
            state = execution.state

            if state == 'RUNNING':
                if (now - start) % ENABLE_SSH_ADMIN_STATUS_INTERVAL\
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
            rm_tmp_key_command += [
                "-i", ssh_key, "-l", ssh_user, host,
                """echo -e "$(sed -e '/%s/d' $HOME/.ssh/authorized_keys)
                " > $HOME/.ssh/authorized_keys""" % tmp_key_comment
            ]
            print("Removing TripleO short term key from %s" % host)
            subprocess.check_call(rm_tmp_key_command, stderr=subprocess.STDOUT)
    finally:
        print("Removing short term keys locally")
        shutil.rmtree(tmp_key_dir)

    print("Enabling ssh admin - COMPLETE.")


def config_download(log, clients, stack, templates,
                    ssh_user, ssh_key, ssh_network,
                    output_dir, override_ansible_cfg, timeout, verbosity=1,
                    deployment_options={},
                    in_flight_validations=False,
                    deployment_timeout=None,
                    skip_tags=None,
                    tags=None,
                    limit_hosts=None,
                    forks=None):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    if not in_flight_validations:
        if skip_tags:
            skip_tags = 'opendev-validation,{}'.format(skip_tags)
        else:
            skip_tags = 'opendev-validation'

    workflow_input = {
        'verbosity': verbosity,
        'plan_name': stack.stack_name,
        'ssh_network': ssh_network,
        'connection_timeout': timeout,
        'config_download_timeout': deployment_timeout,
        'deployment_options': deployment_options,
        'skip_tags': skip_tags,
        'tags': tags,
        'limit_hosts': utils.playbook_limit_parse(limit_hosts),
        'forks': forks
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
            print(payload['message'], end='')

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

        for payload in base.wait_for_messages(workflow_client, ws, execution):
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


def set_deployment_status(clients, status='success',
                          working_dir='/home/stack/overcloud-deploy/overcloud',
                          **workflow_input):
    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    if status == 'DEPLOY_SUCCESS':
        workflow = 'tripleo.deployment.v1.set_deployment_status_success'
    elif status == 'DEPLOY_FAILED':
        workflow = 'tripleo.deployment.v1.set_deployment_status_failed'
    elif status == 'DEPLOYING':
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

    utils.update_deployment_status(
        stack_name=workflow_input['plan'],
        status=status,
        working_dir=working_dir)

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
