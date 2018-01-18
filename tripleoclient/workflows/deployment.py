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
import re
import subprocess
import time

from heatclient.common import event_utils
from openstackclient import shell

from tripleoclient import exceptions
from tripleoclient import utils

from tripleoclient.workflows import base


def deploy(clients, **workflow_input):

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    with tripleoclients.messaging_websocket() as ws:
        execution = base.start_workflow(
            workflow_client,
            'tripleo.deployment.v1.deploy_plan',
            workflow_input=workflow_input
        )

        # The deploy workflow ends once the Heat create/update starts. This
        # means that is shouldn't take very long. Wait for six minutes for
        # messages from the workflow.
        for payload in base.wait_for_messages(workflow_client, ws, execution,
                                              360):
            assert payload['status'] == "SUCCESS", pprint.pformat(payload)


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

    deploy(clients, **workflow_input)

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
    verbose_events = verbose_level > 0
    create_result = utils.wait_for_stack_ready(
        orchestration_client, plan_name, marker, action, verbose_events)
    if not create_result:
        shell.OpenStackShell().run(["stack", "failures", "list", plan_name])
        if stack is None:
            raise exceptions.DeploymentError("Heat Stack create failed.")
        else:
            raise exceptions.DeploymentError("Heat Stack update failed.")


def overcloudrc(workflow_client, **input_):
    return base.call_action(workflow_client, 'tripleo.deployment.overcloudrc',
                            **input_)


def config_download(log, clients, stack, templates, deployed_server,
                    ssh_user, ssh_key, output_dir, verbosity=1):
    role_net_hostname_map = utils.get_role_net_hostname_map(stack)
    hostnames = []
    for role in role_net_hostname_map:
        hostnames.extend(role_net_hostname_map[role].get('ctlplane', []))

    ips = []
    hosts_entry = utils.get_hosts_entry(stack)
    for hostname in hostnames:
        for line in hosts_entry.split('\n'):
            match = re.search('\s*%s\s*' % hostname, line)
            if match:
                ips.append(line.split(' ')[0])

    script_path = os.path.join(templates,
                               'deployed-server',
                               'scripts',
                               'enable-ssh-admin.sh')

    env = os.environ.copy()
    env.update(dict(OVERCLOUD_HOSTS=' '.join(ips),
                    OVERCLOUD_SSH_USER=ssh_user))

    if ssh_key:
        env['OVERCLOUD_SSH_KEY'] = ssh_key

    proc = subprocess.Popen([script_path], env=env, shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)

    while True:
        line = proc.stdout.readline().decode('utf-8')
        if line:
            log.info(line.rstrip())
        if line == '' and proc.poll() is not None:
            break
    if proc.returncode != 0:
        raise RuntimeError('%s failed.' % script_path)

    workflow_client = clients.workflow_engine
    tripleoclients = clients.tripleoclient

    workflow_input = {
        'verbosity': verbosity
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
