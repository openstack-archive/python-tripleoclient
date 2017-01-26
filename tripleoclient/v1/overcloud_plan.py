#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

import json
import logging
import uuid

from osc_lib.command import command
from osc_lib.i18n import _

from tripleoclient import utils
from tripleoclient.workflows import deployment
from tripleoclient.workflows import plan_management


class ListPlans(command.Lister):
    """List overcloud deployment plans."""

    log = logging.getLogger(__name__ + ".ListPlans")

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        workflow_client = self.app.client_manager.workflow_engine
        execution = workflow_client.action_executions.create(
            'tripleo.plan.list')

        try:
            json_results = json.loads(execution.output)['result']
        except Exception:
            self.log.exception("Error parsing JSON %s", execution.output)
            json_results = []

        result = []
        for r in json_results:
            result.append((r,))

        return (("Plan Name",), result)


class DeletePlan(command.Command):
    """Delete an overcloud deployment plan.

    The plan will not be deleted if a stack exists with the same name.
    """

    log = logging.getLogger(__name__ + ".DeletePlan")

    def get_parser(self, prog_name):
        parser = super(DeletePlan, self).get_parser(prog_name)
        parser.add_argument('plans', metavar='<name>', nargs="+",
                            help=_('Name of the plan(s) to delete'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        workflow_client = self.app.client_manager.workflow_engine

        for plan in parsed_args.plans:
            print("Deleting plan %s..." % plan)
            plan_management.delete_deployment_plan(workflow_client,
                                                   container=plan)


class CreatePlan(command.Command):
    """Create a deployment plan"""

    log = logging.getLogger(__name__ + ".CreatePlan")

    def get_parser(self, prog_name):
        parser = super(CreatePlan, self).get_parser(prog_name)
        parser.add_argument(
            'name',
            help=_('The name of the plan, which is used for the object '
                   'storage container, workflow environment and orchestration '
                   'stack names.'))
        parser.add_argument(
            '--templates',
            help=_('The directory containing the Heat templates to deploy. '
                   'If this isn\'t provided, the templates packaged on the '
                   'Undercloud will be used.'),
        )
        parser.add_argument(
            '--disable-password-generation',
            action='store_true',
            default=False,
            help=_('Disable password generation.')
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        name = parsed_args.name
        generate_passwords = not parsed_args.disable_password_generation

        if parsed_args.templates:
            plan_management.create_plan_from_templates(
                clients, name, parsed_args.templates,
                generate_passwords=generate_passwords)
        else:
            plan_management.create_default_plan(
                clients, container=name, queue_name=str(uuid.uuid4()),
                generate_passwords=generate_passwords)


class DeployPlan(command.Command):
    """Deploy a deployment plan"""

    log = logging.getLogger(__name__ + ".DeployPlan")

    def get_parser(self, prog_name):
        parser = super(DeployPlan, self).get_parser(prog_name)
        parser.add_argument('name', help=_('The name of the plan to deploy.'))
        parser.add_argument('--timeout', '-t', metavar='<TIMEOUT>',
                            type=int,
                            help=_('Deployment timeout in minutes.'))
        parser.add_argument('--run-validations', action='store_true',
                            default=False,
                            help=_('Run the pre-deployment validations. These '
                                   'external validations are from the TripleO '
                                   'Validations project.'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        clients = self.app.client_manager
        orchestration_client = clients.orchestration
        stack = utils.get_stack(orchestration_client, parsed_args.name)

        print("Starting to deploy plan: {}".format(parsed_args.name))
        deployment.deploy_and_wait(self.log, clients, stack, parsed_args.name,
                                   self.app_args.verbose_level,
                                   timeout=parsed_args.timeout,
                                   run_validations=parsed_args.run_validations)
