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

import logging
import os.path

from osc_lib.i18n import _
from six.moves.urllib import request

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils
from tripleoclient.workflows import deployment
from tripleoclient.workflows import plan_management


class ListPlans(command.Lister):
    """List overcloud deployment plans."""

    log = logging.getLogger(__name__ + ".ListPlans")

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        clients = self.app.client_manager

        plans = plan_management.list_deployment_plans(clients)

        result = []
        for r in plans:
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

        clients = self.app.client_manager

        for plan in parsed_args.plans:
            print("Deleting plan %s..." % plan)
            plan_management.delete_deployment_plan(clients,
                                                   container=plan)


class CreatePlan(command.Command):
    """Create a deployment plan"""

    log = logging.getLogger(__name__ + ".CreatePlan")

    def get_parser(self, prog_name):
        parser = super(CreatePlan, self).get_parser(prog_name)
        source_group = parser.add_mutually_exclusive_group()
        parser.add_argument(
            'name',
            help=_('The name of the plan, which is used for the object '
                   'storage container, workflow environment and orchestration '
                   'stack names.'))
        source_group.add_argument(
            '--templates',
            help=_('The directory containing the Heat templates to deploy. '
                   'If this or --source_url isn\'t provided, the templates '
                   'packaged on the Undercloud will be used.'),
        )
        parser.add_argument(
            '--plan-environment-file', '-p',
            help=_('Plan Environment file, overrides the default %s in the '
                   '--templates directory') % constants.PLAN_ENVIRONMENT
        )
        parser.add_argument(
            '--disable-password-generation',
            action='store_true',
            default=False,
            help=_('Disable password generation.')
        )
        source_group.add_argument(
            '--source-url',
            help=_('The url of a git repository containing the Heat templates '
                   'to deploy. If this or --templates isn\'t provided, the '
                   'templates packaged on the Undercloud will be used.')
        )
        parser.add_argument(
            '--disable-container-prepare',
            action='store_true',
            default=False,
            help=_('Disable the container preparation actions to prevent '
                   'container tags from being updated and new containers '
                   'from being fetched. If you skip this but do not have '
                   'the container parameters configured, the deployment '
                   'action may fail.')
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        clients = self.app.client_manager

        name = parsed_args.name
        use_default_templates = False
        generate_passwords = not parsed_args.disable_password_generation
        source_url = parsed_args.source_url
        # if the templates and source_url params are not used, then
        # use the default templates
        if not parsed_args.templates and not parsed_args.source_url:
            use_default_templates = True

        # Needs this to avoid too long lines
        disable_container_prepare = parsed_args.disable_container_prepare

        if parsed_args.templates:
            plan_management.create_plan_from_templates(
                clients, name, parsed_args.templates,
                generate_passwords=generate_passwords,
                plan_env_file=parsed_args.plan_environment_file,
                verbosity_level=utils.playbook_verbosity(self=self),
                disable_image_params_prepare=disable_container_prepare
            )
        else:
            plan_management.create_deployment_plan(
                container=name,
                generate_passwords=generate_passwords,
                source_url=source_url,
                use_default_templates=use_default_templates,
                verbosity_level=utils.playbook_verbosity(self=self),
                disable_image_params_prepare=disable_container_prepare
            )


class DeployPlan(command.Command):
    """Deploy a deployment plan"""

    log = logging.getLogger(__name__ + ".DeployPlan")

    def get_parser(self, prog_name):
        parser = super(DeployPlan, self).get_parser(prog_name)
        parser.add_argument('name', help=_('The name of the plan to deploy.'))
        parser.add_argument('--timeout', '-t', metavar='<TIMEOUT>',
                            type=int, default=240,
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
        deployment.deploy_and_wait(
            log=self.log,
            clients=clients,
            stack=stack,
            plan_name=parsed_args.name,
            verbose_level=utils.playbook_verbosity(self=self),
            timeout=parsed_args.timeout,
            run_validations=parsed_args.run_validations,
        )


class ExportPlan(command.Command):
    """Export a deployment plan"""

    log = logging.getLogger(__name__ + ".ExportPlan")

    def get_parser(self, prog_name):
        parser = super(ExportPlan, self).get_parser(prog_name)
        parser.add_argument('plan', metavar='<name>',
                            help=_('Name of the plan to export.'))
        parser.add_argument('--output-file', '-o', metavar='<output file>',
                            help=_('Name of the output file for export. '
                                   'It will default to "<name>.tar.gz".'))
        parser.add_argument('--force-overwrite', '-f', action='store_true',
                            default=False,
                            help=_('Overwrite output file if it exists.'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        plan = parsed_args.plan
        outfile = parsed_args.output_file or '%s.tar.gz' % plan

        if os.path.exists(outfile) and not parsed_args.force_overwrite:
            raise exceptions.PlanExportError(
                "File '%s' already exists, not exporting." % outfile)

        print("Exporting plan %s..." % plan)

        tempurl = plan_management.export_deployment_plan(
            self.app.client_manager, plan
        )
        f = request.urlopen(tempurl)
        tarball_contents = f.read()
        f.close()

        with open(outfile, 'wb') as f:
            f.write(tarball_contents)
