#   Copyright 2019 Red Hat, Inc.
#
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
#

import argparse
import json
import logging
import yaml

from openstack import exceptions as os_exceptions
from osc_lib.cli import parseractions
from osc_lib import exceptions
from osc_lib.i18n import _
from prettytable import PrettyTable

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils
from tripleoclient.workflows import deployment

from validations_libs import constants as v_consts
from validations_libs import utils as v_utils
from validations_libs.validation_actions import ValidationActions
from validations_libs.validation_logs import ValidationLogs

LOG = logging.getLogger(__name__ + ".TripleoValidator")

RED = "\033[1;31m"
GREEN = "\033[0;32m"
CYAN = "\033[36m"
YELLOW = "\033[0;33m"
RESET = "\033[0;0m"

FAILED_VALIDATION = "{}FAILED{}".format(RED, RESET)
PASSED_VALIDATION = "{}PASSED{}".format(GREEN, RESET)

GROUP_FILE = constants.VALIDATION_GROUPS_INFO

NO_VALIDATION_STATE = ['DEPLOY_FAILED', 'DEPLOYING']


class _CommaListGroupAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        opts = v_utils.get_validation_group_name_list(GROUP_FILE)
        for value in values.split(','):
            if value not in opts:
                message = ("Invalid choice: {value} (choose from {choice})"
                           .format(value=value,
                                   choice=opts))
                raise argparse.ArgumentError(self, message)
        setattr(namespace, self.dest, values.split(','))


class _CommaListAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values.split(','))


class TripleOValidatorGroupInfo(command.Lister):
    """Display Information about Validation Groups"""

    auth_required = False

    def get_parser(self, prog_name):
        parser = super(TripleOValidatorGroupInfo, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        actions = ValidationActions(constants.ANSIBLE_VALIDATION_DIR)
        return actions.group_information(GROUP_FILE)


class TripleOValidatorShow(command.ShowOne):
    """Display detailed information about a Validation"""

    auth_required = False

    def get_parser(self, prog_name):
        parser = super(TripleOValidatorShow, self).get_parser(prog_name)

        parser.add_argument('validation_id',
                            metavar="<validation>",
                            type=str,
                            help='Validation ID')

        return parser

    def take_action(self, parsed_args):
        LOG.debug(_('Show validation result'))
        actions = ValidationActions(constants.ANSIBLE_VALIDATION_DIR)

        try:
            data = actions.show_validations(parsed_args.validation_id)
        except Exception as e:
            raise exceptions.CommandError(e)

        if data:
            return data.keys(), data.values()


class TripleOValidatorShowParameter(command.Command):
    """Display Validations Parameters"""

    auth_required = False

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            add_help=True
        )

        ex_group = parser.add_mutually_exclusive_group(required=False)

        ex_group.add_argument(
            '--validation',
            metavar='<validation_id>[,<validation_id>,...]',
            dest='validation_name',
            action=_CommaListAction,
            default=[],
            help=_("List specific validations, "
                   "if more than one validation is required "
                   "separate the names with commas: "
                   "--validation check-ftype,512e | "
                   "--validation 512e")
        )

        ex_group.add_argument(
            '--group',
            metavar='<group_id>[,<group_id>,...]',
            action=_CommaListGroupAction,
            default=[],
            help=_("List specific group validations, "
                   "if more than one group is required "
                   "separate the group names with commas: "
                   "pre-upgrade,prep | "
                   "openshift-on-openstack")
        )

        parser.add_argument(
            '--download',
            action='store',
            default=None,
            help=_("Create a json or a yaml file "
                   "containing all the variables "
                   "available for the validations: "
                   "/tmp/myvars")
        )

        parser.add_argument(
            '-f', '--format',
            action='store',
            metavar='<format>',
            default='json',
            choices=['json', 'yaml'],
            help=_("Print representation of the validation. "
                   "The choices of the output format is json,yaml. ")
        )

        return parser

    def take_action(self, parsed_args):
        actions = ValidationActions(constants.ANSIBLE_VALIDATION_DIR)
        params = actions.show_validations_parameters(
            parsed_args.validation_name,
            parsed_args.group,
            parsed_args.format,
            parsed_args.download)
        if parsed_args.download:
            print("The file {} has been created successfully".format(
                parsed_args.download))
        else:
            print(params)


class TripleOValidatorList(command.Lister):
    """List the available validations"""

    auth_required = False

    def get_parser(self, prog_name):
        parser = super(TripleOValidatorList, self).get_parser(prog_name)

        parser.add_argument(
            '--group',
            metavar='<group>[,<group>,...]',
            action=_CommaListGroupAction,
            default=[],
            help=_("List specific group validations, "
                   "if more than one group is required "
                   "separate the group names with commas: "
                   "--group pre-upgrade,prep | "
                   "--group openshift-on-openstack")
        )

        return parser

    def take_action(self, parsed_args):
        LOG.debug(_('Launch listing the validations'))
        try:
            v_consts.DEFAULT_VALIDATIONS_BASEDIR = constants.\
                DEFAULT_VALIDATIONS_BASEDIR
            actions = ValidationActions(
                validation_path=constants.ANSIBLE_VALIDATION_DIR
            )
            return actions.list_validations(parsed_args.group)
        except Exception as e:
            raise RuntimeError(_("Validations listing finished with errors\n"
                                 "Output: {}").format(e))


class TripleOValidatorRun(command.Command):
    """Run the available validations"""

    auth_required = False

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            add_help=False
        )

        parser.add_argument(
            '--plan', '--stack',
            dest='plan',
            default=None,
            help=_("Execute the validations using a custom plan name")
        )

        parser.add_argument(
            '--ssh-user',
            dest='ssh_user',
            default='heat-admin',
            help=_("Ssh User name for the Overcloud ssh connection.")
        )

        parser.add_argument(
            '--limit', action='store', required=False, help=_(
                "A string that identifies a single node or comma-separated"
                "list of nodes to be upgraded in parallel in this upgrade"
                " run invocation. For example: --limit \"compute-0,"
                " compute-1, compute-5\".")
        )

        parser.add_argument(
            '--static-inventory',
            action='store',
            default='',
            help=_(
                "Provide your own static inventory file. You can generate "
                "such an inventory calling tripleo-ansible-inventory command. "
                "Especially useful when heat service isn't available."
            )
        )

        parser.add_argument(
            '--python-interpreter',
            action='store',
            default="/usr/libexec/platform-python",
            help=_("Python interpreter for Ansible execution. ")
        )

        extra_vars_group = parser.add_mutually_exclusive_group(required=False)

        extra_vars_group.add_argument(
            '--extra-vars',
            metavar="key1=<val1>[,key2=val2 --extra-vars key3=<val3>]",
            action=parseractions.MultiKeyValueAction,
            help=_(
                "Add Ansible extra variables to the validation(s) execution "
                "as KEY=VALUE pair(s). Note that if you pass the same "
                "KEY multiple times, the last given VALUE for that same KEY "
                "will override the other(s)")
        )

        extra_vars_group.add_argument(
            '--extra-vars-file',
            action='store',
            default='',
            help=_(
                "Add a JSON/YAML file containing extra variable "
                "to a validation: "
                "--extra-vars-file /home/stack/vars.[json|yaml] "
                "If using Mistral, only a valid JSON file will be "
                "supported."
            )
        )

        parser.add_argument(
            '--extra-env-vars',
            metavar="key1=<val1>[,key2=val2 --extra-env-vars key3=<val3>]",
            action=parseractions.MultiKeyValueAction,
            help=_(
                "Add extra environment variables you may need "
                "to provide to your Ansible execution "
                "as KEY=VALUE pairs. Note that if you pass the same "
                "KEY multiple times, the last given VALUE for that same KEY "
                "will override the other(s)")
        )

        ex_group = parser.add_mutually_exclusive_group(required=True)

        ex_group.add_argument(
            '--validation',
            metavar='<validation_id>[,<validation_id>,...]',
            dest="validation_name",
            action=_CommaListAction,
            default=[],
            help=_("Run specific validations, "
                   "if more than one validation is required "
                   "separate the names with commas: "
                   "--validation check-ftype,512e | "
                   "--validation 512e")
        )

        ex_group.add_argument(
            '--group',
            metavar='<group>[,<group>,...]',
            action=_CommaListGroupAction,
            default=[],
            help=_("Run specific group validations, "
                   "if more than one group is required "
                   "separate the group names with commas: "
                   "--group pre-upgrade,prep | "
                   "--group openshift-on-openstack")
        )

        return parser

    def _run_validator_run(self, parsed_args):
        LOG = logging.getLogger(__name__ + ".ValidationsRunAnsible")

        plan = parsed_args.plan
        # Try to perform OpenStack authentication, if no authentication
        # and static inventory provided continue, else raise error.
        try:
            clients = self.app.client_manager
            clients._auth_required = True
            clients.setup_auth()
        except os_exceptions.ConfigException:
            msg = "Running Validations without authentication."
            LOG.warning("{}{}{}".format(YELLOW, msg, RESET))
            if not parsed_args.static_inventory:
                raise exceptions.CommandError(
                    _("No static inventory provided, please provide a valid "
                      "inventory or use authentication."))
        else:
            if plan:
                status = deployment.get_deployment_status(clients, plan=plan)
                if not status or status in NO_VALIDATION_STATE:
                    raise exceptions.CommandError(
                        _("The plan and the stack '{}' doesn't exist OR are "
                          "in 'failed' or 'deploying' state. "
                          "Please use a valid plan".format(plan)))
            else:
                msg = "Running Validations without Overcloud settings."
                LOG.warning("{}{}{}".format(YELLOW, msg, RESET))
        limit = parsed_args.limit

        extra_vars = dict()
        if parsed_args.extra_vars:
            # if using multiple --extra-vars argument in the command-line
            # we will get a list of multiple dictionaries.
            for keypair in parsed_args.extra_vars:
                extra_vars.update(keypair)

        if parsed_args.extra_vars_file:
            try:
                with open(parsed_args.extra_vars_file, 'r') as env_file:
                    extra_vars.update(yaml.safe_load(env_file.read()))
            except yaml.YAMLError as e:
                error_msg = (
                    "The request body must be properly formatted YAML/JSON. "
                    "Details: %s." % e)
                raise exceptions.CommandError(error_msg)

        # Ansible execution should be quiet while using the validations_json
        # default callback and be verbose while passing ANSIBLE_SDTOUT_CALLBACK
        # environment variable to Ansible through the --extra-env-vars argument
        quiet_mode = True
        extra_env_vars = dict()
        if parsed_args.extra_env_vars:
            # if using multiple --extra-env-vars argument in the command-line
            # we will get a list of multiple dictionaries.
            for keypair in parsed_args.extra_env_vars:
                if "ANSIBLE_STDOUT_CALLBACK" in keypair.keys():
                    quiet_mode = False
                extra_env_vars.update(keypair)

        # We don't check if the file exists in order to support
        # passing a string such as "localhost,", like we can do with
        # the "-i" option of ansible-playbook.
        if parsed_args.static_inventory:
            static_inventory = parsed_args.static_inventory
        else:
            static_inventory = oooutils.get_tripleo_ansible_inventory(
                ssh_user=parsed_args.ssh_user,
                stack=parsed_args.plan,
                undercloud_connection='local',
                return_inventory_file_path=True)

        v_consts.DEFAULT_VALIDATIONS_BASEDIR = constants.\
            DEFAULT_VALIDATIONS_BASEDIR
        actions = ValidationActions()
        try:
            results = actions.run_validations(
                inventory=static_inventory,
                limit_hosts=limit,
                group=parsed_args.group,
                extra_vars=extra_vars,
                validations_dir=constants.ANSIBLE_VALIDATION_DIR,
                validation_name=parsed_args.validation_name,
                extra_env_vars=extra_env_vars,
                python_interpreter=parsed_args.python_interpreter,
                quiet=quiet_mode)
        except RuntimeError as e:
            raise exceptions.CommandError(e)

        is_failed_validation = False
        if results:
            # Build output
            t = PrettyTable(border=True, header=True, padding_width=1)
            # Set Field name by getting the result dict keys
            t.field_names = results[0].keys()
            t.align = 'l'
            for r in results:
                if r.get('Status_by_Host'):
                    h = []
                    for host in r['Status_by_Host'].split(', '):
                        _name, _status = host.split(',')
                        color = (GREEN if _status == 'PASSED' else RED)
                        _name = '{}{}{}'.format(color, _name, RESET)
                        h.append(_name)
                    r['Status_by_Host'] = ', '.join(h)
                if r.get('Status'):
                    status = r.get('Status')
                    if status == 'FAILED':
                        is_failed_validation = True
                    color = (CYAN if status in ['starting', 'running']
                             else GREEN if status == 'PASSED' else RED)
                    r['Status'] = '{}{}{}'.format(color, status, RESET)
                t.add_row(r.values())
            print(t)
        else:
            msg = "No Validation has been run, please check your parameters."
            LOG.info(_(msg))

        if not parsed_args.static_inventory:
            LOG.debug(_('Removing static tripleo ansible inventory file'))
            oooutils.cleanup_tripleo_ansible_inventory_file(
                static_inventory)

        if is_failed_validation:
            raise exceptions.CommandError(
                _("One or more validations have failed."))

    def take_action(self, parsed_args):
        self._run_validator_run(parsed_args)


class TripleOValidatorShowRun(command.Command):
    """Display details about a Validation execution"""

    auth_required = False

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            add_help=False
        )

        parser.add_argument('uuid',
                            metavar="<uuid>",
                            type=str,
                            help='Validation UUID Run')

        parser.add_argument('--full',
                            action='store_true',
                            help='Show Full Details for the run')

        return parser

    def take_action(self, parsed_args):
        vlogs = ValidationLogs()
        data = vlogs.get_logfile_content_by_uuid(parsed_args.uuid)
        if data:
            if parsed_args.full:
                for d in data:
                    print(json.dumps(d, indent=4, sort_keys=True))
            else:
                for d in data:
                    for p in d.get('validation_output', []):
                        print(json.dumps(p['task'],
                                         indent=4,
                                         sort_keys=True))
        else:
            raise exceptions.CommandError(
                "Could not find the log file linked to this UUID: %s" %
                parsed_args.uuid)


class TripleOValidatorShowHistory(command.Lister):
    """Display Validations execution history"""

    auth_required = False

    def get_parser(self, prog_name):
        parser = super(TripleOValidatorShowHistory, self).get_parser(prog_name)

        parser.add_argument('--validation',
                            metavar="<validation>",
                            type=str,
                            help='Display execution history for a validation')

        return parser

    def take_action(self, parsed_args):
        actions = ValidationActions(constants.ANSIBLE_VALIDATION_DIR)
        return actions.show_history(parsed_args.validation)
