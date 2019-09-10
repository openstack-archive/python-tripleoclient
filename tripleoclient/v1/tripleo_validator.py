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
import os
import pwd
import six
import sys

from concurrent.futures import ThreadPoolExecutor
from osc_lib.command import command
from osc_lib.i18n import _

from tripleoclient import constants
from tripleoclient import utils as oooutils
from tripleoclient.workflows import validations

LOG = logging.getLogger(__name__ + ".TripleoValidator")


class _CommaListGroupAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        opts = constants.VALIDATION_GROUPS
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


class TripleOValidatorList(command.Command):
    """List the available validations"""

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            add_help=False
        )

        parser.add_argument(
            '--output',
            action='store',
            default='table',
            choices=['table', 'json', 'yaml'],
            help=_("Change the default output: "
                   "--output json|yaml")
        )

        parser.add_argument(
            '--parameters',
            action='store_true',
            default=False,
            help=_("List available validations parameters")
        )

        parser.add_argument(
            '--create-vars-file',
            metavar=('[json|yaml]', '/tmp/myvars'),
            action='store',
            default=[],
            nargs=2,
            help=_("Create a json or a yaml file "
                   "containing all the variables "
                   "available for the validations: "
                   "[yaml|json] /tmp/myvars")
        )

        ex_group = parser.add_mutually_exclusive_group(required=False)

        ex_group.add_argument(
            '--validation-name',
            metavar='<validation_id>[,<validation_id>,...]',
            action=_CommaListAction,
            default=[],
            help=_("List specific validations, "
                   "if more than one validation is required "
                   "separate the names with commas: "
                   "--validation-name check-ftype,512e | "
                   "--validation-name 512e")
        )

        ex_group.add_argument(
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

    def _create_variables_file(self, data, varsfile):
        msg = (_("The file %s already exists on the filesystem, "
                 "do you still want to continue [y/N] "))

        if varsfile[0] not in ['json', 'yaml']:
            raise RuntimeError(_('Wrong file type: %s') % varsfile[0])
        else:
            LOG.debug(_('Launch variables file creation'))
            try:
                if os.path.exists(varsfile[-1]):
                    confirm = oooutils.prompt_user_for_confirmation(
                        message=msg % varsfile[-1], logger=LOG)
                    if not confirm:
                        raise RuntimeError(_("Action not confirmed, exiting"))

                with open(varsfile[-1], 'w') as f:
                    params = {}
                    for val_name in data.keys():
                        for k, v in data[val_name].get('parameters').items():
                            params[k] = v

                    if varsfile[0] == 'json':
                        f.write(oooutils.get_validations_json(params))
                    elif varsfile[0] == 'yaml':
                        f.write(oooutils.get_validations_yaml(params))
                print(
                    _('The file %s has been created successfully') %
                    varsfile[-1])
            except Exception as e:
                print(_("Creating variables file finished with errors"))
                print('Output: {}'.format(e))

    def _run_validator_list(self, parsed_args):
        clients = self.app.client_manager

        workflow_input = {
            "group_names": parsed_args.group
        }

        LOG.debug(_('Launch listing the validations'))
        try:
            output = validations.list_validations(clients, workflow_input)
            if parsed_args.parameters:
                out = oooutils.get_validations_parameters(
                    {'validations': output},
                    parsed_args.validation_name,
                    parsed_args.group
                )

                if parsed_args.create_vars_file:
                    self._create_variables_file(out,
                                                parsed_args.create_vars_file)
                else:
                    print(oooutils.get_validations_json(out))
            else:
                if parsed_args.output == 'json':
                    out = oooutils.get_validations_json(
                        {'validations': output})
                elif parsed_args.output == 'yaml':
                    out = oooutils.get_validations_yaml(
                        {'validations': output})
                else:
                    out = oooutils.get_validations_table(
                        {'validations': output})
                print(out)
        except Exception as e:
            raise RuntimeError(_("Validations listing finished with errors\n"
                                 "Output: {}").format(e))

    def take_action(self, parsed_args):
        self._run_validator_list(parsed_args)


class TripleOValidatorRun(command.Command):
    """Run the available validations"""

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
            default='overcloud',
            help=_("Execute the validations using a custom plan name")
        )

        parser.add_argument(
            '--use-mistral',
            action='store_true',
            default=False,
            help=_("Execute the validations using Mistral")
        )

        parser.add_argument(
            '--workers', '-w',
            metavar='N',
            dest='workers',
            default=1,
            type=int,
            help=_("The maximum number of threads that can "
                   "be used to execute the given validations")
        )

        extra_vars_group = parser.add_mutually_exclusive_group(required=False)

        extra_vars_group.add_argument(
            '--extra-vars',
            action='store',
            default={},
            type=json.loads,
            help=_(
                "Add a dictionary as extra variable to a validation: "
                "--extra-vars '{\"min_undercloud_ram_gb\": 24}'")
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

        ex_group = parser.add_mutually_exclusive_group(required=True)

        ex_group.add_argument(
            '--validation-name',
            metavar='<validation_id>[,<validation_id>,...]',
            action=_CommaListAction,
            default=[],
            help=_("Run specific validations, "
                   "if more than one validation is required "
                   "separate the names with commas: "
                   "--validation-name check-ftype,512e | "
                   "--validation-name 512e")
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

    def _run_validation_run_with_mistral(self, parsed_args):
        clients = self.app.client_manager
        LOG = logging.getLogger(__name__ + ".ValidationsRunWithMistral")
        extra_vars_input = {}

        if parsed_args.extra_vars:
            extra_vars_input = parsed_args.extra_vars

        if parsed_args.extra_vars_file:
            try:
                with open(parsed_args.extra_vars_file, 'r') as vars_file:
                    extra_vars_input = json.load(vars_file)
            except ValueError as e:
                raise RuntimeError(
                    'Error occured while decoding extra vars JSON file: %s' %
                    e)

        if not parsed_args.validation_name:
            workflow_input = {
                "plan": parsed_args.plan,
                "group_names": parsed_args.group
            }
        else:
            workflow_input = {
                "plan": parsed_args.plan,
                "validation_names": parsed_args.validation_name,
                "validation_inputs": extra_vars_input
            }

        LOG.debug(_('Running the validations with Mistral'))
        output = validations.run_validations(clients, workflow_input)
        for out in output:
            print('[{}] - {}\n{}'.format(
                out.get('status'),
                out.get('validation_name'),
                oooutils.indent(out.get('stdout'))))

    def _run_ansible(self, logger, plan, workdir, log_path_dir, playbook,
                     inventory, retries, output_callback, extra_vars,
                     python_interpreter, gathering_policy):
        rc, output = oooutils.run_ansible_playbook(
            logger=logger,
            plan=plan,
            workdir=workdir,
            log_path_dir=log_path_dir,
            playbook=playbook,
            inventory=inventory,
            retries=retries,
            output_callback=output_callback,
            extra_vars=extra_vars,
            python_interpreter=python_interpreter,
            gathering_policy=gathering_policy)
        return rc, output

    def _run_validator_run(self, parsed_args):
        clients = self.app.client_manager
        LOG = logging.getLogger(__name__ + ".ValidationsRunAnsible")
        playbooks = []
        extra_vars_input = {}

        if parsed_args.extra_vars:
            extra_vars_input = parsed_args.extra_vars

        if parsed_args.extra_vars_file:
            extra_vars_input = parsed_args.extra_vars_file

        if parsed_args.group:
            workflow_input = {
                "group_names": parsed_args.group
            }

            LOG.debug(_('Getting the validations list by group'))
            try:
                output = validations.list_validations(
                    clients, workflow_input)
                for val in output:
                    playbooks.append(val.get('id') + '.yaml')
            except Exception as e:
                print(
                    _("Validations listing by group finished with errors"))
                print('Output: {}'.format(e))

        else:
            for pb in parsed_args.validation_name:
                playbooks.append(pb + '.yaml')

        python_interpreter = \
            "/usr/bin/python{}".format(sys.version_info[0])

        static_inventory = oooutils.get_tripleo_ansible_inventory(
            ssh_user='heat-admin',
            stack=parsed_args.plan,
            undercloud_connection='local',
            return_inventory_file_path=True)

        failed_val = False

        with ThreadPoolExecutor(max_workers=parsed_args.workers) as executor:
            LOG.debug(_('Running the validations with Ansible'))
            tasks_exec = {
                executor.submit(
                    self._run_ansible,
                    logger=LOG,
                    plan=parsed_args.plan,
                    workdir=constants.ANSIBLE_VALIDATION_DIR,
                    log_path_dir=pwd.getpwuid(os.getuid()).pw_dir,
                    playbook=playbook,
                    inventory=static_inventory,
                    retries=False,
                    output_callback='validation_output',
                    extra_vars=extra_vars_input,
                    python_interpreter=python_interpreter,
                    gathering_policy='explicit'): playbook
                for playbook in playbooks
            }

        for tk, pl in six.iteritems(tasks_exec):
            try:
                rc, output = tk.result()
                print('[SUCCESS] - {}\n{}'.format(pl, oooutils.indent(output)))
            except Exception as e:
                failed_val = True
                LOG.error('[FAILED] - {}\n{}'.format(
                    pl, oooutils.indent(e.args[0])))

        LOG.debug(_('Removing static tripleo ansible inventory file'))
        oooutils.cleanup_tripleo_ansible_inventory_file(
            static_inventory)

        if failed_val:
            LOG.error(_('One or more validations have failed!'))
            sys.exit(1)
        sys.exit(0)

    def take_action(self, parsed_args):
        if parsed_args.use_mistral:
            self._run_validation_run_with_mistral(parsed_args)
        else:
            self._run_validator_run(parsed_args)
