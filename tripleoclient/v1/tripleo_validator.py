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
import six
import sys
import textwrap

from concurrent.futures import ThreadPoolExecutor
from osc_lib import exceptions
from osc_lib.i18n import _

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils

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


class TripleOValidatorGroupInfo(command.Lister):
    """Display Information about Validation Groups"""

    def get_parser(self, prog_name):
        parser = super(TripleOValidatorGroupInfo, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        group_file = constants.VALIDATION_GROUPS_INFO
        group = oooutils.parse_all_validation_groups_on_disk(group_file)

        if not group:
            raise exceptions.CommandError(
                "Could not find groups information file %s" % group_file)

        column_name = ("Groups", "Description")
        return (column_name, group)


class TripleOValidatorShow(command.ShowOne):
    """Display detailed information about a Validation"""

    def get_parser(self, prog_name):
        parser = super(TripleOValidatorShow, self).get_parser(prog_name)

        parser.add_argument('validation_id',
                            metavar="<validation>",
                            type=str,
                            help='Validation ID')

        return parser

    def take_action(self, parsed_args):
        validation = self.get_validations_details(parsed_args.validation_id)
        if not validation:
            raise exceptions.CommandError(
                "Could not find validation %s" % parsed_args.validation_id)

        return self.format_validation(validation)

    def get_validations_details(self, validation):
        results = oooutils.parse_all_validations_on_disk(
            constants.ANSIBLE_VALIDATION_DIR)

        for r in results:
            if r['id'] == validation:
                return r
        return []

    def format_validation(self, validation):
        column_names = ["ID"]
        data = [validation.pop('id')]

        if 'name' in validation:
            column_names.append("Name")
            data.append(validation.pop('name'))

        if 'description' in validation:
            column_names.append("Description")
            data.append(textwrap.fill(validation.pop('description')))

        other_fields = list(validation.keys())
        other_fields.sort()
        for field in other_fields:
            column_names.append(field.capitalize())
            data.append(validation[field])

        return column_names, data


class TripleOValidatorShowParameter(command.Command):
    """Display Validations Parameters"""

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
            metavar=('[json|yaml]', '/tmp/myvars'),
            action='store',
            default=[],
            nargs=2,
            help=_("Create a json or a yaml file "
                   "containing all the variables "
                   "available for the validations: "
                   "[yaml|json] /tmp/myvars")
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

    def _run_validator_show_parameter(self, parsed_args):
        LOG.debug(_('Launch showing parameters for the validations'))
        try:
            validations = oooutils.parse_all_validations_on_disk(
                constants.ANSIBLE_VALIDATION_DIR)

            out = oooutils.get_validations_parameters(
                {'validations': validations},
                parsed_args.validation_name,
                parsed_args.group
            )

            if parsed_args.download:
                self._create_variables_file(out,
                                            parsed_args.download)
            else:
                if parsed_args.format == 'yaml':
                    print(oooutils.get_validations_yaml(out))
                else:
                    print(oooutils.get_validations_json(out))
        except Exception as e:
            raise RuntimeError(_("Validations Show Parameters "
                                 "finished with errors\n"
                                 "Output: {}").format(e))

    def take_action(self, parsed_args):
        self._run_validator_show_parameter(parsed_args)


class TripleOValidatorList(command.Lister):
    """List the available validations"""

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
            validations = oooutils.parse_all_validations_on_disk(
                constants.ANSIBLE_VALIDATION_DIR, parsed_args.group)

            return_values = []
            column_name = ('ID', 'Name', 'Groups')

            for val in validations:
                return_values.append((val.get('id'), val.get('name'),
                                      val.get('groups')))
            return (column_name, return_values)
        except Exception as e:
            raise RuntimeError(_("Validations listing finished with errors\n"
                                 "Output: {}").format(e))


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
        playbooks = []
        extra_vars_input = {}

        if parsed_args.extra_vars:
            extra_vars_input = parsed_args.extra_vars

        if parsed_args.extra_vars_file:
            extra_vars_input = parsed_args.extra_vars_file

        if parsed_args.group:
            LOG.debug(_('Getting the validations list by group'))
            try:
                output = oooutils.parse_all_validations_on_disk(
                    constants.ANSIBLE_VALIDATION_DIR, parsed_args.group)
                for val in output:
                    playbooks.append(val.get('id') + '.yaml')
            except Exception as e:
                print(
                    _("Validations listing by group finished with errors"))
                print('Output: {}'.format(e))

        else:
            for pb in parsed_args.validation_name:
                playbooks.append(pb + '.yaml')

        static_inventory = oooutils.get_tripleo_ansible_inventory(
            ssh_user='heat-admin',
            stack=parsed_args.plan,
            undercloud_connection='local',
            return_inventory_file_path=True)

        failed_val = False

        with oooutils.TempDirs() as tmp:
            with ThreadPoolExecutor(max_workers=parsed_args.workers) as exe:
                LOG.debug(_('Running the validations with Ansible'))
                tasks_exec = {
                    exe.submit(
                        oooutils.run_ansible_playbook,
                        plan=parsed_args.plan,
                        workdir=tmp,
                        playbook=playbook,
                        playbook_dir=constants.ANSIBLE_VALIDATION_DIR,
                        parallel_run=True,
                        inventory=static_inventory,
                        output_callback='validation_output',
                        quiet=True,
                        extra_vars=extra_vars_input,
                        gathering_policy='explicit'): playbook
                    for playbook in playbooks
                }

        for tk, pl in six.iteritems(tasks_exec):
            try:
                _rc, output = tk.result()
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
        self._run_validator_run(parsed_args)
