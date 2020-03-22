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
import textwrap
import time

from concurrent.futures import ThreadPoolExecutor
from osc_lib import exceptions
from osc_lib.i18n import _
from prettytable import PrettyTable

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils

LOG = logging.getLogger(__name__ + ".TripleoValidator")

RED = "\033[1;31m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"

FAILED_VALIDATION = "{}FAILED{}".format(RED, RESET)
PASSED_VALIDATION = "{}PASSED{}".format(GREEN, RESET)

GROUP_FILE = constants.VALIDATION_GROUPS_INFO


class _CommaListGroupAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        opts = oooutils.get_validation_group_name_list()
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
        group = oooutils.prepare_validation_groups_for_display()

        if not group:
            raise exceptions.CommandError(
                "Could not find groups information file %s" % GROUP_FILE)

        group_info = []
        for gp in group:
            validations = oooutils.parse_all_validations_on_disk(
                constants.ANSIBLE_VALIDATION_DIR, gp[0])
            group_info.append((gp[0], gp[1], len(validations)))

        column_name = ("Groups", "Description", "Number of Validations")
        return (column_name, group_info)


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
        logfile_contents = oooutils.parse_all_validations_logs_on_disk(
            validation_id=parsed_args.validation_id)

        if not validation:
            raise exceptions.CommandError(
                "Could not find validation %s" % parsed_args.validation_id)

        return self.format_validation(validation, logfile_contents)

    def get_validations_details(self, validation):
        results = oooutils.parse_all_validations_on_disk(
            constants.ANSIBLE_VALIDATION_DIR)

        for r in results:
            if r['id'] == validation:
                return r
        return []

    def format_validation(self, validation, logfile):
        column_names = ["ID"]
        data = [validation.pop('id')]

        if 'name' in validation:
            column_names.append("Name")
            data.append(validation.pop('name'))

        if 'description' in validation:
            column_names.append("Description")
            data.append(textwrap.fill(validation.pop('description')))

        if 'groups' in validation:
            column_names.append("Groups")
            data.append(", ".join(validation.pop('groups')))

        other_fields = list(validation.keys())
        other_fields.sort()
        for field in other_fields:
            column_names.append(field.capitalize())
            data.append(validation[field])

        # history, stats ...
        total_number = 0
        failed_number = 0
        passed_number = 0
        last_execution = None
        dates = []

        if logfile:
            total_number = len(logfile)

        for run in logfile:
            if 'validation_output' in run and run.get('validation_output'):
                failed_number += 1
            else:
                passed_number += 1

            date_time = \
                run['plays'][0]['play']['duration'].get('start').split('T')
            date_start = date_time[0]
            time_start = date_time[1].split('Z')[0]
            newdate = \
                time.strptime(date_start + time_start, '%Y-%m-%d%H:%M:%S.%f')
            dates.append(newdate)

        if dates:
            last_execution = time.strftime('%Y-%m-%d %H:%M:%S', max(dates))

        column_names.append("Number of execution")
        data.append("Total: {}, Passed: {}, Failed: {}".format(total_number,
                                                               passed_number,
                                                               failed_number))

        column_names.append("Last execution date")
        data.append(last_execution)

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
                    for val_name in list(data.keys()):
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
                                      ", ".join(val.get('groups'))))
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
                    _("Getting Validations list by group name"
                      "finished with errors"))
                print('Output: {}'.format(e))

        else:
            for pb in parsed_args.validation_name:
                if pb not in oooutils.get_validation_group_name_list():
                    playbooks.append(pb + '.yaml')
                else:
                    raise exceptions.CommandError(
                        "Please, use '--group' argument instead of "
                        "'--validation' to run validation(s) by their name(s)."
                    )

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
                        output_callback='validation_json',
                        quiet=True,
                        extra_vars=extra_vars_input,
                        gathering_policy='explicit'): playbook
                    for playbook in playbooks
                }

        results = []

        for tk, pl in six.iteritems(tasks_exec):
            try:
                _rc, output = tk.result()
                results.append({
                    'validation': {
                        'validation_id': pl,
                        'logfile': None,
                        'status': 'PASSED',
                        'output': output
                    }})
            except Exception as e:
                failed_val = True
                results.append({
                    'validation': {
                        'validation_id': pl,
                        'logfile': None,
                        'status': 'FAILED',
                        'output': str(e)
                    }})

        if results:
            new_log_files = oooutils.get_new_validations_logs_on_disk()

            for i in new_log_files:
                val_id = "{}.yaml".format(i.split('_')[1])
                for res in results:
                    if res['validation'].get('validation_id') == val_id:
                        res['validation']['logfile'] = \
                            os.path.join(constants.VALIDATIONS_LOG_BASEDIR, i)

            t = PrettyTable(border=True, header=True, padding_width=1)
            t.field_names = [
                "UUID", "Validations", "Status", "Host Group(s)",
                "Status by Host", "Unreachable Host(s)", "Duration"]

            for validation in results:
                r = []
                logfile = validation['validation'].get('logfile', None)
                if logfile and os.path.exists(logfile):
                    with open(logfile, 'r') as val:
                        contents = json.load(val)

                    for i in contents['plays']:
                        host = [x for x in i['play'].get('host').split(', ')]
                        val_id = i['play'].get('validation_id')
                        time_elapsed = \
                            i['play']['duration'].get('time_elapsed', None)

                    r.append(contents['plays'][0]['play'].get('id'))
                    r.append(val_id)
                    if validation['validation'].get('status') == "PASSED":
                        r.append(PASSED_VALIDATION)
                    else:
                        r.append(FAILED_VALIDATION)

                    unreachable_hosts = []
                    hosts_result = []
                    for ht in list(contents['stats'].keys()):
                        if contents['stats'][ht]['unreachable'] != 0:
                            unreachable_hosts.append(ht)
                        elif contents['stats'][ht]['failures'] != 0:
                            hosts_result.append("{}{}{}".format(
                                RED, ht, RESET))
                        else:
                            hosts_result.append("{}{}{}".format(
                                GREEN, ht, RESET))

                    r.append(", ".join(host))
                    r.append(", ".join(hosts_result))
                    r.append("{}{}{}".format(RED,
                                             ", ".join(unreachable_hosts),
                                             RESET))
                    r.append(time_elapsed)
                    t.add_row(r)

            t.sortby = "UUID"
            for field in t.field_names:
                if field == "Status":
                    t.align['Status'] = "l"
                else:
                    t.align[field] = "l"

            print(t)

            if len(new_log_files) > len(results):
                LOG.warn(_('Looks like we have more log files than '
                           'executed validations'))

            for i in new_log_files:
                os.rename(
                    "{}/{}".format(constants.VALIDATIONS_LOG_BASEDIR,
                                   i), "{}/processed_{}".format(
                                       constants.VALIDATIONS_LOG_BASEDIR, i))

        LOG.debug(_('Removing static tripleo ansible inventory file'))
        oooutils.cleanup_tripleo_ansible_inventory_file(
            static_inventory)

        if failed_val:
            raise exceptions.CommandError(
                _('One or more validations have failed!'))

    def take_action(self, parsed_args):
        self._run_validator_run(parsed_args)


class TripleOValidatorShowRun(command.Command):
    """Display details about a Validation execution"""

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
        logfile_contents = oooutils.parse_all_validations_logs_on_disk(
            uuid_run=parsed_args.uuid)

        if len(logfile_contents) > 1:
            raise exceptions.CommandError(
                "Multiple log files found for UUID: %s" % parsed_args.uuid)

        if logfile_contents:
            if parsed_args.full:
                print(oooutils.get_validations_json(logfile_contents[0]))
            else:
                for data in logfile_contents:
                    for tasks in data['validation_output']:
                        print(oooutils.get_validations_json(tasks))
        else:
            raise exceptions.CommandError(
                "Could not find the log file linked to this UUID: %s" %
                parsed_args.uuid)


class TripleOValidatorShowHistory(command.Lister):
    """Display Validations execution history"""

    def get_parser(self, prog_name):
        parser = super(TripleOValidatorShowHistory, self).get_parser(prog_name)

        parser.add_argument('--validation',
                            metavar="<validation>",
                            type=str,
                            help='Display execution history for a validation')

        return parser

    def take_action(self, parsed_args):
        logfile_contents = oooutils.parse_all_validations_logs_on_disk(
            validation_id=parsed_args.validation)

        if not logfile_contents:
            msg = "No History Found"
            if parsed_args.validation:
                raise exceptions.CommandError(
                    "{} for {}.".format(
                        msg, parsed_args.validation))
            else:
                raise exceptions.CommandError(
                    "{}.".format(msg, parsed_args.validation))

        return_values = []
        column_name = ('UUID', 'Validations',
                       'Status', 'Execution at',
                       'Duration')

        for run in logfile_contents:
            status = PASSED_VALIDATION
            if 'plays' in run and run.get('plays'):
                date_time = \
                    run['plays'][0]['play']['duration'].get('start').split('T')
                time_elapsed = \
                    run['plays'][0]['play']['duration'].get('time_elapsed')
                date_start = date_time[0]
                time_start = date_time[1].split('Z')[0]

                for k, v in six.iteritems(run['stats']):
                    if v.get('failures') != 0:
                        status = FAILED_VALIDATION

                return_values.append(
                    (run['plays'][0]['play'].get('id'),
                     run['plays'][0]['play'].get('validation_id'), status,
                     "{} {}".format(date_start, time_start), time_elapsed))

        return (column_name, return_values)
