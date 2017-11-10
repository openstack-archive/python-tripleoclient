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

from osc_lib.command import command
from osc_lib import exceptions
from osc_lib.i18n import _

from tripleoclient.workflows import roles


class ListRoles(command.Lister):
    """List the current and available roles in a given plan"""

    log = logging.getLogger(__name__ + ".ListRoles")

    def get_parser(self, prog_name):
        parser = super(ListRoles, self).get_parser(prog_name)
        parser.add_argument(
            '--name',
            dest='name',
            default='overcloud',
            help=_('The name of the plan, which is used for the object '
                   'storage container, workflow environment and orchestration '
                   'stack names.'),
        )
        parser.add_argument(
            '--detail',
            action='store_true',
            help=_('Include details about each role'))
        parser.add_argument(
            '--current',
            action='store_true',
            help=_('Only show the information for the roles currently enabled '
                   'for the plan.'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action({})'.format(parsed_args))

        if parsed_args.current:
            result = roles.list_roles(
                self.app.client_manager.workflow_engine,
                container=parsed_args.name,
                detail=parsed_args.detail)
        else:
            result = roles.list_available_roles(
                self.app.client_manager,
                container=parsed_args.name)
            # The workflow returns all the details by default, trim
            # them down if not required.
            if not parsed_args.detail:
                result = [r['name'] for r in result]

        if parsed_args.detail:
            if result:
                result.sort(key=lambda r: r['name'])

            role_list = self.format_role_details(result)
            column_names = ("Role Name",
                            "Description",
                            "Services Default",
                            "Other Details")
            return (column_names, role_list)
        else:
            if result:
                result.sort()
            return (("Role Name",), [(r,) for r in result])

    def format_role_details(self, result):
        role_list = []
        for r in result:
            name = r.pop('name')
            description = service_defaults = ''
            detail = []

            if 'description' in r:
                description = r.pop('description')
            if 'ServicesDefault' in r:
                r['ServicesDefault'].sort()
                service_defaults = '\n'.join(r.pop('ServicesDefault'))
            for k, v in r.items():
                detail.append("%s: %s" % (k, v))

            role_list.append((name, description, service_defaults,
                              '\n'.join(detail)))
        return role_list


class ShowRole(command.ShowOne):
    """Show details for a specific role, given a plan"""

    log = logging.getLogger(__name__ + ".ShowRole")

    def get_parser(self, prog_name):
        parser = super(ShowRole, self).get_parser(prog_name)
        parser.add_argument(
            '--name',
            dest='name',
            default='overcloud',
            help=_('The name of the plan, which is used for the object '
                   'storage container, workflow environment and orchestration '
                   'stack names.'),
        )
        parser.add_argument('role',
                            metavar="<role>",
                            help=_('Name of the role to look up.'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action({})'.format(parsed_args))

        role = self.get_role_details(parsed_args.name, parsed_args.role)
        if not role:
            raise exceptions.CommandError(
                "Could not find role %s" % parsed_args.role)

        return self.format_role(role)

    def get_role_details(self, name, role_name):
        result = roles.list_available_roles(
            self.app.client_manager,
            container=name)

        for r in result:
            if r['name'] == role_name:
                return r
        return []

    def format_role(self, role):
        column_names = ['Name']
        data = [role.pop('name')]

        if 'description' in role:
            column_names.append('Description')
            data.append(role.pop('description'))
        if 'ServicesDefault' in role:
            column_names.append('Services Default')
            role['ServicesDefault'].sort()
            data.append('\n'.join(role.pop('ServicesDefault')))

        other_fields = list(role.keys())
        other_fields.sort()
        for field in other_fields:
            column_names.append(field)
            data.append(role[field])

        return column_names, data
