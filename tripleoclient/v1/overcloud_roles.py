#   Copyright 2017 Red Hat, Inc.
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

from __future__ import print_function

import collections
import os
import sys

from tripleo_common.exception import NotFound
from tripleo_common.utils import roles as rolesutils

from tripleoclient import command
from tripleoclient.constants import TRIPLEO_HEAT_TEMPLATES


class RolesBaseCommand(command.Command):
    auth_required = False

    def get_parser(self, prog_name):
        parser = super(RolesBaseCommand, self).get_parser(prog_name)
        path = os.path.join(TRIPLEO_HEAT_TEMPLATES, 'roles')
        parser.add_argument('--roles-path', metavar='<roles directory>',
                            default=path,
                            help='Filesystem path containing the role yaml  '
                                 'files. By default this is {}'.format(path))
        return parser


class RolesGenerate(RolesBaseCommand):
    """Generate roles_data.yaml file"""
    def get_parser(self, prog_name):
        parser = super(RolesGenerate, self).get_parser(prog_name)
        parser.add_argument('-o', '--output-file', metavar='<output file>',
                            help='File to capture all output to. For example, '
                                 'roles_data.yaml')
        parser.add_argument('--skip-validate', action='store_false',
                            help='Skip role metadata type validation when'
                                 'generating the roles_data.yaml')
        parser.add_argument('roles', nargs="+", metavar='<role>',
                            help='List of roles to use to generate the '
                                 'roles_data.yaml file for the deployment. '
                                 'NOTE: Ordering is important if no role has '
                                 'the "primary" and "controller" tags. If no '
                                 'role is tagged then the first role listed '
                                 'will be considered the primary role. This '
                                 'usually is the controller role.')
        return parser

    def _capture_output(self, filename=None):
        """Capture stdout to a file if provided"""
        if filename is not None:
            sys.stdout = open(filename, 'w')

    def _stop_capture_output(self, filename=None):
        """Stop capturing stdout to a file if provided"""
        if filename is not None:
            sys.stdout.close()

    def take_action(self, parsed_args):
        """Generate roles_data.yaml from imputed roles

        From the provided roles, validate that we have yaml files for the each
        role in our roles path and print them out concatenated together in the
        order they were provided.
        """
        self.log.debug('take_action({})'.format(parsed_args))
        roles_path = os.path.realpath(parsed_args.roles_path)
        # eliminate any dupes from the command line with an OrderedDict
        requested_roles = collections.OrderedDict.fromkeys(parsed_args.roles)
        available_roles = rolesutils.get_roles_list_from_directory(roles_path)
        rolesutils.check_role_exists(available_roles,
                                     list(requested_roles.keys()))
        self._capture_output(parsed_args.output_file)
        roles_data = rolesutils.generate_roles_data_from_directory(
            roles_path, list(requested_roles.keys()),
            parsed_args.skip_validate)
        sys.stdout.write(roles_data)
        self._stop_capture_output(parsed_args.output_file)


class RoleList(RolesBaseCommand):
    """List availables roles (DEPRECATED).

    Please use "openstack overcloud roles list" instead.
    """
    def get_parser(self, prog_name):
        parser = super(RoleList, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action({})'.format(parsed_args))
        self.log.warning('This command is deprecated. Please use "openstack '
                         'overcloud roles list" instead.')
        roles_path = os.path.realpath(parsed_args.roles_path)
        roles = rolesutils.get_roles_list_from_directory(roles_path)
        print('\n'.join(roles))


class RoleShow(RolesBaseCommand):
    """Show information about a given role (DEPRECATED).


    Please use "openstack overcloud roles show" intead.
    """
    def get_parser(self, prog_name):
        parser = super(RoleShow, self).get_parser(prog_name)
        parser.add_argument('role', metavar='<role>',
                            help='Role to display more information about.')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action({})'.format(parsed_args))
        self.log.warning('This command is deprecated. Please use "openstack '
                         'overcloud roles show" instead.')
        roles_path = os.path.realpath(parsed_args.roles_path)
        role_name = parsed_args.role
        file_path = os.path.join(roles_path, '{}.yaml'.format(role_name))
        try:
            with open(file_path, 'r') as f:
                role = rolesutils.validate_role_yaml(f)
        except IOError:
            raise NotFound("Role '{}' not found. Use 'openstack overcloud "
                           "roles list' to see the available roles.".
                           format(parsed_args.role))

        if 'name' in role:
            print('#' * 79)
            print("# Role Data for '{}'".format(role['name']))
            print('#' * 79)

        for key in sorted(role.keys()):
            print("{}:".format(key), end='')
            value = role[key]

            if isinstance(value, (list, tuple)):
                print('')
                print('\n'.join([' * {0}'.format(v) for v in value]))
            else:
                print(" '{}'".format(value))
