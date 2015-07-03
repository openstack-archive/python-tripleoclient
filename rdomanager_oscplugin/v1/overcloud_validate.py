#   Copyright 2015 Red Hat, Inc.
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

import logging
import os

from cliff import command

from rdomanager_oscplugin import utils


class ValidateOvercloud(command.Command):
    """Validates the functionality of an overcloud using Tempest"""

    auth_required = False
    log = logging.getLogger(__name__ + ".ValidateOvercloud")

    def _run_tempest(self, overcloud_auth_url, overcloud_admin_password,
                     tempest_args, skipfile):
        tempest_run_dir = os.path.join(os.path.expanduser("~"), "tempest")
        try:
            os.stat(tempest_run_dir)
        except OSError:
            os.mkdir(tempest_run_dir)

        os.chdir(tempest_run_dir)

        utils.run_shell('/usr/share/openstack-tempest-kilo/tools/'
                        'configure-tempest-directory')
        utils.run_shell('./tools/config_tempest.py --out etc/tempest.conf '
                        '--debug --create '
                        'identity.uri %(auth_url)s '
                        'compute.allow_tenant_isolation true '
                        'object-storage.operator_role SwiftOperator '
                        'identity.admin_password %(admin_password)s '
                        'compute.build_timeout 500 '
                        'compute.image_ssh_user cirros '
                        'compute.ssh_user cirros '
                        'network.build_timeout 500 '
                        'volume.build_timeout 500 '
                        'scenario.ssh_user cirros' %
                        {'auth_url': overcloud_auth_url,
                         'admin_password': overcloud_admin_password})

        args = ['./tools/run-tests.sh', ]

        if tempest_args is not None:
            args.append(tempest_args)
        if skipfile is not None:
            args.extend(['--skip-file', skipfile])

        utils.run_shell(' '.join(args))

    def get_parser(self, prog_name):
        parser = super(ValidateOvercloud, self).get_parser(prog_name)

        parser.add_argument('--overcloud-auth-url', required=True)
        parser.add_argument('--overcloud-admin-password', required=True)
        parser.add_argument('--tempest-args')
        parser.add_argument('--skipfile')

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        self._run_tempest(parsed_args.overcloud_auth_url,
                          parsed_args.overcloud_admin_password,
                          parsed_args.tempest_args,
                          parsed_args.skipfile)
