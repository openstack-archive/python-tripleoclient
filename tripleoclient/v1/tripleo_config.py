#   Copyright 2018 Red Hat, Inc.
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

import argparse
import logging

from cliff import command
from osc_lib.i18n import _

# For ansible.cfg generation
from tripleo_common.actions import ansible


class GenerateAnsibleConfig(command.Command):
    """Generate the default ansible.cfg for deployments."""

    log = logging.getLogger(__name__ + ".GenerateAnsibleConfig")

    def get_parser(self, prog_name):
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False
        )
        parser.add_argument('--output-dir',
                            dest='output_dir',
                            help=_("Directory to output ansible.cfg and "
                                   "ansible.log files."),
                            default='.')
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        ansible.write_default_ansible_cfg(parsed_args.output_dir)
