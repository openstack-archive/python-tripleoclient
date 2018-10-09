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

import logging

from osc_lib.command import command
from tripleoclient import utils


class Command(command.Command):

    log = logging.getLogger(__name__ + ".Command")

    def run(self, parsed_args):
        utils.store_cli_param(self.cmd_name, parsed_args)
        try:
            super(Command, self).run(parsed_args)
        except Exception:
            self.log.exception("Exception occured while running the command")
            raise


class Lister(Command, command.Lister):
    pass
