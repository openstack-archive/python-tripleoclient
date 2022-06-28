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

from argparse import _StoreAction
import logging

from osc_lib.command import command
from osc_lib import exceptions as oscexc

from tripleoclient import exceptions
from tripleoclient import utils


class Command(command.Command):

    log = logging.getLogger(__name__ + ".Command")

    def run(self, parsed_args):
        utils.store_cli_param(self.cmd_name, parsed_args)
        try:
            super(Command, self).run(parsed_args)
        except (oscexc.CommandError, exceptions.Base):
            raise
        except Exception:
            self.log.exception("Exception occured while running the command")
            raise

    def get_key_pair(self, parsed_args):
        """Autodetect or return a user defined key file.

        :param parsed_args: An argparse object.
        :type parsed_args: Object

        :returns: String
        """

        if not parsed_args.overcloud_ssh_key:
            key = utils.get_key(
                stack=parsed_args.stack,
                needs_pair=True
            )
            if not key:
                raise oscexc.CommandError(
                    'No key pair found, set the ssh key using'
                    'the --overcloud-ssh-key switch.'
                )
            return key

        return parsed_args.overcloud_ssh_key

    def _configure_logging(self, parsed_args):
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        self.log.addHandler(handler)
        if self.app_args.verbose_level >= 2:
            handler.setLevel(logging.DEBUG)
        else:
            handler.setLevel(logging.INFO)


class Lister(Command, command.Lister):
    pass


class ShowOne(Command, command.ShowOne):
    pass


class DeprecatedActionStore(_StoreAction):
    """To deprecated an option an store the value"""
    log = logging.getLogger(__name__)

    def __call__(self, parser, namespace, values, option_string=None):
        """Display the warning message"""
        if len(self.option_strings) == 1:
            message = 'The option {option} is deprecated, it will be removed'\
                      ' in a future version'.format(
                          option=self.option_strings[0])
        else:
            option = ', '.join(self.option_strings)
            message = 'The options {option} is deprecated, it will be removed'\
                      ' in a future version'.format(option=option)

        self.log.warning(message)
        super(DeprecatedActionStore, self).__call__(
            parser, namespace, values, option_string)
