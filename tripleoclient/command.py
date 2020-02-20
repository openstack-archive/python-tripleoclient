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

from tripleo_common.utils import config

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

    @staticmethod
    def get_ansible_key_and_dir(no_workflow, stack, orchestration):
        """Return the ansible directory and key path.

        :param no_workflow: Enable or disable the mistral workflow code path.
        :type no_workflow: Boolean

        :oaram stack: Name of a given stack to run against.
        :type stack: String

        :param orchestration: Orchestration client object.
        :type orchestration: Object

        :returns: Tuple
        """

        if no_workflow:
            key = utils.get_key(stack=stack)
            stack_config = config.Config(orchestration)
            with utils.TempDirs(chdir=False) as tmp:
                stack_config.write_config(
                    stack_config.fetch_config(stack),
                    stack,
                    tmp
                )
                return key, tmp
        else:
            # Assumes execution will take place from within a mistral
            # container.
            key = '.ssh/tripleo-admin-rsa'
            return key, None

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
        else:
            return parsed_args.overcloud_ssh_key


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
