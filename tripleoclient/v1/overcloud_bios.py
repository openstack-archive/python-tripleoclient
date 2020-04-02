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

import logging
import os

from osc_lib.i18n import _
import yaml

from tripleoclient import command
from tripleoclient import utils
from tripleoclient.workflows import baremetal


class ConfigureBIOS(command.Command):
    """Apply BIOS configuration on given nodes"""

    log = logging.getLogger(__name__ + ".ConfigureBIOS")

    def get_parser(self, prog_name):
        parser = super(ConfigureBIOS, self).get_parser(prog_name)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('node_uuids',
                           nargs="*",
                           metavar="<node_uuid>",
                           default=[],
                           help=_('Baremetal Node UUIDs for the node(s) to '
                                  'configure BIOS'))
        group.add_argument("--all-manageable",
                           action='store_true',
                           help=_("Configure BIOS for all nodes currently in "
                                  "'manageable' state"))
        parser.add_argument('--configuration', metavar='<configuration>',
                            dest='configuration',
                            help=_('BIOS configuration (YAML/JSON string or '
                                   'file name).'))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action({args})".format(args=parsed_args))

        if os.path.exists(parsed_args.configuration):
            with open(parsed_args.configuration, 'r') as fp:
                configuration = yaml.safe_load(fp.read())
        else:
            try:
                configuration = yaml.safe_load(parsed_args.configuration)
            except yaml.YAMLError as exc:
                raise RuntimeError(
                    _('Configuration is not an existing file and cannot be '
                      'parsed as YAML: %s') % exc)

        # Basic sanity check, we defer the full check to Ironic
        try:
            settings = configuration['settings']
        except KeyError:
            raise ValueError(
                _('Configuration must contain key "settings"'))
        except TypeError:
            raise TypeError(
                _('Configuration must be an object, got %r instead')
                % configuration)

        if (not isinstance(settings, list) or
                not all(isinstance(item, dict) for item in settings)):
            raise TypeError(
                _('BIOS settings list is expected to be a list of '
                  'objects, got %r instead') % settings)

        clients = self.app.client_manager
        if parsed_args.node_uuids:
            baremetal.apply_bios_configuration(
                node_uuids=parsed_args.node_uuids,
                configuration=configuration,
                verbosity=utils.playbook_verbosity(self=self)
            )
        else:
            baremetal.apply_bios_configuration_on_manageable_nodes(
                clients,
                configuration=configuration,
                verbosity=utils.playbook_verbosity(self=self)
            )


class ResetBIOS(command.Command):
    """Reset BIOS configuration to factory default"""

    log = logging.getLogger(__name__ + ".ResetBIOS")

    def get_parser(self, prog_name):
        parser = super(ResetBIOS, self).get_parser(prog_name)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('node_uuids',
                           nargs="*",
                           metavar="<node_uuid>",
                           default=[],
                           help=_('Baremetal Node UUIDs for the node(s) to '
                                  'reset BIOS'))
        group.add_argument("--all-manageable",
                           action='store_true',
                           help=_("Reset BIOS on all nodes currently in "
                                  "'manageable' state"))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action({args})".format(args=parsed_args))

        clients = self.app.client_manager
        if parsed_args.node_uuids:
            baremetal.reset_bios_configuration(
                node_uuids=parsed_args.node_uuids,
                verbosity=utils.playbook_verbosity(self=self)
            )
        else:
            baremetal.reset_bios_configuration_on_manageable_nodes(
                clients=clients,
                verbosity=utils.playbook_verbosity(self=self)
            )
