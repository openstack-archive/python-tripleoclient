#   Copyright 2016 Red Hat, Inc.
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

from osc_lib.command import command
from osc_lib.i18n import _
import uuid
import yaml

from tripleoclient.workflows import baremetal


class CreateRAID(command.Command):
    """Create RAID on given nodes"""

    log = logging.getLogger(__name__ + ".CreateRAID")

    def get_parser(self, prog_name):
        parser = super(CreateRAID, self).get_parser(prog_name)
        parser.add_argument('--node', action='append', required=True,
                            help=_('Nodes to create RAID on (expected to be '
                                   'in manageable state). Can be specified '
                                   'multiple times.'))
        parser.add_argument('configuration',
                            help=_('RAID configuration (YAML/JSON string or '
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
            disks = configuration['logical_disks']
        except KeyError:
            raise ValueError(
                _('Configuration must contain key "logical_disks"'))
        except TypeError:
            raise TypeError(
                _('Configuration must be an object, got %r instead')
                % configuration)

        if (not isinstance(disks, list) or
                not all(isinstance(item, dict) for item in disks)):
            raise TypeError(
                _('Logical disks list is expected to be a list of objects, '
                  'got %r instead') % disks)

        queue_name = str(uuid.uuid4())
        clients = self.app.client_manager
        baremetal.create_raid_configuration(clients,
                                            queue_name=queue_name,
                                            node_uuids=parsed_args.node,
                                            configuration=configuration)
