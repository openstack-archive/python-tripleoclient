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

import logging

from osc_lib.i18n import _

from tripleoclient import command
from tripleoclient import exceptions
from tripleoclient import utils

DEPRECATION_MSG = '''
This command has been DEPRECATED and will be removed. The compute service is no
longer used on the undercloud by default, hence profile matching with compute
flavors is no longer used.
'''


class MatchProfiles(command.Command):
    """Assign and validate profiles on nodes"""

    log = logging.getLogger(__name__ + ".MatchProfiles")

    def get_parser(self, prog_name):
        parser = super(MatchProfiles, self).get_parser(prog_name)
        parser.epilog = DEPRECATION_MSG
        parser.add_argument(
            '--dry-run',
            action='store_true',
            default=False,
            help=_('Only run validations, but do not apply any changes.')
        )
        utils.add_deployment_plan_arguments(parser)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        self.log.warning(DEPRECATION_MSG)
        bm_client = self.app.client_manager.baremetal

        flavors = self._collect_flavors(parsed_args)

        errors, warnings = utils.assign_and_verify_profiles(
            bm_client, flavors,
            assign_profiles=True,
            dry_run=parsed_args.dry_run
        )
        if errors:
            raise exceptions.ProfileMatchingError(
                _('Failed to validate and assign profiles.'))

    def _collect_flavors(self, parsed_args):
        """Collect nova flavors in use.

        :returns: dictionary flavor name -> (flavor object, scale)
        """
        compute_client = self.app.client_manager.compute

        flavors = {f.name: f for f in compute_client.flavors.list()}
        result = {}

        message = "Provided --{}-flavor, '{}', does not exist"

        for target, (flavor_name, scale) in (
            utils.get_roles_info(parsed_args).items()
        ):
            if flavor_name is None or not scale:
                self.log.debug("--{}-flavor not used".format(target))
                continue

            try:
                flavor = flavors[flavor_name]
            except KeyError:
                raise exceptions.ProfileMatchingError(
                    message.format(target, flavor_name))

            result[flavor_name] = (flavor, scale)

        return result


POSTFIX = '_profile'


class ListProfiles(command.Lister):
    """List overcloud node profiles"""

    log = logging.getLogger(__name__ + ".ListProfiles")

    def get_parser(self, prog_name):
        parser = super(ListProfiles, self).get_parser(prog_name)
        parser.epilog = DEPRECATION_MSG
        parser.add_argument(
            '--all',
            action='store_true',
            default=False,
            help=_('List all nodes, even those not available to Nova.')
        )
        utils.add_deployment_plan_arguments(parser)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        self.log.warning(DEPRECATION_MSG)
        bm_client = self.app.client_manager.baremetal
        compute_client = self.app.client_manager.compute

        hypervisors = {h.hypervisor_hostname: h
                       for h in compute_client.hypervisors.list()
                       if h.hypervisor_type == 'ironic'}
        result = []

        maintenance = None if parsed_args.all else False
        for node in bm_client.node.list(detail=True, maintenance=maintenance):
            error = ''

            if node.provision_state not in ('active', 'available'):
                error = "Provision state %s" % node.provision_state
            elif node.power_state in (None, 'error'):
                error = "Power state %s" % node.power_state
            elif node.maintenance:
                error = "Maintenance"
            else:
                try:
                    hypervisor = hypervisors[node.uuid]
                except KeyError:
                    error = 'No hypervisor record'
                else:
                    if hypervisor.status != 'enabled':
                        error = 'Compute service disabled'
                    elif hypervisor.state != 'up':
                        error = 'Compute service down'

            if error and not parsed_args.all:
                continue

            caps = utils.node_get_capabilities(node)
            profile = caps.get('profile')
            possible_profiles = [k[:-len(POSTFIX)]
                                 for k, v in caps.items()
                                 if k.endswith(POSTFIX) and
                                 v.lower() in ('1', 'true')]
            # sorting for convenient display and testing
            possible_profiles.sort()

            record = (node.uuid, node.name or '', node.provision_state,
                      profile, ', '.join(possible_profiles))
            if parsed_args.all:
                record += (error,)
            result.append(record)

        cols = ("Node UUID", "Node Name", "Provision State", "Current Profile",
                "Possible Profiles")
        if parsed_args.all:
            cols += ('Error',)
        return (cols, result)
