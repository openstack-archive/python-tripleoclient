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

from __future__ import print_function

import argparse
import json
import logging
import time
import uuid

from osc_lib.command import command
from osc_lib.i18n import _

from tripleoclient import exceptions
from tripleoclient import utils
from tripleoclient.workflows import baremetal


class ValidateInstackEnv(command.Command):
    """Validate `instackenv.json` which is used in `baremetal import`."""

    auth_required = False
    log = logging.getLogger(__name__ + ".ValidateInstackEnv")

    def get_parser(self, prog_name):
        parser = super(ValidateInstackEnv, self).get_parser(prog_name)
        parser.add_argument(
            '-f', '--file', dest='instackenv',
            help=_("Path to the instackenv.json file."),
            default='instackenv.json')
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        self.error_count = 0

        with open(parsed_args.instackenv, 'r') as net_file:
            env_data = json.load(net_file)

        maclist = []
        baremetal_ips = []
        for node in env_data['nodes']:
            self.log.info("Checking node %s" % node['pm_addr'])

            try:
                if len(node['pm_password']) == 0:
                    self.log.error('ERROR: Password 0 length.')
                    self.error_count += 1
            except Exception as e:
                self.log.error('ERROR: Password does not exist: %s', e)
                self.error_count += 1
            try:
                if len(node['pm_user']) == 0:
                    self.log.error('ERROR: User 0 length.')
                    self.error_count += 1
            except Exception as e:
                self.log.error('ERROR: User does not exist: %s', e)
                self.error_count += 1
            try:
                if len(node['mac']) == 0:
                    self.log.error('ERROR: MAC address 0 length.')
                    self.error_count += 1
                maclist.extend(node['mac'])
            except Exception as e:
                self.log.error('ERROR: MAC address does not exist: %s', e)
                self.error_count += 1

            if node['pm_type'] == "pxe_ssh":
                self.log.debug("Identified virtual node")

            if node['pm_type'] == "pxe_ipmitool":
                self.log.debug("Identified baremetal node")

                cmd = ('ipmitool -R 1 -I lanplus -H %s -U %s -P %s chassis '
                       'status' % (node['pm_addr'], node['pm_user'],
                                   node['pm_password']))
                self.log.debug("Executing: %s", cmd)
                status = utils.run_shell(cmd)
                if status != 0:
                    self.log.error('ERROR: ipmitool failed')
                    self.error_count += 1
                baremetal_ips.append(node['pm_addr'])

        if not utils.all_unique(baremetal_ips):
            self.log.error('ERROR: Baremetals IPs are not all unique.')
            self.error_count += 1
        else:
            self.log.debug('Baremetal IPs are all unique.')

        if not utils.all_unique(maclist):
            self.log.error('ERROR: MAC addresses are not all unique.')
            self.error_count += 1
        else:
            self.log.debug('MAC addresses are all unique.')

        if self.error_count == 0:
            print('SUCCESS: found 0 errors')
        else:
            print('FAILURE: found %d errors' % self.error_count)


class ImportBaremetal(command.Command):
    """Import baremetal nodes from a JSON, YAML or CSV file"""

    log = logging.getLogger(__name__ + ".ImportBaremetal")

    def get_parser(self, prog_name):
        parser = super(ImportBaremetal, self).get_parser(prog_name)
        parser.add_argument('-s', '--service-host', dest='service_host',
                            help=_('Deprecated, this argument has no impact.'))
        parser.add_argument(
            '--json', dest='json', action='store_true',
            help=_('Deprecated, now detected via file extension.'))
        parser.add_argument(
            '--csv', dest='csv', action='store_true',
            help=_('Deprecated, now detected via file extension.'))
        parser.add_argument('--deploy-kernel',
                            default='bm-deploy-kernel',
                            help=_('Image with deploy kernel.'))
        parser.add_argument('--deploy-ramdisk',
                            default='bm-deploy-ramdisk',
                            help=_('Image with deploy ramdisk.'))
        parser.add_argument('--no-deploy-image', action='store_true',
                            help=_('Skip setting the deploy kernel and '
                                   'ramdisk.'))
        parser.add_argument('--instance-boot-option',
                            choices=['local', 'netboot'], default='local',
                            help=_('Whether to set instances for booting from '
                                   'local hard drive (local) or network '
                                   '(netboot).'))
        parser.add_argument('file_in', type=argparse.FileType('r'))
        parser.add_argument(
            '--initial-state',
            choices=['enroll', 'available'],
            default='available',
            help=_('Provision state for newly-enrolled nodes.')
        )

        return parser

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)

        file_type = None
        if parsed_args.json:
            file_type = 'json'
        elif parsed_args.csv:
            file_type = 'csv'

        nodes_config = utils.parse_env_file(parsed_args.file_in, file_type)

        client = self.app.client_manager.baremetal
        if parsed_args.initial_state == "enroll":
            api_version = client.http_client.os_ironic_api_version
            if [int(part) for part in api_version.split('.')] < [1, 11]:
                raise exceptions.InvalidConfiguration(
                    _("OS_BAREMETAL_API_VERSION must be >=1.11 for use of "
                      "'enroll' provision state; currently %s") % api_version)

        queue_name = str(uuid.uuid4())

        if parsed_args.no_deploy_image:
            deploy_kernel = None
            deploy_ramdisk = None
        else:
            deploy_kernel = parsed_args.deploy_kernel
            deploy_ramdisk = parsed_args.deploy_ramdisk

        nodes = baremetal.register_or_update(
            self.app.client_manager,
            nodes_json=nodes_config,
            queue_name=queue_name,
            kernel_name=deploy_kernel,
            ramdisk_name=deploy_ramdisk,
            instance_boot_option=parsed_args.instance_boot_option
        )

        if parsed_args.initial_state == "available":
            # NOTE(dtantsur): newly enrolled nodes state is reported as
            # "enroll" from the workflow even though it's actually "manageable"
            # because the node list is built before "manage" action is run.
            node_uuids = [node['uuid'] for node in nodes
                          if node['provision_state'] in {'manageable',
                                                         'enroll'}]
            baremetal.provide(self.app.client_manager, node_uuids=node_uuids,
                              queue_name=queue_name)


class StartBaremetalIntrospectionBulk(command.Command):
    """Start bulk introspection on all baremetal nodes."""

    log = logging.getLogger(__name__ + ".StartBaremetalIntrospectionBulk")

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)

        queue_name = str(uuid.uuid4())
        clients = self.app.client_manager
        client = self.app.client_manager.baremetal

        # TODO(d0ugal): We don't yet have a workflow to move from available
        # or enroll to manageable. Once we do, this should be switched over.
        print("Setting nodes for introspection to manageable...")
        self.log.debug("Moving available/enroll nodes to manageable state.")
        available_nodes = utils.nodes_in_states(client, ("available",
                                                         "enroll"))
        for node_uuid in utils.set_nodes_state(client, available_nodes,
                                               'manage', 'manageable'):
            self.log.debug(
                "Node {0} has been set to manageable.".format(node_uuid))

        print("Starting introspection of manageable nodes")
        baremetal.introspect_manageable_nodes(clients, queue_name=queue_name)

        print("Setting manageable nodes to available...")
        self.log.debug("Moving manageable nodes to available state.")

        baremetal.provide_manageable_nodes(clients, queue_name=queue_name)


class StatusBaremetalIntrospectionBulk(command.Lister):
    """Get the status of all baremetal nodes"""

    log = logging.getLogger(__name__ + ".StatusBaremetalIntrospectionBulk")

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)
        client = self.app.client_manager.baremetal
        inspector_client = self.app.client_manager.baremetal_introspection

        statuses = []

        for node in client.node.list():
            self.log.debug("Getting introspection status of Ironic node {0}"
                           .format(node.uuid))

            statuses.append((node.uuid,
                             inspector_client.get_status(node.uuid)))

        return (
            ("Node UUID", "Finished", "Error"),
            list((node_uuid, status['finished'], status['error'])
                 for (node_uuid, status) in statuses)
        )


class ConfigureReadyState(command.Command):
    """Configure all baremetal nodes for enrollment"""

    log = logging.getLogger(__name__ + ".ConfigureReadyState")
    sleep_time = 15
    loops = 120

    def _configure_bios(self, nodes):
        nodes_with_reboot_request = set()

        for node, profile in nodes:
            if (profile in self.ready_state_config and
                    'bios_settings' in self.ready_state_config[profile]):

                print("Configuring BIOS for node {0}".format(node.uuid))
                settings = self.ready_state_config[profile]['bios_settings']
                resp = self.bm_client.node.vendor_passthru(
                    node.uuid, 'set_bios_config', http_method='POST',
                    args=settings)

                if resp.commit_required:
                    nodes_with_reboot_request.add(node)
                    self.bm_client.node.vendor_passthru(
                        node.uuid, 'commit_bios_config', http_method='POST')

        # NOTE(ifarkas): give the DRAC card some time to process the job
        time.sleep(self.sleep_time)

        return nodes_with_reboot_request

    def _wait_for_drac_config_jobs(self, nodes):
        for node in nodes:
            print("Waiting for DRAC config jobs to finish on node {0}"
                  .format(node.uuid))

            for _r in range(self.loops):
                resp = self.bm_client.node.vendor_passthru(
                    node.uuid, 'list_unfinished_jobs', http_method='GET')
                if not resp.unfinished_jobs:
                    break

                time.sleep(self.sleep_time)
            else:
                msg = ("Timed out waiting for DRAC config jobs on node {0}"
                       .format(node.uuid))
                raise exceptions.Timeout(msg)

    def _change_power_state(self, nodes, target_power_state):
        for node in nodes:
            print("Changing power state on "
                  "node {0} to {1}".format(node.uuid, target_power_state))
            self.bm_client.node.set_power_state(node.uuid, target_power_state)

    def _apply_changes(self, nodes):
        self._change_power_state(nodes, 'reboot')
        self._wait_for_drac_config_jobs(nodes)

    def get_parser(self, prog_name):
        parser = super(ConfigureReadyState, self).get_parser(prog_name)
        parser.add_argument('file', help=_('JSON file containing the '
                            'ready-state configuration for each profile'))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        self.bm_client = self.app.client_manager.baremetal

        with open(parsed_args.file, 'r') as fp:
            self.ready_state_config = json.load(fp)

        drac_nodes = []
        for node in self.bm_client.node.list(detail=True):
            if 'drac' not in node.driver:
                continue

            selected_profile = utils.node_get_capabilities(node).get('profile')
            if selected_profile is None:
                continue

            drac_nodes.append((node, selected_profile))

        changed_nodes = self._configure_bios(drac_nodes)
        self._apply_changes(changed_nodes)

        self._change_power_state([node for node, profile in drac_nodes], 'off')


class ConfigureBaremetalBoot(command.Command):
    """Configure baremetal boot for all nodes"""

    log = logging.getLogger(__name__ + ".ConfigureBaremetalBoot")
    loops = 12
    sleep_time = 10

    def get_parser(self, prog_name):
        parser = super(ConfigureBaremetalBoot, self).get_parser(prog_name)
        parser.add_argument('--deploy-kernel',
                            default='bm-deploy-kernel',
                            help=_('Image with deploy kernel.'))
        parser.add_argument('--deploy-ramdisk',
                            default='bm-deploy-ramdisk',
                            help=_('Image with deploy ramdisk.'))
        parser.add_argument('--root-device',
                            help=_('Define the root device for nodes. '
                                   'Can be either a list of device names '
                                   '(without /dev) to choose from or one of '
                                   'two strategies: largest or smallest. For '
                                   'it to work this command should be run '
                                   'after the introspection.'))
        parser.add_argument('--root-device-minimum-size',
                            type=int, default=4,
                            help=_('Minimum size (in GiB) of the detected '
                                   'root device. Used with --root-device.'))
        parser.add_argument('--overwrite-root-device-hints',
                            action='store_true',
                            help=_('Whether to overwrite existing root device '
                                   'hints when --root-device is used.'))
        return parser

    def take_action(self, parsed_args):

        self.log.debug("take_action(%s)" % parsed_args)

        queue_name = str(uuid.uuid4())
        bm_client = self.app.client_manager.baremetal

        for node in bm_client.node.list(maintenance=False):
            # NOTE(bnemec): Ironic won't let us update the node while the
            # power_state is transitioning.
            # Make sure we have the current node state, and not a cached one
            # from the list call above, which may have happened minutes ago.
            node_detail = bm_client.node.get(node.uuid)
            if node_detail.power_state is None:
                self.log.warning('Node %s power state is in transition. '
                                 'Waiting up to %d seconds for it to '
                                 'complete.',
                                 node_detail.uuid,
                                 self.loops * self.sleep_time)
                for _r in range(self.loops):
                    time.sleep(self.sleep_time)
                    node_detail = bm_client.node.get(node.uuid)
                    if node_detail.power_state is not None:
                        break
                else:
                    msg = ('Timed out waiting for node %s power state.' %
                           node.uuid)
                    raise exceptions.Timeout(msg)

            baremetal.configure(
                self.app.client_manager,
                node_uuids=[node.uuid],
                queue_name=queue_name,
                kernel_name=parsed_args.deploy_kernel,
                ramdisk_name=parsed_args.deploy_ramdisk,
                root_device=parsed_args.root_device,
                root_device_minimum_size=parsed_args.root_device_minimum_size,
                overwrite_root_device_hints=(
                    parsed_args.overwrite_root_device_hints)
            )


class ShowNodeCapabilities(command.Lister):
    """List the capabilities for all Nodes"""

    log = logging.getLogger(__name__ + ".ShowNodeProfile")

    def take_action(self, parsed_args):
        self.log.warning('This command is deprecated and will be removed soon '
                         'please use "openstack overcloud profiles list" to '
                         'get the list of all nodes and their profiles')
        bm_client = self.app.client_manager.baremetal
        rows = []
        for node in bm_client.node.list():
            node_detail = bm_client.node.get(node.uuid)
            capabilities = node_detail.properties.get('capabilities')
            rows.append((node.uuid, capabilities))
        return (("Node UUID", "Node Capabilities"), rows, )
