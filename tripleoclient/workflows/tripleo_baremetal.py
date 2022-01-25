# -*- coding: utf-8 -*-
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging
from typing import Dict
from typing import List

from concurrent import futures
from openstack import connect as sdkclient
from openstack import exceptions
from openstack.utils import iterate_timeout
from tripleoclient import exceptions as ooo_exceptions


class TripleoBaremetal(object):

    """Base class for TripleO Baremetal operations.

    The TripleoBase class provides access to commonly used elements
    required to interact with and perform baremetal operations for TripleO.

    :param timeout: How long to wait until we consider this job to have
                    timed out
    :type timeout: integer

    :param verbosity: How verbose should we be. Currently, this just sets
                      DEBUG for any non-zero value provided.
    :type verbosity: integer
    """

    def __init__(self, timeout: int = 1200, verbosity: int = 1):
        self.conn = sdkclient(
            cloud='undercloud'
        )
        self.timeout = timeout
        self.log = logging.getLogger(__name__)
        if verbosity > 0:
            self.log.setLevel(logging.DEBUG)

    def all_manageable_nodes(self):
        """This method returns a list of manageable nodes from Ironic

        We take no arguments and instead create a list of nodes that
        are in the manageable state and NOT in maintenenace. We return the
        subsequent list.

        Raises:
          NoNodeFound: If no nodes match the above description, we will raise
                       an exception.

        Returns:
          nodes: The List of manageable nodes that are not currently in
                 maintenance.
        """
        nodes = [n.id for n in self.conn.baremetal.nodes(
            provision_state='manageable', is_maintenance=False)]

        if not nodes:
            raise ooo_exceptions.NoNodeFound

        return nodes


class TripleoProvide(TripleoBaremetal):

    """TripleoProvide handles state transition of baremetal nodes.

    The TripleoProvide class handles the transition of nodes between the
    manageable and available states.

    :param wait_for_bridge_mapping: Bool to determine whether or not we are
                                    waiting for the bridge mapping to be
                                    active in ironic-neutron-agent
    :type wait_for_bridge_mapping: bool

    """

    def __init__(self, wait_for_bridge_mappings: bool = False,
                 verbosity: int = 1):

        super().__init__(verbosity)
        self.wait_for_bridge_mappings = wait_for_bridge_mappings

    def _wait_for_unlocked(self, node: str, timeout: int):
        timeout_msg = f'Timeout waiting for node {node} to be unlocked'

        for count in iterate_timeout(timeout, timeout_msg):
            node_info = self.conn.baremetal.get_node(
                node,
                fields=['reservation']
            )

            if node_info.reservation is None:
                return

    def _wait_for_bridge_mapping(self, node: str):

        client = self.conn.network
        timeout_msg = (f'Timeout waiting for node {node} to have '
                       'bridge_mappings set in the ironic-neutron-agent '
                       'entry')

        # default agent polling period is 30s, so wait 60s
        timeout = 60

        for count in iterate_timeout(timeout, timeout_msg):
            agents = list(
                client.agents(host=node, binary='ironic-neutron-agent'))

            if agents:
                if agents[0].configuration.get('bridge_mappings'):
                    return

    def provide(self, nodes: str):

        """Transition nodes to the Available state.

        provide handles the state transition from the nodes current state
        to the available state

        :param nodes: The node UUID or name that we will be working on
        :type nodes: String
        """

        client = self.conn.baremetal
        node_timeout = self.timeout
        nodes_wait = nodes[:]

        for node in nodes:
            self.log.info('Providing node: {}'.format(node))
            self._wait_for_unlocked(node, node_timeout)

            if self.wait_for_bridge_mappings:
                self._wait_for_bridge_mapping(node)

            try:
                client.set_node_provision_state(
                    node,
                    "provide",
                    wait=False)

            except Exception as e:
                nodes_wait.remove(node)
                self.log.error(
                    "Can not start providing for node {}: {}".format(
                        nodes, e))
                return

        try:
            self.log.info(
                "Waiting for available state: {}".format(nodes_wait))

            client.wait_for_nodes_provision_state(
                nodes=nodes_wait,
                expected_state='available',
                timeout=self.timeout,
                fail=False
            )

        except exceptions.ResourceFailure as e:
            self.log.error("Failed providing nodes due to failure: {}".format(
                e))
            return

        except exceptions.ResourceTimeout as e:
            self.log.error("Failed providing nodes due to timeout: {}".format(
                e))

    def provide_manageable_nodes(self):
        self.provide(self.all_manageable_nodes())


class TripleoClean(TripleoBaremetal):

    """TripleoClean manages the Ironic node cleaning process.

    :param all_manageable: Should we work on all nodes in the manageable state
    :type all_manageable: bool

    :param provide: Should we also set the nodes back to the available state
    :type provide: bool

    :param timeout: How long should we wait before we consider the nodes to
                    have failed.
    :type timeout: integer

    :param raid_config: The raid configuration we should configure on the node
    :type raid_config: Dictionary

    :param concurrency: How many nodes should we do at once
    :type concurrency: integer

    :param clean_steps: The Ironic cleaning steps that should be executed on
                        the nodes
    :type clean_steps: List
    """
    log = logging.getLogger(__name__)

    def __init__(self, all_manageable: bool = False, provide: bool = False,
                 timeout: int = 60, raid_config: Dict = {},
                 concurrency: int = 1, verbosity: int = 0,
                 clean_steps: List = [{'interface': 'deploy',
                                       'step': 'erase_devices_metadata'}]):
        super().__init__(verbosity=verbosity, timeout=timeout)
        self.all_manageable = all_manageable
        self.provide = provide
        self.raid_config = raid_config
        self.clean_steps = clean_steps
        self.concurrency = concurrency

    def _parallel_nodes_cleaning(self, nodes: List):
        client = self.conn.baremetal
        node_timeout = self.timeout
        clean_steps = self.clean_steps
        failed_nodes = []
        success_nodes = []
        if self.raid_config:
            for node in nodes:
                try:
                    client.update_node(
                        node,
                        target_raid_config=self.raid_config
                    )
                    success_nodes.append(node)
                    self.log.info("Setting the raid configuration "
                                  "for node {} succeeded.".format(node))
                except exceptions.BadRequestException as err:
                    self.log.error("Setting raid configuration "
                                   "for node {} failed. Error: {}".format(
                                       node, err
                                   ))
                    failed_nodes.append(node)
                    nodes.pop(nodes.index(node))
        workers = min(len(nodes), self.concurrency) or 1
        with futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_build = {
                executor.submit(
                    client.set_node_provision_state,
                    node,
                    "clean",
                    clean_steps=clean_steps,
                    wait=True
                ): node for node in nodes
            }
            done, not_done = futures.wait(
                future_to_build,
                timeout=node_timeout,
                return_when=futures.ALL_COMPLETED
            )
        try:
            self.log.info(
                "Waiting for manageable state: {}".format(nodes))
            res = client.wait_for_nodes_provision_state(
                    nodes=nodes,
                    expected_state='manageable',
                    timeout=self.timeout,
                    fail=False
                )
        except exceptions.ResourceFailure as e:
            self.log.error("Failed providing nodes due to failure: {}".format(
                e))
        except exceptions.ResourceTimeout as e:
            self.log.error("Failed providing nodes due to timeout: {}".format(
                e))
        finally:
            err_nodes = [n.name for n in res if n.last_error]
            s_nodes = [n.name for n in res if not n.last_error]
            for node in err_nodes:
                failed_nodes.append(node)
            for node in s_nodes:
                success_nodes.append(node)

        return(set(failed_nodes), set(success_nodes))

    def clean_manageable_nodes(self):
        self.clean(nodes=self.all_manageable_nodes())

    def clean(self, nodes: List):
        """clean manages the cleaning process for the Ironic nodes.

        Using the provided clean steps, this method will clean the provided
        baremetal nodes.

        :param nodes: A list of nodes to clean
        :type nodes: List
        """
        if not nodes:
            self.log.error("Provide either UUID or names of nodes!")
            try:
                failed_nodes, success_nodes = self._parallel_nodes_cleaning(
                    nodes)
                if failed_nodes:
                    msg = ("Cleaning completed with failures. "
                           f"{failed_nodes} node(s) failed.")
                    self.log.error(msg)
                else:
                    msg = ("Cleaning completed "
                           f"successfully: {len(success_nodes)} nodes")
                    self.log.info(msg)
            except exceptions.OpenStackCloudException as err:
                self.log.error(str(err))
