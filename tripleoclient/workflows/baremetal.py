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
import socket
import netaddr
import tempfile

import ironic_inspector_client
from oslo_concurrency import processutils
from oslo_utils import units
from tripleo_common import exception as tc_exceptions
from tripleo_common.utils import nodes as node_utils

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils

LOG = logging.getLogger(__name__)


def validate_nodes(clients, nodes_json):
    """Validate nodes.

    :param clients: Application client object.
    :type clients: Object

    :param nodes_json:
    :type nodes_json: Object

    :returns: Boolean
    """
    validated_nodes = node_utils.validate_nodes(nodes_json)
    if not validated_nodes:
        return True
    raise exceptions.RegisterOrUpdateError(validated_nodes)


def register_or_update(clients, nodes_json, kernel_name=None,
                       ramdisk_name=None, instance_boot_option=None,
                       boot_mode=None):
    """Node Registration or Update

    :param clients: Application client object.
    :type clients: Object

    :param nodes_json:
    :type nodes_json: Object

    :param kernel_name: Kernel to use
    :type kernel_name: String

    :param ramdisk_name: RAMDISK to use
    :type ramdisk_name: String

    :param instance_boot_option: Whether to set instances for booting from
                                 local hard drive (local) or network
                                 (netboot).
    :type instance_boot_option: String
    :param boot_mode: Whether to set the boot mode to UEFI (uefi) or legacy
                      BIOS (bios)
    :type boot_mode: String

    :returns: List
    """

    for node in nodes_json:
        caps = node.get('capabilities', {})
        caps = node_utils.capabilities_to_dict(caps)
        if instance_boot_option:
            caps.setdefault('boot_option', instance_boot_option)
        if boot_mode:
            caps.setdefault('boot_mode', boot_mode)
        node['capabilities'] = node_utils.dict_to_capabilities(caps)

    registered_nodes = node_utils.register_all_nodes(
        nodes_json,
        client=clients.baremetal,
        kernel_name=kernel_name,
        ramdisk_name=ramdisk_name)
    if not isinstance(registered_nodes, list):
        raise exceptions.RegisterOrUpdateError(registered_nodes)
    else:
        for node in registered_nodes:
            if node.provision_state == 'enroll':
                clients.baremetal.node.set_provision_state(
                    node_uuid=node.uuid,
                    state='manage'
                )
                print('Successfully registered node UUID {}'.format(node.uuid))
            else:
                print('Node UUID {} is already registered'.format(node.uuid))

    return registered_nodes


def introspect(clients, node_uuids, run_validations, concurrency,
               node_timeout, max_retries, retry_timeout, verbosity=0):
    """Introspect Baremetal Nodes

    :param clients: Application client object.
    :type clients: Object

    :param node_uuids: List of instance UUID(s).
    :type node_uuids: List

    :param run_validations: Enable or disable validations
    :type run_validations: Boolean

    :param concurrency: concurrency level
    :type concurrency: Integer

    :param verbosity: Verbosity level
    :type verbosity: Integer
    """

    with utils.TempDirs() as tmp:
        utils.run_ansible_playbook(
            playbook='cli-baremetal-introspect.yaml',
            inventory='localhost,',
            workdir=tmp,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=verbosity,
            extra_vars={
                "node_uuids": node_uuids,
                "run_validations": run_validations,
                "concurrency": concurrency,
                "node_timeout": node_timeout,
                "max_retries": max_retries,
                "retry_timeout": retry_timeout,

            }
        )

    print('Successfully introspected nodes: {}'.format(node_uuids))


def introspect_manageable_nodes(clients, run_validations, concurrency,
                                node_timeout, max_retries, retry_timeout,
                                verbosity=0):
    """Introspect all manageable nodes

    :param clients: Application client object.
    :type clients: Object

    :param run_validations: Enable or disable validations
    :type run_validations: Boolean

    :param concurrency: Concurrency level
    :type concurrency: Integer

    :param node_timeout: Node timeout for introspection
    :type node_timeout: Integer

    :param max_retries: Max retries for introspection
    :type max_retries: Integer

    :param retry_timeout: Max timeout to wait between retries
    :type retry_timeout: Integer

    :param verbosity: Verbosity level
    :type verbosity: Integer
    """

    introspect(
        clients=clients,
        node_uuids=[
            i.uuid for i in clients.baremetal.node.list()
            if i.provision_state == "manageable" and not i.maintenance
        ],
        run_validations=run_validations,
        concurrency=concurrency,
        node_timeout=node_timeout,
        max_retries=max_retries,
        retry_timeout=retry_timeout,
        verbosity=verbosity
    )


def _configure_boot(clients, node_uuid,
                    kernel_name=None,
                    ramdisk_name=None,
                    instance_boot_option=None,
                    boot_mode=None):
    baremetal_client = clients.baremetal
    image_ids = {'kernel': kernel_name, 'ramdisk': ramdisk_name}
    node = baremetal_client.node.get(node_uuid)
    capabilities = node.properties.get('capabilities', {})
    capabilities = node_utils.capabilities_to_dict(capabilities)
    if instance_boot_option is not None:
        capabilities['boot_option'] = instance_boot_option
    if boot_mode is not None:
        capabilities['boot_mode'] = boot_mode
    capabilities = node_utils.dict_to_capabilities(capabilities)

    baremetal_client.node.update(node.uuid, [
        {
            'op': 'add',
            'path': '/properties/capabilities',
            'value': capabilities,
        },
        {
            'op': 'add',
            'path': '/driver_info/deploy_ramdisk',
            'value': image_ids['ramdisk'],
        },
        {
            'op': 'add',
            'path': '/driver_info/deploy_kernel',
            'value': image_ids['kernel'],
        },
        {
            'op': 'add',
            'path': '/driver_info/rescue_ramdisk',
            'value': image_ids['ramdisk'],
        },
        {
            'op': 'add',
            'path': '/driver_info/rescue_kernel',
            'value': image_ids['kernel'],
        },
    ])


def _apply_root_device_strategy(clients, node_uuid, strategy,
                                minimum_size=4, overwrite=False):
    node = clients.baremetal.node.get(node_uuid)
    if node.properties.get('root_device') and not overwrite:
        # This is a correct situation, we still want to allow people to
        # fine-tune the root device setting for a subset of nodes.
        # However, issue a warning, so that they know which nodes were not
        # updated during this run.
        LOG.warning('Root device hints are already set for node %s '
                    'and overwriting is not requested, skipping',
                    node.uuid)
        LOG.warning('You may unset them by running $ openstack baremetal node '
                    'unset --properties root_device %s',
                    node.uuid)
        return

    inspector_client = clients.baremetal_introspection
    baremetal_client = clients.baremetal
    try:
        data = inspector_client.get_data(node.uuid)
    except ironic_inspector_client.ClientError:
        raise exceptions.RootDeviceDetectionError(
            'No introspection data found for node %s, '
            'root device cannot be detected' % node.uuid)
    except AttributeError:
        raise RuntimeError('Ironic inspector client version 1.2.0 or '
                           'newer is required for detecting root device')

    try:
        disks = data['inventory']['disks']
    except KeyError:
        raise exceptions.RootDeviceDetectionError(
            'Malformed introspection data for node %s: '
            'disks list is missing' % node.uuid)

    minimum_size *= units.Gi
    disks = [d for d in disks if d.get('size', 0) >= minimum_size]

    if not disks:
        raise exceptions.RootDeviceDetectionError(
            'No suitable disks found for node %s' % node.uuid)

    for disk in disks:
        # NOTE(TheJulia): An md device should not explicitly forced,
        # If software raid, Ironic knows exactly what it is doing.
        if 'md' in disk['name']:
            LOG.warning('A "md" device %(md)s, signifying software RAID, '
                        'has been detected. If software raid is in '
                        'use, this should not necessarilly need to '
                        'be set or used if software raid is being '
                        'managed by Ironic, unless the operator knows'
                        'better due to site configuration. '
                        'Unfortunately, we cannot guess a '
                        'root deivce hint when Ironic managing a '
                        'software raid device. If this is in error '
                        'please set an explicit root device hint using '
                        '$ openstack baremetal node set --property '
                        'root_device=/dev/<DEVICE>',
                        {'md': disk['name']})
            return

    if strategy == 'smallest':
        # NOTE(TheJulia): This is redundant, Ironic does this by default,
        # and maintains a list of invalid devices which would show up in a
        # the introspetion data which cannot be used. Such as flash cards.
        disks.sort(key=lambda d: d['size'])
        root_device = disks[0]
    elif strategy == 'largest':
        disks.sort(key=lambda d: d['size'], reverse=True)
        root_device = disks[0]
    else:
        disk_names = [x.strip() for x in strategy.split(',')]
        disks = {d['name']: d for d in disks}
        for candidate in disk_names:
            try:
                root_device = disks['/dev/%s' % candidate]
            except KeyError:
                continue
            else:
                break
        else:
            raise exceptions.RootDeviceDetectionError(
                'Cannot find a disk with any of names %(strategy)s '
                'for node %(node)s' %
                {'strategy': strategy, 'node': node.uuid})

    hint = None
    for hint_name in ('wwn_with_extension', 'wwn', 'serial'):
        if root_device.get(hint_name):
            hint = {hint_name: root_device[hint_name]}
            break

    if hint is None:
        # I don't think it might actually happen, but just in case
        raise exceptions.RootDeviceDetectionError(
            'Neither WWN nor serial number are known for device %(dev)s '
            'on node %(node)s; root device hints cannot be used' %
            {'dev': root_device['name'], 'node': node.uuid})

    # During the introspection process we got local_gb assigned according
    # to the default strategy. Now we need to update it.
    new_size = root_device['size'] / units.Gi
    # This -1 is what we always do to account for partitioning
    new_size -= 1

    # NOTE(TheJulia): local_gb is only used for partition images,
    # and is ignored with Whole Disk Images. With movement to Whole
    # Disk images, this is tech debt and should be removed at some point.
    baremetal_client.node.update(
        node.uuid,
        [{'op': 'add', 'path': '/properties/root_device', 'value': hint},
         {'op': 'add', 'path': '/properties/local_gb', 'value': new_size}])

    LOG.info('Updated root device for node %(node)s, new device '
             'is %(dev)s, new local_gb is %(local_gb)d',
             {'node': node.uuid, 'dev': root_device, 'local_gb': new_size})


def create_raid_configuration(clients, node_uuids, configuration,
                              verbosity=0):
    """Create RAID configuration on nodes.

    :param clients: application client object.
    :type clients: Object

    :param node_uuids: List of instance UUID(s).
    :type node_uuids: List

    :param configuration: RAID configuration object.
    :type configuration: Object

    :param verbosity: Verbosity level
    :type verbosity: Integer
    """

    with utils.TempDirs() as tmp:
        utils.run_ansible_playbook(
            playbook='cli-baremetal-raid.yaml',
            inventory='localhost,',
            workdir=tmp,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=verbosity,
            extra_vars={
                'node_uuids': node_uuids,
                'raid_configuration': configuration
            }
        )

    print('Successfully configured RAID for nodes: {}'.format(node_uuids))


def _existing_ips(existing_nodes):
    result = set()
    for node in existing_nodes:
        try:
            handler = node_utils.find_driver_handler(node['driver'])
        except tc_exceptions.InvalidNode:
            LOG.warning('No known handler for driver %(driver)s of '
                        'node %(node)s, ignoring it',
                        {'driver': node['driver'], 'node': node['uuid']})
            continue

        address_field = handler.convert_key('pm_addr')
        if address_field is None:
            LOG.info('No address field for driver %(driver)s of '
                     'node %(node)s, ignoring it',
                     {'driver': node['driver'], 'node': node['uuid']})
            continue

        address = node['driver_info'].get(address_field)
        if address is None:
            LOG.warning('No address for node %(node)s, ignoring it',
                        {'node': node['uuid']})
            continue

        try:
            ip = socket.gethostbyname(address)
        except socket.gaierror as exc:
            LOG.warning('Cannot resolve %(field)s "%(value)s" '
                        'for node %(node)s: %(error)s',
                        {'field': address_field, 'value': address,
                         'node': node['uuid'], 'error': exc})
            continue

        port_field = handler.convert_key('pm_port')
        port = node['driver_info'].get(port_field, handler.default_port)
        if port is not None:
            port = int(port)

        LOG.debug('Detected existing BMC at %s with port %s', ip, port)
        result.add((ip, port))

    return result


def _ip_address_list(ip_addresses):
    if isinstance(ip_addresses, str):
        return [str(ip) for ip in
                netaddr.IPNetwork(ip_addresses).iter_hosts()]
    return ip_addresses


def _get_candidate_nodes(ip_addresses, ports,
                         credentials, existing_nodes):
    existing = _existing_ips(existing_nodes)
    try:
        ip_addresses = _ip_address_list(ip_addresses)
    except netaddr.AddrFormatError as exc:
        LOG.error("Cannot parse network address: %s", exc)
        raise

    result = []
    # NOTE(dtantsur): we iterate over IP addresses last to avoid
    # spamming the same BMC with too many requests in a row.
    for username, password in credentials:
        for port in ports:
            port = int(port)
            for ip in ip_addresses:
                if (ip, port) in existing or (ip, None) in existing:
                    LOG.info('Skipping existing node %s:%s', ip, port)
                    continue

                result.append({'ip': ip, 'username': username,
                               'password': password, 'port': port})

    return result


def _probe_node(ip, port, username, password,
                attempts=2, ipmi_driver='ipmi'):
    # TODO(dtantsur): redfish support
    LOG.debug('Probing for IPMI BMC: %s@%s:%s',
              username, ip, port)

    with tempfile.NamedTemporaryFile(mode='wt') as fp:
        fp.write(password or '\0')
        fp.flush()

        try:
            # TODO(dtantsur): try also IPMI v1.5
            processutils.execute('ipmitool', '-I', 'lanplus',
                                 '-H', ip, '-L', 'ADMINISTRATOR',
                                 '-p', str(port), '-U', username,
                                 '-f', fp.name, 'power', 'status',
                                 attempts=attempts)
        except processutils.ProcessExecutionError as exc:
            LOG.debug('Probing %(ip)s failed: %(exc)s',
                      {'ip': ip, 'exc': exc})
            return None

    LOG.info('Found a BMC on %(ip)s with user %(user)s',
             {'ip': ip, 'user': username})
    return {
        'pm_type': ipmi_driver,
        'pm_addr': ip,
        'pm_user': username,
        'pm_password': password,
        'pm_port': port,
    }


def discover_and_enroll(clients, ip_addresses, credentials, kernel_name,
                        ramdisk_name, instance_boot_option,
                        existing_nodes=None, ports=None):
    """Discover nodes and enroll baremetal nodes.

    :param clients: application client object.
    :type clients: Object

    :param ip_addresses: List of IP addresses.
    :type ip_addresses: List || String

    :param credentials: Credential information object
    :type credentials: Tuple

    :param kernel_name: Kernel to use
    :type kernel_name: String

    :param ramdisk_name: RAMDISK to use
    :type ramdisk_name: String

    :param instance_boot_option: Boot options to use
    :type instance_boot_option: String

    :param existing_nodes: List of nodes already discovered. If this is
                           undefined this object will be set to an empty
                           array.
    :type existing_nodes: List

    :param ports: List of ports, if no ports are provided the list of ports
                  will be limted to [623].
    :type ports: List

    :returns: List
    """

    if not ports:
        ports = [623]

    if not existing_nodes:
        existing_nodes = list()

    candidate_nodes = _get_candidate_nodes(
        ip_addresses,
        ports,
        credentials,
        existing_nodes
    )
    probed_nodes = list()
    for node in candidate_nodes:
        probed_nodes.append(_probe_node(**node))
        print('Successfully probed node IP {}'.format(node['ip']))

    return register_or_update(
        clients=clients,
        nodes_json=probed_nodes,
        instance_boot_option=instance_boot_option,
        kernel_name=kernel_name,
        ramdisk_name=ramdisk_name
    )


def apply_bios_configuration(node_uuids, configuration, verbosity=0):
    """Apply BIOS settings on nodes.

    :param node_uuids: List of instance UUID(s).
    :type node_uuids: List

    :param configuration: BIOS configuration object.
    :type configuration: Object

    :param verbosity: Verbosity level
    :type verbosity: Integer
    """

    print('Applying BIOS settings for given nodes, this may take time')

    with utils.TempDirs() as tmp:
        utils.run_ansible_playbook(
            playbook='cli-baremetal-bios.yaml',
            inventory='localhost,',
            workdir=tmp,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=verbosity,
            extra_vars={
                'node_uuids': node_uuids,
                'bios_configuration': configuration
            }
        )

    print('Successfully applied the BIOS for nodes: {}'.format(node_uuids))


def apply_bios_configuration_on_manageable_nodes(clients, configuration,
                                                 verbosity=0):
    """Apply BIOS settings on manageable nodes.

    :param clients: application client object.
    :type clients: Object

    :param configuration: BIOS configuration object.
    :type configuration: Object

    :param verbosity: Verbosity level
    :type verbosity: Integer
    """

    apply_bios_configuration(
        node_uuids=[
            i.uuid for i in clients.baremetal.node.list()
            if i.provision_state == "manageable" and not i.maintenance
        ],
        configuration=configuration,
        verbosity=verbosity
    )


def reset_bios_configuration(node_uuids, verbosity=0):
    """Reset BIOS settings on nodes.

    :param node_uuids: List of instance UUID(s).
    :type node_uuids: List

    :param verbosity: Verbosity level
    :type verbosity: Integer
    """

    with utils.TempDirs() as tmp:
        utils.run_ansible_playbook(
            playbook='cli-baremetal-bios-reset.yaml',
            inventory='localhost,',
            workdir=tmp,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=verbosity,
            extra_vars={
                'node_uuids': node_uuids
            }
        )

    print('Successfully reset the BIOS for nodes: {}'.format(node_uuids))


def reset_bios_configuration_on_manageable_nodes(clients, verbosity=0):
    """Reset BIOS settings on manageable nodes.

    :param clients: application client object.
    :type clients: Object

    :param verbosity: Verbosity level
    :type verbosity: Integer
    """

    reset_bios_configuration(
        node_uuids=[
            i.uuid for i in clients.baremetal.node.list()
            if i.provision_state == "manageable" and not i.maintenance
        ],
        verbosity=verbosity
    )
