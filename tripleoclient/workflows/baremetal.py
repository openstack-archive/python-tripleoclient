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

from __future__ import print_function

import six

from tripleo_common.actions import baremetal

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils


def validate_nodes(clients, nodes_json):
    """Validate nodes.

    :param clients: Application client object.
    :type clients: Object

    :param nodes_json:
    :type nodes_json: Object

    :returns: Boolean
    """

    context = clients.tripleoclient.create_mistral_context()
    nodes = baremetal.ValidateNodes(nodes_json=nodes_json)
    validated_nodes = nodes.run(context=context)
    if not validated_nodes:
        return True
    else:
        raise exceptions.RegisterOrUpdateError(validated_nodes)


def register_or_update(clients, nodes_json, kernel_name=None,
                       ramdisk_name=None, instance_boot_option=None):
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

    :returns: List
    """

    context = clients.tripleoclient.create_mistral_context()
    nodes = baremetal.RegisterOrUpdateNodes(
        nodes_json=nodes_json,
        ramdisk_name=ramdisk_name,
        kernel_name=kernel_name,
        instance_boot_option=instance_boot_option
    )

    registered_nodes = nodes.run(context=context)
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


def _format_errors(payload):
    errors = []
    messages = payload.get('message', [])
    for msg in messages:
        # Adapt for different formats
        if isinstance(msg, six.string_types):
            text = msg
        else:
            text = msg.get('result') or msg.get('message', '')
        try:
            # With multiple workflows, the error message can become
            # quite large and unreadable as it gets passed from task to
            # task. This attempts to keep only the last, and hopefully
            # useful part.
            errors.append(text.rstrip('\n').split('\n')[-1])
        except Exception:
            errors.append(text)
    return '\n'.join(errors)


def provide(verbosity, node_uuids):
    """Provide Baremetal Nodes

    :param verbosity: Verbosity level
    :type verbosity: Integer

    :param node_uuids: List of instance UUID(s).
    :type node_uuids: List
    """

    with utils.TempDirs() as tmp:
        utils.run_ansible_playbook(
            playbook='cli-overcloud-node-provide.yaml',
            inventory='localhost,',
            workdir=tmp,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=verbosity,
            extra_vars={
                'node_uuids': node_uuids
            }
        )

    print('Successfully provided nodes: {}'.format(node_uuids))


def provide_manageable_nodes(clients, verbosity=0):
    """Provide all manageable Nodes

    :param clients: Application client object.
    :type clients: Object

    :param verbosity: Verbosity level
    :type verbosity: Integer
    """

    provide(
        verbosity=verbosity,
        node_uuids=[
            i.uuid for i in clients.baremetal.node.list()
            if i.provision_state == "manageable" and not i.maintenance
        ]
    )


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


def configure(clients, node_uuids, kernel_name='bm-deploy-kernel',
              ramdisk_name='bm-deploy-ramdisk', instance_boot_option=None,
              root_device=None, root_device_minimum_size=4,
              overwrite_root_device_hints=False):
    """Configure Node boot options.

    :param node_uuids: List of instance UUID(s).
    :type node_uuids: List

    :param kernel_name: Kernel to use
    :type kernel_name: String

    :param ramdisk_name: RAMDISK to use
    :type ramdisk_name: String

    :param instance_boot_option: Boot options to use
    :type instance_boot_option: String

    :param root_device: Path (name) of the root device.
    :type root_device: String

    :param root_device_minimum_size: Size of the given root device.
    :type root_device_minimum_size: Integer

    :param overwrite_root_device_hints: Whether to overwrite existing root
                                        device hints when `root_device` is
                                        used.
    :type overwrite_root_device_hints: Boolean
    """

    context = clients.tripleoclient.create_mistral_context()
    for node_uuid in node_uuids:
        boot_action = baremetal.ConfigureBootAction(
            node_uuid=node_uuid,
            kernel_name=kernel_name,
            ramdisk_name=ramdisk_name,
            instance_boot_option=instance_boot_option
        ).run(context=context)
        if boot_action:
            raise RuntimeError(boot_action)
        root_device_action = baremetal.ConfigureRootDeviceAction(
            node_uuid=node_uuid,
            root_device=root_device,
            minimum_size=root_device_minimum_size,
            overwrite=overwrite_root_device_hints
        )
        root_device_action.run(context=context)
    else:
        print('Successfully configured the nodes.')


def configure_manageable_nodes(clients, kernel_name='bm-deploy-kernel',
                               ramdisk_name='bm-deploy-ramdisk',
                               instance_boot_option=None,
                               root_device=None, root_device_minimum_size=4,
                               overwrite_root_device_hints=False):
    """Configure all manageable Nodes.

    kernel_name=parsed_args.deploy_kernel,
    ramdisk_name=parsed_args.deploy_ramdisk,
    instance_boot_option=parsed_args.instance_boot_option,
    root_device=parsed_args.root_device,
    root_device_minimum_size=parsed_args.root_device_minimum_size,
    overwrite_root_device_hints=(parsed_args.overwrite_root_device_hints)

    :param kernel_name: Kernel to use
    :type kernel_name: String

    :param ramdisk_name: RAMDISK to use
    :type ramdisk_name: String

    :param instance_boot_option: Boot options to use
    :type instance_boot_option: String

    :param root_device: Path (name) of the root device.
    :type root_device: String

    :param root_device_minimum_size: Size of the given root device.
    :type root_device_minimum_size: Integer

    :param overwrite_root_device_hints: Whether to overwrite existing root
                                        device hints when `root_device` is
                                        used.
    :type overwrite_root_device_hints: Boolean
    """

    configure(
        clients=clients,
        node_uuids=[
            i.uuid for i in clients.baremetal.node.list()
            if i.provision_state == "manageable" and not i.maintenance
        ],
        kernel_name=kernel_name,
        ramdisk_name=ramdisk_name,
        instance_boot_option=instance_boot_option,
        root_device=root_device,
        root_device_minimum_size=root_device_minimum_size,
        overwrite_root_device_hints=overwrite_root_device_hints
    )


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

    context = clients.tripleoclient.create_mistral_context()

    get_candiate_nodes = baremetal.GetCandidateNodes(
        ip_addresses,
        ports,
        credentials,
        existing_nodes
    )
    probed_nodes = list()
    for node in get_candiate_nodes.run(context=context):
        probed_nodes.append(
            baremetal.ProbeNode(**node).run(context=context)
        )
        print('Successfully probed node IP {}'.format(node['ip']))

    return register_or_update(
        clients=clients,
        nodes_json=probed_nodes,
        instance_boot_option=instance_boot_option,
        kernel_name=kernel_name,
        ramdisk_name=ramdisk_name
    )


def clean_nodes(node_uuids, verbosity=0):
    """Clean Baremetal Nodes

    :param node_uuids: List of instance UUID(s).
    :type node_uuids: List

    :param verbosity: Verbosity level
    :type verbosity: Integer
    """

    with utils.TempDirs() as tmp:
        utils.run_ansible_playbook(
            playbook='cli-baremetal-clean.yaml',
            inventory='localhost,',
            workdir=tmp,
            playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
            verbosity=verbosity,
            extra_vars={
                'node_uuids': node_uuids
            }
        )

    print('Successfully cleaned nodes: {}'.format(node_uuids))


def clean_manageable_nodes(clients, verbosity=0):
    """Clean all manageable Nodes

    :param clients: application client object.
    :type clients: Object

    :param verbosity: Verbosity level
    :type verbosity: Integer
    """

    clean_nodes(
        node_uuids=[
            i.uuid for i in clients.baremetal.node.list()
            if i.provision_state == "manageable" and not i.maintenance
        ],
        verbosity=verbosity
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
