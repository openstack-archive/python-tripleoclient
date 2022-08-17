#   Copyright 2021 Red Hat, Inc.
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
import re
import uuid
import yaml

from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from osc_lib import utils

from tripleo_common.utils import passwords

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils


def arg_parse_common(parser):
    """Multiple classes below need these arguments added
    """
    parser.add_argument('--cephadm-ssh-user', dest='cephadm_ssh_user',
                        help=_("Name of the SSH user used by cephadm. "
                               "Warning: if this option is used, it "
                               "must be used consistently for every "
                               "'openstack overcloud ceph' call. "
                               "Defaults to 'ceph-admin'. "
                               "(default=Env: CEPHADM_SSH_USER)"),
                        default=utils.env("CEPHADM_SSH_USER",
                                          default="ceph-admin"))

    parser.add_argument('--stack', dest='stack',
                        help=_('Name or ID of heat stack '
                               '(default=Env: OVERCLOUD_STACK_NAME)'),
                        default=utils.env('OVERCLOUD_STACK_NAME',
                                          default='overcloud'))
    parser.add_argument(
        '--working-dir', action='store',
        help=_('The working directory for the deployment where all '
               'input, output, and generated files will be stored.\n'
               'Defaults to "$HOME/overcloud-deploy/<stack>"'))

    return parser


def ceph_hosts_in_inventory(ceph_hosts, ceph_spec, inventory):
    """Raise command error if any ceph_hosts are not in the inventory
    """
    all_host_objs = oooutils.parse_ansible_inventory(inventory, 'all')
    all_hosts = list(map(lambda x: str(x), all_host_objs))
    for ceph_host in ceph_hosts['_admin'] + ceph_hosts['non_admin']:
        if ceph_host not in all_hosts:
            raise oscexc.CommandError(
                "Ceph host '%s' from Ceph spec '%s' was "
                "not found in Ansible inventory '%s' so "
                "unable to modify that host via Ansible."
                % (ceph_host, ceph_spec, inventory))


class OvercloudCephDeploy(command.Command):

    log = logging.getLogger(__name__ + ".OvercloudCephDeploy")
    auth_required = False

    def get_parser(self, prog_name):
        parser = super(OvercloudCephDeploy, self).get_parser(prog_name)

        parser.add_argument('baremetal_env', nargs='?',
                            metavar='<deployed_baremetal.yaml>',
                            help=_('Path to the environment file '
                                   'output from "openstack '
                                   'overcloud node provision". '
                                   'This argument may be excluded '
                                   'only if --ceph-spec is used.'))
        parser.add_argument('-o', '--output', required=True,
                            metavar='<deployed_ceph.yaml>',
                            help=_('The path to the output environment '
                                   'file describing the Ceph deployment '
                                   ' to pass to the overcloud deployment.'))
        parser.add_argument('-y', '--yes', default=False, action='store_true',
                            help=_('Skip yes/no prompt before overwriting an '
                                   'existing <deployed_ceph.yaml> output file '
                                   '(assume yes).'))
        parser.add_argument('--skip-user-create', default=False,
                            action='store_true',
                            help=_("Do not create the cephadm SSH user. "
                                   "This user is necessary to deploy but "
                                   "may be created in a separate step via "
                                   "'openstack overcloud ceph user enable'."))
        parser.add_argument('--skip-hosts-config', default=False,
                            action='store_true',
                            help=_("Do not update /etc/hosts on deployed "
                                   "servers. By default this is configured "
                                   "so overcloud nodes can reach each other "
                                   "and the undercloud by name."))
        parser.add_argument('--skip-container-registry-config', default=False,
                            action='store_true',
                            help=_("Do not update "
                                   "/etc/containers/registries.conf on "
                                   "deployed servers. By default this is "
                                   "configured so overcloud nodes can pull "
                                   "containers from the undercloud registry."))
        parser = arg_parse_common(parser)
        parser.add_argument('--roles-data',
                            help=_(
                                "Path to an alternative roles_data.yaml. "
                                "Used to decide which node gets which "
                                "Ceph mon, mgr, or osd service "
                                "based on the node's role in "
                                "<deployed_baremetal.yaml>."),
                            default=os.path.join(
                                constants.TRIPLEO_HEAT_TEMPLATES,
                                constants.OVERCLOUD_ROLES_FILE))
        parser.add_argument('--network-data',
                            help=_(
                                "Path to an alternative network_data.yaml. "
                                "Used to define Ceph public_network and "
                                "cluster_network. This file is searched "
                                "for networks with name_lower values of "
                                "storage and storage_mgmt. If none found, "
                                "then search repeats but with "
                                "service_net_map_replace in place of "
                                "name_lower. Use --public-network-name or "
                                "--cluster-network-name options to override "
                                "name of the searched for network from "
                                "storage or storage_mgmt to a customized "
                                "name. If network_data has no storage "
                                "networks, both default to ctlplane. "
                                "If found network has >1 subnet, they are "
                                "all combined (for routed traffic). "
                                "If a network has ipv6 true, then "
                                "the ipv6_subnet is retrieved instead "
                                "of the ip_subnet, and the Ceph global "
                                "ms_bind_ipv4 is set false and the "
                                "ms_bind_ipv6 is set true. Use --config "
                                "to override these defaults if desired."),
                            default=os.path.join(
                                constants.TRIPLEO_HEAT_TEMPLATES,
                                constants.OVERCLOUD_NETWORKS_FILE))
        parser.add_argument('--public-network-name',
                            help=_(
                                "Name of the network defined in "
                                "network_data.yaml which should be "
                                "used for the Ceph public_network. "
                                "Defaults to 'storage'."),
                            default='storage')
        parser.add_argument('--cluster-network-name',
                            help=_(
                                "Name of the network defined in "
                                "network_data.yaml which should be "
                                "used for the Ceph cluster_network. "
                                "Defaults to 'storage_mgmt'."),
                            default='storage_mgmt')
        parser.add_argument('--cluster',
                            help=_(
                                "Name of the Ceph cluster. "
                                "If set to 'foo', then the files "
                                "/etc/ceph/<FSID>/foo.conf and "
                                "/etc/ceph/<FSID>/foo.client.admin.keyring "
                                "will be created. Otherwise these "
                                "files will use the name 'ceph'. "
                                "Changing this means changing command line "
                                "calls too, e.g. 'ceph health' will become "
                                "'ceph --cluster foo health' unless export "
                                "CEPH_ARGS='--cluster foo' is used."),
                            default='ceph')
        parser.add_argument('--mon-ip',
                            help=_(
                                "IP address of the first Ceph monitor. "
                                "If not set, an IP from the Ceph "
                                "public_network of a server with the "
                                "mon label from the Ceph spec is used. "
                                "IP must already be active on server."),
                            default='')
        parser.add_argument('--config',
                            help=_(
                                "Path to an existing ceph.conf with settings "
                                "to be assimilated by the new cluster via "
                                "'cephadm bootstrap --config' ")),
        parser.add_argument('--cephadm-extra-args',
                            help=_(
                                "String of extra parameters to pass cephadm. "
                                "E.g. if --cephadm-extra-args '--log-to-file "
                                " --skip-prepare-host', then cephadm boostrap "
                                "will use those options. Warning: requires "
                                "--force as not all possible options ensure a "
                                "functional deployment.")),
        parser.add_argument('--force', default=False,
                            action='store_true',
                            help=_("Run command regardless of consequences."))
        parser.add_argument('--ansible-extra-vars',
                            help=_(
                                "Path to an existing Ansible vars file which "
                                "can override any variable in "
                                "tripleo-ansible. If "
                                "'--ansible-extra-vars vars.yaml' is passed, "
                                "then 'ansible-playbook -e @vars.yaml ...' is "
                                "used to call tripleo-ansible Ceph roles. "
                                "Warning: requires --force as not all "
                                "options ensure a functional deployment."))
        parser.add_argument('--ceph-client-username',
                            help=_(
                                "Name of the cephx user. E.g. if "
                                "'openstack' is used, then "
                                "'ceph auth get client.openstack' will "
                                "return a working user with key and "
                                "capabilities on the deployed Ceph cluster. "
                                "Ignored unless tripleo_cephadm_pools is set "
                                "via --ansible-extra-vars. "
                                "If this parameter is not set and "
                                "tripleo_cephadm_keys is set via "
                                "--ansible-extra-vars, then "
                                "'openstack' will be used. "
                                "Used to set CephClientUserName in --output."),
                            default='openstack'),
        parser.add_argument('--ceph-client-key',
                            help=_(
                                "Value of the cephx key. E.g. "
                                "'AQC+vYNXgDAgAhAAc8UoYt+OTz5uhV7ItLdwUw=='. "
                                "Ignored unless tripleo_cephadm_pools is set "
                                "via --ansible-extra-vars. "
                                "If this parameter is not set and "
                                "tripleo_cephadm_keys is set via "
                                "--ansible-extra-vars, then a random "
                                "key will be generated. "
                                "Used to set CephClientKey in --output."),
                            default='')
        parser.add_argument('--skip-cephx-keys', default=False,
                            action='store_true',
                            help=_("Do not create cephx keys even if "
                                   "tripleo_cephadm_pools is set via "
                                   "--ansible-extra-vars. If this option "
                                   "is used, then even the defaults of "
                                   "--ceph-client-key and "
                                   "--ceph-client-username are ignored, "
                                   "but the pools defined via "
                                   "--ansible-extra-vars "
                                   "are still created."))
        parser.add_argument('--ceph-vip',
                            help=_(
                                "Path to an existing Ceph services/network "
                                "mapping file."),
                            default=None),
        parser.add_argument('--daemons',
                            help=_(
                                "Path to an existing Ceph daemon options "
                                "definition."),
                            default=None),
        parser.add_argument('--single-host-defaults', default=False,
                            action='store_true',
                            help=_("Adjust configuration defaults to suit "
                                   "a single-host Ceph cluster."))
        spec_group = parser.add_mutually_exclusive_group()
        spec_group.add_argument('--ceph-spec',
                                help=_(
                                    "Path to an existing Ceph spec file. If "
                                    "not provided a spec will be generated "
                                    "automatically based on --roles-data and "
                                    "<deployed_baremetal.yaml>. The "
                                    "<deployed_baremetal.yaml> parameter is "
                                    "optional only if --ceph-spec is used."),
                                default=None)
        spec_group.add_argument('--osd-spec',
                                help=_(
                                    "Path to an existing OSD spec file. "
                                    "Mutually exclusive with --ceph-spec. "
                                    "If the Ceph spec file is generated "
                                    "automatically, then the OSD spec "
                                    "in the Ceph spec file defaults to "
                                    "{data_devices: {all: true}} "
                                    "for all service_type osd. "
                                    "Use --osd-spec to override the "
                                    "data_devices value inside the "
                                    "Ceph spec file."),
                                default=None)
        parser.add_argument('--crush-hierarchy',
                            help=_(
                                "Path to an existing crush hierarchy spec "
                                "file. "),
                            default=None)
        parser.add_argument('--standalone', default=False,
                            action='store_true',
                            help=_("Use single host Ansible inventory. "
                                   "Used only for development or testing "
                                   "environments."))
        parser.add_argument('--container-image-prepare',
                            help=_(
                                "Path to an alternative "
                                "container_image_prepare_defaults.yaml. "
                                "Used to control which Ceph container is "
                                "pulled by cephadm via the ceph_namespace, "
                                "ceph_image, and ceph_tag variables in "
                                "addition to registry authentication via "
                                "ContainerImageRegistryCredentials."
                            ),
                            default=None)
        parser.add_argument('--cephadm-default-container', default=False,
                            action='store_true',
                            help=_("Use the default continer defined in "
                                   "cephadm instead of "
                                   "container_image_prepare_defaults.yaml. "
                                   "If this is used, 'cephadm bootstrap' is "
                                   "not passed the --image parameter."))
        container_group = parser.add_argument_group("container-image-prepare "
                                                    "overrides",
                                                    "The following options "
                                                    "may be used to override "
                                                    "individual values "
                                                    "set via "
                                                    "--container-image-prepare"
                                                    ". If the example "
                                                    "variables below were "
                                                    "set the image would be "
                                                    "concatenated into "
                                                    "quay.io/ceph/ceph:latest "
                                                    "and a custom registry "
                                                    "login would be used."
                                                    )
        container_group.add_argument('--container-namespace',
                                     required=False,
                                     help='e.g. quay.io/ceph')
        container_group.add_argument('--container-image',
                                     required=False,
                                     help='e.g. ceph')
        container_group.add_argument('--container-tag',
                                     required=False,
                                     help='e.g. latest')
        container_group.add_argument('--registry-url',
                                     required=False,
                                     help='')
        container_group.add_argument('--registry-username',
                                     required=False,
                                     help='')
        container_group.add_argument('--registry-password',
                                     required=False,
                                     help='')

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        output_path = os.path.abspath(parsed_args.output)
        overwrite = parsed_args.yes
        ceph_ingress = True
        if (os.path.exists(output_path) and not overwrite
                and not oooutils.prompt_user_for_confirmation(
                    'Overwrite existing file %s [y/N]?' % parsed_args.output,
                    self.log)):
            raise oscexc.CommandError("Will not overwrite existing file:"
                                      " %s. See the --yes parameter to "
                                      "override this behavior. " %
                                      parsed_args.output)
        else:
            overwrite = True

        if not parsed_args.working_dir:
            working_dir = oooutils.get_default_working_dir(
                parsed_args.stack)
        else:
            working_dir = os.path.abspath(parsed_args.working_dir)
        oooutils.makedirs(working_dir)

        if parsed_args.standalone:
            inventory = oooutils.standalone_ceph_inventory(working_dir)
            ceph_ingress = False
        else:
            inventory = os.path.join(working_dir,
                                     constants.TRIPLEO_STATIC_INVENTORY)
        if not os.path.exists(inventory):
            raise oscexc.CommandError(
                "Inventory file not found in working directory: "
                "%s. It should have been created by "
                "'openstack overcloud node provision'."
                % inventory)

        # mandatory extra_vars are now set, add others conditionally
        extra_vars = {
            "deployed_ceph_tht_path": output_path,
            "working_dir": working_dir,
            "stack_name": parsed_args.stack,
            "tripleo_cephadm_standalone": parsed_args.standalone,
            "tripleo_cephadm_ingress": ceph_ingress,
            "tripleo_ceph_client_vars": os.path.join(working_dir,
                                                     'ceph_client.yml')
        }
        extra_vars_file = None
        # optional paths to pass to playbook
        if parsed_args.ceph_spec is None and \
           parsed_args.baremetal_env is None:
            raise oscexc.CommandError(
                "Either <deployed_baremetal.yaml> "
                "or --ceph-spec must be used.")

        if parsed_args.baremetal_env:
            baremetal_env_path = os.path.abspath(parsed_args.baremetal_env)
            if not os.path.exists(baremetal_env_path):
                raise oscexc.CommandError(
                    "Baremetal environment file does not exist:"
                    " %s" % parsed_args.baremetal_env)
            else:
                extra_vars['baremetal_deployed_path'] = \
                    os.path.abspath(parsed_args.baremetal_env)

        if parsed_args.roles_data:
            if not os.path.exists(parsed_args.roles_data):
                raise oscexc.CommandError(
                    "Roles Data file not found --roles-data %s."
                    % os.path.abspath(parsed_args.roles_data))
            else:
                extra_vars['tripleo_roles_path'] = \
                    os.path.abspath(parsed_args.roles_data)

        if parsed_args.config:
            if not os.path.exists(parsed_args.config):
                raise oscexc.CommandError(
                    "Config file not found --config %s."
                    % os.path.abspath(parsed_args.config))
            else:
                extra_vars['tripleo_cephadm_bootstrap_conf'] = \
                    os.path.abspath(parsed_args.config)

        if parsed_args.network_data:
            if not os.path.exists(parsed_args.network_data):
                raise oscexc.CommandError(
                    "Network Data file not found --network-data %s."
                    % os.path.abspath(parsed_args.network_data))

        ceph_networks_map = \
            oooutils.get_ceph_networks(parsed_args.network_data,
                                       parsed_args.public_network_name,
                                       parsed_args.cluster_network_name)
        extra_vars = {**extra_vars, **ceph_networks_map}

        if parsed_args.cluster:
            extra_vars['tripleo_cephadm_cluster'] = \
                parsed_args.cluster

        if parsed_args.mon_ip:
            if not oooutils.is_valid_ip(parsed_args.mon_ip):
                raise oscexc.CommandError(
                    "Invalid IP address '%s' passed to --mon-ip."
                    % parsed_args.mon_ip)
            else:
                extra_vars['tripleo_cephadm_first_mon_ip'] = \
                    parsed_args.mon_ip

        if parsed_args.ceph_spec:
            if not os.path.exists(parsed_args.ceph_spec):
                raise oscexc.CommandError(
                    "Ceph Spec file not found --ceph-spec %s."
                    % os.path.abspath(parsed_args.ceph_spec))
            else:
                extra_vars['dynamic_ceph_spec'] = False
                extra_vars['ceph_spec_path'] = \
                    os.path.abspath(parsed_args.ceph_spec)

        if parsed_args.osd_spec:
            if not os.path.exists(parsed_args.osd_spec):
                raise oscexc.CommandError(
                    "OSD Spec file not found --osd-spec %s."
                    % os.path.abspath(parsed_args.osd_spec))
            else:
                extra_vars['osd_spec_path'] = \
                    os.path.abspath(parsed_args.osd_spec)

        if parsed_args.crush_hierarchy:
            if not os.path.exists(parsed_args.crush_hierarchy):
                raise oscexc.CommandError(
                    "Crush Hierarchy Spec file not found --crush-hierarchy %s."
                    % os.path.abspath(parsed_args.crush_hierarchy))
            else:
                extra_vars['crush_hierarchy_path'] = \
                    os.path.abspath(parsed_args.crush_hierarchy)
        if parsed_args.ceph_vip:
            if not os.path.exists(parsed_args.ceph_vip):
                raise oscexc.CommandError(
                    "ceph vip mapping file not found --ceph-vip %s."
                    % os.path.abspath(parsed_args.ceph_vip))
            else:
                extra_vars['tripleo_cephadm_ha_services_path'] = \
                    os.path.abspath(parsed_args.ceph_vip)
        if parsed_args.cephadm_extra_args and not parsed_args.force:
            raise oscexc.CommandError(
                "--cephadm-extra-args requires --force.")
        if parsed_args.cephadm_extra_args and parsed_args.force:
            extra_vars['tripleo_cephadm_extra_args'] = \
                parsed_args.cephadm_extra_args

        if parsed_args.ansible_extra_vars and not parsed_args.force:
            raise oscexc.CommandError(
                "--ansible-extra-vars requires --force.")
        if parsed_args.ansible_extra_vars and parsed_args.force:
            if not os.path.exists(parsed_args.ansible_extra_vars):
                raise oscexc.CommandError(
                    "Ansible vars file not found --ansible-extra-vars %s."
                    % os.path.abspath(parsed_args.ansible_extra_vars))
            else:
                # utils.run_ansible_playbook() assums extra_vars_file is a dict
                with open(os.path.abspath(parsed_args.ansible_extra_vars),
                          'r') as f:
                    extra_vars_file = yaml.safe_load(f)
                if (not parsed_args.skip_cephx_keys and
                    'tripleo_cephadm_pools' in extra_vars_file and # noqa
                    'tripleo_cephadm_keys' not in extra_vars_file): # noqa
                    # create tripleo_cephadm_keys and add it to extra_vars
                    self.log.debug("Generating tripleo_cephadm_keys")
                    if len(parsed_args.ceph_client_key) == 0:
                        parsed_args.ceph_client_key = \
                            passwords.create_cephx_key()
                    cephx = re.compile(r"^[a-zA-Z0-9+/]{38}==$")
                    if not cephx.match(parsed_args.ceph_client_key):
                        msg = ("'%s' is not a valid cephx key"
                               % str(parsed_args.ceph_client_key))
                        raise oscexc.CommandError(msg)
                    extra_vars['tripleo_cephadm_keys'] = \
                        oooutils.get_tripleo_cephadm_keys(
                            parsed_args.ceph_client_username,
                            parsed_args.ceph_client_key,
                            list(map(lambda x: x.get('name', ''),
                                     extra_vars_file['tripleo_cephadm_pools']))
                        )
                    # pass CLI args to THT via --output deployed_ceph.yaml
                    extra_vars['ceph_client_key'] = parsed_args.ceph_client_key
                    extra_vars['ceph_client_username'] =\
                        parsed_args.ceph_client_username
                else:
                    self.log.debug("Not generating tripleo_cephadm_keys. "
                                   "Either --skip-cephx-keys was used, "
                                   "or tripleo_cephadm_pools was not "
                                   "in %s, or tripleo_cephadm_keys was "
                                   "in %s." % (
                                       (parsed_args.ansible_extra_vars,)*2))

        if parsed_args.daemons:
            if not os.path.exists(parsed_args.daemons):
                raise oscexc.CommandError(
                    "ceph daemon options file not found --daemons %s."
                    % os.path.abspath(parsed_args.daemons))
            else:
                daemon_opt = oooutils.process_ceph_daemons(
                    os.path.abspath(parsed_args.daemons))
                # merge the processed extra_vars for daemons
                extra_vars = {**extra_vars, **daemon_opt}
        # optional container vars to pass to playbook
        keys = ['ceph_namespace', 'ceph_image', 'ceph_tag']
        push_sub_keys = ['ceph_namespace']
        key = 'ContainerImagePrepare'
        container_dict = \
            oooutils.parse_container_image_prepare(key, keys,
                                                   parsed_args.
                                                   container_image_prepare,
                                                   push_sub_keys)

        extra_vars['tripleo_cephadm_container_ns'] = \
            parsed_args.container_namespace or \
            container_dict['ceph_namespace']
        extra_vars['tripleo_cephadm_container_image'] = \
            parsed_args.container_image or \
            container_dict['ceph_image']
        extra_vars['tripleo_cephadm_container_tag'] = \
            parsed_args.container_tag or \
            container_dict['ceph_tag']

        # optional container registry vars to pass to playbook
        if 'tripleo_cephadm_container_ns' in extra_vars:
            keys = [extra_vars['tripleo_cephadm_container_ns']]
            key = 'ContainerImageRegistryCredentials'
            registry_dict = \
                oooutils.parse_container_image_prepare(key, keys,
                                                       parsed_args.
                                                       container_image_prepare)
            # It's valid for the registry_dict to be empty so
            # we cannot default to it with an 'or' like we can
            # for ceph_{namespace,image,tag} as above.
            if 'registry_url' in registry_dict:
                extra_vars['tripleo_cephadm_registry_url'] = \
                    registry_dict['registry_url']
            if 'registry_password' in registry_dict:
                extra_vars['tripleo_cephadm_registry_password'] = \
                    registry_dict['registry_password']
            if 'registry_username' in registry_dict:
                extra_vars['tripleo_cephadm_registry_username'] = \
                    registry_dict['registry_username']
            # Whether registry vars came out of --container-image-prepare
            # or not, we need either to set them (as above) or override
            # them if they were passed via the CLI (as follows)
            if parsed_args.registry_url:
                extra_vars['tripleo_cephadm_registry_url'] = \
                    parsed_args.registry_url
            if parsed_args.registry_password:
                extra_vars['tripleo_cephadm_registry_password'] = \
                    parsed_args.registry_password
            if parsed_args.registry_username:
                extra_vars['tripleo_cephadm_registry_username'] = \
                    parsed_args.registry_username

        if parsed_args.cephadm_ssh_user:
            extra_vars["tripleo_cephadm_ssh_user"] = \
                parsed_args.cephadm_ssh_user

        if parsed_args.single_host_defaults:
            extra_vars["tripleo_cephadm_single_host_defaults"] = True

        if parsed_args.cephadm_default_container:
            extra_vars["tripleo_cephadm_default_container"] = True

        skip_tags = []
        if parsed_args.skip_user_create:
            skip_tags.append('cephadm_ssh_user')

        if not parsed_args.skip_hosts_config:
            # call playbook to set /etc/hosts
            uc_host_list = [oooutils.get_undercloud_host_entry()]
            ctlplane_map = oooutils.get_ctlplane_attrs()
            short_name = oooutils.get_hostname(short=True)
            long_name = oooutils.get_hostname(short=False)
            dns_domain = long_name.replace(short_name+'.', '')
            hosts_extra_vars = dict(
                tripleo_hosts_entries_undercloud_hosts_entries=uc_host_list,
                tripleo_hosts_entries_overcloud_hosts_entries=[],
                tripleo_hosts_entries_vip_hosts_entries=[],
                tripleo_hosts_entries_extra_hosts_entries=[],
                tripleo_stack_name=parsed_args.stack,
                hostname_resolve_network=ctlplane_map['network']['name'],
                cloud_domain=dns_domain,
            )
            self.log.debug("Adding undercloud host entry "
                           "to overcloud /etc/hosts. (%s)"
                           % hosts_extra_vars)
            with oooutils.TempDirs() as tmp:
                oooutils.run_ansible_playbook(
                    playbook='cli-hosts-file-config.yaml',
                    inventory=inventory,
                    workdir=tmp,
                    playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                    verbosity=oooutils.playbook_verbosity(self=self),
                    reproduce_command=False,
                    extra_vars=hosts_extra_vars,
                    extra_vars_file=extra_vars_file,
                )
        else:
            self.log.debug("Not updating /etc/hosts because "
                           "--skip-hosts-config was used.")

        if not parsed_args.skip_container_registry_config and \
           container_dict.get('push_destination_boolean', False):
            # call playbook to set /etc/containers/registries.conf
            ns = container_dict.get('ceph_namespace', '').partition('/')[0]
            if ns:
                reg_extra_vars = dict(tripleo_podman_insecure_registries=[ns])
                self.log.debug("Adding %s as a container registry." % ns)
                with oooutils.TempDirs() as tmp:
                    oooutils.run_ansible_playbook(
                        playbook='cli-container-registry-config.yaml',
                        inventory=inventory,
                        workdir=tmp,
                        playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                        verbosity=oooutils.playbook_verbosity(self=self),
                        extra_vars=reg_extra_vars,
                        extra_vars_file=extra_vars_file,
                        reproduce_command=False,
                    )
            else:
                self.log.debug("Not updating container regsitry. "
                               "ceph_namespace is empty.")
        else:
            self.log.debug("Not updating container regsitry. "
                           "Either container_image_prepare_defaults.yaml "
                           "or file from --container-image-prepare "
                           "is not setting push_destination. Or "
                           "--skip-container-registry-config was used.")

        # call playbook to deploy ceph
        with oooutils.TempDirs() as tmp:
            oooutils.run_ansible_playbook(
                playbook='cli-deployed-ceph.yaml',
                inventory=inventory,
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=oooutils.playbook_verbosity(self=self),
                extra_vars=extra_vars,
                extra_vars_file=extra_vars_file,
                reproduce_command=False,
                skip_tags=','.join(skip_tags),
            )


class OvercloudCephUserDisable(command.Command):

    log = logging.getLogger(__name__ + ".OvercloudCephUserDisable")
    auth_required = False

    def get_parser(self, prog_name):
        parser = super(OvercloudCephUserDisable, self).get_parser(prog_name)
        parser.add_argument('ceph_spec',
                            metavar='<ceph_spec.yaml>',
                            help=_(
                                "Path to an existing Ceph spec file "
                                "which describes the Ceph cluster "
                                "where the cephadm SSH user will have "
                                "their public and private keys removed "
                                "and cephadm will be disabled. "
                                "Spec file is necessary to determine "
                                "which nodes to modify. "
                                "WARNING: Ceph cluster administration or "
                                "modification will no longer function."))
        parser.add_argument('-y', '--yes', default=False, action='store_true',
                            help=_('Skip yes/no prompt before disabling '
                                   'cephadm and its SSH user. '
                                   '(assume yes).'))
        parser = arg_parse_common(parser)
        required = parser.add_argument_group('required named arguments')
        required.add_argument('--fsid',
                              metavar='<FSID>', required=True,
                              help=_("The FSID of the Ceph cluster to be "
                                     "disabled. Required for disable option."))
        parser.add_argument('--standalone', default=False,
                            action='store_true',
                            help=_("Use single host Ansible inventory. "
                                   "Used only for development or testing "
                                   "environments."))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        ceph_spec = os.path.abspath(parsed_args.ceph_spec)

        if not os.path.exists(ceph_spec):
            raise oscexc.CommandError(
                "Ceph spec file does not exist:"
                " %s" % parsed_args.ceph_spec)

        overwrite = parsed_args.yes
        if (not overwrite
                and not oooutils.prompt_user_for_confirmation(
                    'Are you sure you want to disable Ceph '
                    'cluster management [y/N]?',
                    self.log)):
            raise oscexc.CommandError("Will not disable cephadm and delete "
                                      "the cephadm SSH user :"
                                      " %s. See the --yes parameter to "
                                      "override this behavior. " %
                                      parsed_args.cephadm_ssh_user)
        else:
            overwrite = True

        # use stack and working_dir to find inventory
        if not parsed_args.working_dir:
            working_dir = oooutils.get_default_working_dir(
                parsed_args.stack)
        else:
            working_dir = os.path.abspath(parsed_args.working_dir)
        oooutils.makedirs(working_dir)

        if parsed_args.standalone:
            inventory = oooutils.standalone_ceph_inventory(working_dir)
        else:
            inventory = os.path.join(working_dir,
                                     constants.TRIPLEO_STATIC_INVENTORY)
        if not os.path.exists(inventory):
            raise oscexc.CommandError(
                "Inventory file not found in working directory: "
                "%s. It should have been created by "
                "'openstack overcloud node provision'."
                % inventory)
        ceph_hosts = oooutils.get_host_groups_from_ceph_spec(ceph_spec)
        ceph_hosts_in_inventory(ceph_hosts, ceph_spec, inventory)

        if parsed_args.fsid:
            try:
                uuid.UUID(parsed_args.fsid)
            except ValueError:
                raise oscexc.CommandError(
                    "--fsid %s is not a valid UUID."
                    % parsed_args.fsid)

        if parsed_args.fsid:  # if no FSID, then no ceph cluster to disable
            # call the playbook to toggle cephadm w/ disable
            # if tripleo_cephadm_backend isn't set it defaults to ''
            extra_vars = {
                "tripleo_cephadm_fsid": parsed_args.fsid,
                "tripleo_cephadm_action": 'disable',
            }
            with oooutils.TempDirs() as tmp:
                oooutils.run_ansible_playbook(
                    playbook='disable_cephadm.yml',
                    inventory=inventory,
                    workdir=tmp,
                    playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                    verbosity=oooutils.playbook_verbosity(self=self),
                    extra_vars=extra_vars,
                    limit_hosts=ceph_hosts['_admin'][0],
                    reproduce_command=False,
                )

        # call the playbook to remove ssh_user_keys
        extra_vars = {
            "tripleo_cephadm_ssh_user": parsed_args.cephadm_ssh_user
        }
        if len(ceph_hosts['_admin']) > 0 or len(ceph_hosts['non_admin']) > 0:
            with oooutils.TempDirs() as tmp:
                oooutils.run_ansible_playbook(
                    playbook='ceph-admin-user-disable.yml',
                    inventory=inventory,
                    workdir=tmp,
                    playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                    verbosity=oooutils.playbook_verbosity(self=self),
                    extra_vars=extra_vars,
                    limit_hosts=",".join(ceph_hosts['_admin']
                                         + ceph_hosts['non_admin']),
                    reproduce_command=False,
                )


class OvercloudCephUserEnable(command.Command):

    log = logging.getLogger(__name__ + ".OvercloudCephUserEnable")
    auth_required = False

    def get_parser(self, prog_name):
        parser = super(OvercloudCephUserEnable, self).get_parser(prog_name)
        parser.add_argument('ceph_spec',
                            metavar='<ceph_spec.yaml>',
                            help=_(
                                "Path to an existing Ceph spec file "
                                "which describes the Ceph cluster "
                                "where the cephadm SSH user will be "
                                "created (if necessary) and have their "
                                "public and private keys installed. "
                                "Spec file is necessary to determine "
                                "which nodes to modify and if "
                                "a public or private key is required."))
        parser.add_argument('--fsid',
                            metavar='<FSID>', required=False,
                            help=_("The FSID of the Ceph cluster to be "
                                   "(re-)enabled. If the user disable "
                                   "option has been used, the FSID may "
                                   "be passed to the user enable option "
                                   "so that cephadm will be re-enabled "
                                   "for the Ceph cluster idenified "
                                   "by the FSID."))
        parser.add_argument('--standalone', default=False,
                            action='store_true',
                            help=_("Use single host Ansible inventory. "
                                   "Used only for development or testing "
                                   "environments."))
        parser = arg_parse_common(parser)

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        if parsed_args.fsid:
            try:
                uuid.UUID(parsed_args.fsid)
            except ValueError:
                raise oscexc.CommandError(
                    "--fsid %s is not a valid UUID."
                    % parsed_args.fsid)

        ceph_spec = os.path.abspath(parsed_args.ceph_spec)

        if not os.path.exists(ceph_spec):
            raise oscexc.CommandError(
                "Ceph spec file does not exist:"
                " %s" % parsed_args.ceph_spec)

        # use stack and working_dir to find inventory
        if not parsed_args.working_dir:
            working_dir = oooutils.get_default_working_dir(
                parsed_args.stack)
        else:
            working_dir = os.path.abspath(parsed_args.working_dir)
        oooutils.makedirs(working_dir)

        if parsed_args.standalone:
            inventory = oooutils.standalone_ceph_inventory(working_dir)
        else:
            inventory = os.path.join(working_dir,
                                     constants.TRIPLEO_STATIC_INVENTORY)
        if not os.path.exists(inventory):
            raise oscexc.CommandError(
                "Inventory file not found in working directory: "
                "%s. It should have been created by "
                "'openstack overcloud node provision'."
                % inventory)

        # get ceph hosts from spec and make sure they're in the inventory
        ceph_hosts = oooutils.get_host_groups_from_ceph_spec(ceph_spec)
        ceph_hosts_in_inventory(ceph_hosts, ceph_spec, inventory)

        extra_vars = {
            "tripleo_admin_user": parsed_args.cephadm_ssh_user,
            "distribute_private_key": True
        }
        for limit_list in [ceph_hosts['_admin'], ceph_hosts['non_admin']]:
            if len(limit_list) > 0:
                if parsed_args.standalone:
                    # In standalone, Ansible groups allovercloud and undercloud
                    # denote the same single host. So just use undercloud to
                    # avoid LP 1979093.
                    limit_list = ['undercloud']
                else:
                    # Need to include the undercloud, where the keys are
                    # generated, in the subset of allovercloud hosts,
                    # denoted by limit_list.
                    limit_list.append('undercloud')
                with oooutils.TempDirs() as tmp:
                    oooutils.run_ansible_playbook(
                        playbook='ceph-admin-user-playbook.yml',
                        inventory=inventory,
                        workdir=tmp,
                        playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                        verbosity=oooutils.playbook_verbosity(self=self),
                        extra_vars=extra_vars,
                        limit_hosts=",".join(limit_list),
                        reproduce_command=False,
                    )
                # _admin hosts are done now so don't distribute private key
                extra_vars["distribute_private_key"] = False

        if parsed_args.fsid:  # if no FSID, then no ceph cluster to disable
            # Call the playbook to toggle cephadm w/ enable
            extra_vars = {
                "tripleo_cephadm_fsid": parsed_args.fsid,
                "tripleo_cephadm_backend": 'cephadm',
                "tripleo_cephadm_action": 'enable'
            }
            with oooutils.TempDirs() as tmp:
                oooutils.run_ansible_playbook(
                    playbook='disable_cephadm.yml',
                    inventory=inventory,
                    workdir=tmp,
                    playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                    verbosity=oooutils.playbook_verbosity(self=self),
                    extra_vars=extra_vars,
                    limit_hosts=ceph_hosts['_admin'][0],
                    reproduce_command=False,
                )


class OvercloudCephSpec(command.Command):

    log = logging.getLogger(__name__ + ".OvercloudCephSpec")
    auth_required = False

    def get_parser(self, prog_name):
        parser = super(OvercloudCephSpec, self).get_parser(prog_name)

        parser.add_argument('baremetal_env', nargs='?',
                            metavar='<deployed_baremetal.yaml>',
                            help=_('Path to the environment file '
                                   'output from "openstack '
                                   'overcloud node provision". '
                                   'This argument may be excluded '
                                   'only if --standalone is used.'))
        parser.add_argument('-o', '--output', required=True,
                            metavar='<ceph_spec.yaml>',
                            help=_('The path to the output cephadm spec '
                                   'file to pass to the "openstack '
                                   'overcloud ceph deploy --ceph-spec '
                                   '<ceph_spec.yaml>" command.'))
        parser.add_argument('-y', '--yes', default=False, action='store_true',
                            help=_('Skip yes/no prompt before overwriting an '
                                   'existing <ceph_spec.yaml> output file '
                                   '(assume yes).'))
        parser.add_argument('--stack', dest='stack',
                            help=_('Name or ID of heat stack '
                                   '(default=Env: OVERCLOUD_STACK_NAME)'),
                            default=utils.env('OVERCLOUD_STACK_NAME',
                                              default='overcloud'))
        parser.add_argument(
            '--working-dir', action='store',
            help=_('The working directory for the deployment where all '
                   'input, output, and generated files will be stored.\n'
                   'Defaults to "$HOME/overcloud-deploy/<stack>"'))
        parser.add_argument('--roles-data',
                            help=_(
                                "Path to an alternative roles_data.yaml. "
                                "Used to decide which node gets which "
                                "Ceph mon, mgr, or osd service "
                                "based on the node's role in "
                                "<deployed_baremetal.yaml>."),
                            default=os.path.join(
                                constants.TRIPLEO_HEAT_TEMPLATES,
                                constants.OVERCLOUD_ROLES_FILE))
        parser.add_argument('--mon-ip',
                            help=_(
                                "IP address of the first Ceph monitor. "
                                "Only available with --standalone."),
                            default='')
        parser.add_argument('--standalone', default=False,
                            action='store_true',
                            help=_("Create a spec file for a standalone "
                                   "deployment. Used for single server "
                                   "development or testing environments."))
        parser.add_argument('--osd-spec',
                            help=_(
                                "Path to an existing OSD spec file. "
                                "When the Ceph spec file is generated "
                                "its OSD spec defaults to "
                                "{data_devices: {all: true}} "
                                "for all service_type osd. "
                                "Use --osd-spec to override the "
                                "data_devices value inside the "
                                "Ceph spec file."),
                            default=None)
        parser.add_argument('--crush-hierarchy',
                            help=_(
                                "Path to an existing crush hierarchy spec "
                                "file. "),
                            default=None)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        output_path = os.path.abspath(parsed_args.output)
        overwrite = parsed_args.yes
        if (os.path.exists(output_path) and not overwrite
                and not oooutils.prompt_user_for_confirmation(
                    'Overwrite existing file %s [y/N]?' % parsed_args.output,
                    self.log)):
            raise oscexc.CommandError("Will not overwrite existing file:"
                                      " %s. See the --yes parameter to "
                                      "override this behavior. " %
                                      parsed_args.output)
        else:
            overwrite = True

        if not parsed_args.working_dir:
            working_dir = oooutils.get_default_working_dir(
                parsed_args.stack)
        else:
            working_dir = os.path.abspath(parsed_args.working_dir)
        oooutils.makedirs(working_dir)

        if parsed_args.standalone:
            inventory = oooutils.standalone_ceph_inventory(working_dir)
        else:
            inventory = os.path.join(working_dir,
                                     constants.TRIPLEO_STATIC_INVENTORY)
        if not os.path.exists(inventory):
            raise oscexc.CommandError(
                "Inventory file not found in working directory: "
                "%s. It should have been created by "
                "'openstack overcloud node provision'."
                % inventory)

        # mandatory extra_vars are now set, add others conditionally
        extra_vars = {
            'ceph_spec_path': output_path,
        }

        # optional paths to pass to playbook
        if parsed_args.standalone is None and \
           parsed_args.baremetal_env is None:
            raise oscexc.CommandError(
                "Either <deployed_baremetal.yaml> "
                "or --standalone must be used.")

        if parsed_args.baremetal_env:
            baremetal_env_path = os.path.abspath(parsed_args.baremetal_env)
            if not os.path.exists(baremetal_env_path):
                raise oscexc.CommandError(
                    "Baremetal environment file does not exist:"
                    " %s" % parsed_args.baremetal_env)
            else:
                extra_vars['baremetal_deployed_path'] = \
                    os.path.abspath(parsed_args.baremetal_env)

        if parsed_args.roles_data:
            if not os.path.exists(parsed_args.roles_data):
                raise oscexc.CommandError(
                    "Roles Data file not found --roles-data %s."
                    % os.path.abspath(parsed_args.roles_data))
            else:
                extra_vars['tripleo_roles_path'] = \
                    os.path.abspath(parsed_args.roles_data)

        if parsed_args.mon_ip:
            if not oooutils.is_valid_ip(parsed_args.mon_ip):
                raise oscexc.CommandError(
                    "Invalid IP address '%s' passed to --mon-ip."
                    % parsed_args.mon_ip)
            else:
                if parsed_args.standalone:
                    extra_vars['tripleo_cephadm_first_mon_ip'] = \
                        parsed_args.mon_ip
                else:
                    raise oscexc.CommandError(
                        "Option --mon-ip may only be "
                        "used with --standalone")

        if parsed_args.osd_spec:
            if not os.path.exists(parsed_args.osd_spec):
                raise oscexc.CommandError(
                    "OSD Spec file not found --osd-spec %s."
                    % os.path.abspath(parsed_args.osd_spec))
            else:
                extra_vars['osd_spec_path'] = \
                    os.path.abspath(parsed_args.osd_spec)

        if parsed_args.crush_hierarchy:
            if not os.path.exists(parsed_args.crush_hierarchy):
                raise oscexc.CommandError(
                    "Crush Hierarchy Spec file not found --crush-hierarchy %s."
                    % os.path.abspath(parsed_args.crush_hierarchy))
            else:
                extra_vars['crush_hierarchy_path'] = \
                    os.path.abspath(parsed_args.crush_hierarchy)

        if parsed_args.standalone:
            spec_playbook = 'cli-standalone-ceph-spec.yaml'
            tags = ''
        else:
            spec_playbook = 'cli-deployed-ceph.yaml'
            tags = 'ceph_spec'

        with oooutils.TempDirs() as tmp:
            oooutils.run_ansible_playbook(
                playbook=spec_playbook,
                inventory=inventory,
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=oooutils.playbook_verbosity(self=self),
                extra_vars=extra_vars,
                reproduce_command=False,
                tags=tags,
            )
