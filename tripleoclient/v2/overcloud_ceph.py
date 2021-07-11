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

from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from osc_lib import utils

from tripleoclient import command
from tripleoclient import constants
from tripleoclient import utils as oooutils


class OvercloudCephDeploy(command.Command):

    log = logging.getLogger(__name__ + ".OvercloudCephDeploy")

    def get_parser(self, prog_name):
        parser = super(OvercloudCephDeploy, self).get_parser(prog_name)

        parser.add_argument('baremetal_env',
                            metavar='<deployed_baremetal.yaml>',
                            help=_('Path to the environment file '
                                   'output from "openstack '
                                   'overcloud node provision".'))
        parser.add_argument('-o', '--output', required=True,
                            metavar='<deployed_ceph.yaml>',
                            help=_('The path to the output environment '
                                   'file describing the Ceph deployment '
                                   ' to pass to the overcloud deployment.'))
        parser.add_argument('-y', '--yes', default=False, action='store_true',
                            help=_('Skip yes/no prompt before overwriting an '
                                   'existing <deployed_ceph.yaml> output file '
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
        spec_group = parser.add_mutually_exclusive_group()
        spec_group.add_argument('--ceph-spec',
                                help=_(
                                    "Path to an existing Ceph spec file. "
                                    "If not provided a spec will be generated "
                                    "automatically based on --roles-data and "
                                    "<deployed_baremetal.yaml>"),
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

        baremetal_env_path = os.path.abspath(parsed_args.baremetal_env)
        output_path = os.path.abspath(parsed_args.output)

        if not os.path.exists(baremetal_env_path):
            raise oscexc.CommandError(
                "Baremetal environment file does not exist:"
                " %s" % parsed_args.baremetal_env)

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
            "baremetal_deployed_path": baremetal_env_path,
            "deployed_ceph_tht_path": output_path,
            "working_dir": working_dir,
            "stack_name": parsed_args.stack,
        }

        # optional paths to pass to playbook
        if parsed_args.roles_data:
            if not os.path.exists(parsed_args.roles_data):
                raise oscexc.CommandError(
                    "Roles Data file not found --roles-data %s."
                    % os.path.abspath(parsed_args.roles_data))
            else:
                extra_vars['tripleo_roles_path'] = \
                    os.path.abspath(parsed_args.roles_data)

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

        # optional container vars to pass to playbook
        keys = ['ceph_namespace', 'ceph_image', 'ceph_tag']
        key = 'ContainerImagePrepare'
        container_dict = \
            oooutils.parse_container_image_prepare(key, keys,
                                                   parsed_args.
                                                   container_image_prepare)
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

        # call the playbook
        with oooutils.TempDirs() as tmp:
            oooutils.run_ansible_playbook(
                playbook='cli-deployed-ceph.yaml',
                inventory=inventory,
                workdir=tmp,
                playbook_dir=constants.ANSIBLE_TRIPLEO_PLAYBOOKS,
                verbosity=oooutils.playbook_verbosity(self=self),
                extra_vars=extra_vars,
            )
