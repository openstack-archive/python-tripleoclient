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
import glob
import logging
import os
import os.path
import re
import shutil
import six
import tempfile
import uuid
import yaml

from heatclient.common import template_utils
from heatclient import exc as hc_exc
from keystoneclient import exceptions as kscexc
from osc_lib.command import command
from osc_lib import exceptions as oscexc
from osc_lib.i18n import _
from osc_lib import utils as osc_utils
from swiftclient.exceptions import ClientException
from tripleo_common import update

from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils
from tripleoclient.workflows import deployment
from tripleoclient.workflows import parameters as workflow_params
from tripleoclient.workflows import plan_management


level = logging.getLogger('os_cloud_config').getEffectiveLevel()
logging.getLogger('os_cloud_config').setLevel(logging.ERROR)
from os_cloud_config import keystone
from os_cloud_config.utils import clients as occ_clients
logging.getLogger('os_cloud_config').setLevel(level)


class DeployOvercloud(command.Command):
    """Deploy Overcloud"""

    log = logging.getLogger(__name__ + ".DeployOvercloud")
    predeploy_errors = 0
    predeploy_warnings = 0

    def __init__(self, *args, **kwargs):
        self._password_cache = None
        super(DeployOvercloud, self).__init__(*args, **kwargs)

    def _update_parameters(self, args, network_client, stack):
        parameters = {}

        stack_is_new = stack is None

        parameters['UpdateIdentifier'] = ''
        parameters['StackAction'] = 'CREATE' if stack_is_new else 'UPDATE'

        # Update parameters from answers file:
        if args.answers_file is not None:
            with open(args.answers_file, 'r') as answers_file:
                answers = yaml.safe_load(answers_file)

            if args.templates is None:
                args.templates = answers['templates']
            if 'environments' in answers:
                if args.environment_files is not None:
                    answers['environments'].extend(args.environment_files)
                args.environment_files = answers['environments']

        param_args = (
            ('NtpServer', 'ntp_server'),
            ('ControllerCount', 'control_scale'),
            ('ComputeCount', 'compute_scale'),
            ('ObjectStorageCount', 'swift_storage_scale'),
            ('BlockStorageCount', 'block_storage_scale'),
            ('CephStorageCount', 'ceph_storage_scale'),
            ('OvercloudControlFlavor', 'control_flavor'),
            ('OvercloudComputeFlavor', 'compute_flavor'),
            ('OvercloudBlockStorageFlavor', 'block_storage_flavor'),
            ('OvercloudSwiftStorageFlavor', 'swift_storage_flavor'),
            ('OvercloudCephStorageFlavor', 'ceph_storage_flavor'),
        )

        if stack_is_new:
            new_stack_args = (
                ('NovaComputeLibvirtType', 'libvirt_type'),
            )
            param_args = param_args + new_stack_args

        # Update parameters from commandline
        for param, arg in param_args:
            if getattr(args, arg, None) is not None:
                parameters[param] = getattr(args, arg)

        return parameters

    def _create_registration_env(self, args):
        tht_root = args.templates

        registry = os.path.join(
            tht_root,
            constants.RHEL_REGISTRATION_EXTRACONFIG_NAME,
            'rhel-registration-resource-registry.yaml')
        user_env = {'rhel_reg_method': args.reg_method,
                    'rhel_reg_org': args.reg_org,
                    'rhel_reg_force': args.reg_force,
                    'rhel_reg_sat_url': args.reg_sat_url,
                    'rhel_reg_activation_key': args.reg_activation_key}
        return [registry], {"parameter_defaults": user_env}

    def _create_parameters_env(self, parameters):
        parameter_defaults = {"parameter_defaults": parameters}
        return parameter_defaults

    def _process_multiple_environments(self, created_env_files, added_files,
                                       tht_root, user_tht_root, cleanup=True):
        env_files = {}
        localenv = {}
        for env_path in created_env_files:
            self.log.debug("Processing environment files %s" % env_path)
            abs_env_path = os.path.abspath(env_path)
            if abs_env_path.startswith(user_tht_root):
                new_env_path = abs_env_path.replace(user_tht_root, tht_root)
                self.log.debug("Redirecting env file %s to %s"
                               % (abs_env_path, new_env_path))
                env_path = new_env_path
            try:
                files, env = template_utils.process_environment_and_files(
                    env_path=env_path)
            except hc_exc.CommandError as ex:
                # This provides fallback logic so that we can reference files
                # inside the resource_registry values that may be rendered via
                # j2.yaml templates, where the above will fail because the
                # file doesn't exist in user_tht_root, but it is in tht_root
                # See bug https://bugs.launchpad.net/tripleo/+bug/1625783
                # for details on why this is needed (backwards-compatibility)
                self.log.debug("Error %s processing environment file %s"
                               % (six.text_type(ex), env_path))
                # Use the temporary path as it's possible the environment
                # itself was rendered via jinja.
                with open(env_path, 'r') as f:
                    env_map = yaml.safe_load(f)
                env_registry = env_map.get('resource_registry', {})
                env_dirname = os.path.dirname(os.path.abspath(env_path))
                for rsrc, rsrc_path in six.iteritems(env_registry):
                    # We need to calculate the absolute path relative to
                    # env_path not cwd (which is what abspath uses).
                    abs_rsrc_path = os.path.normpath(
                        os.path.join(env_dirname, rsrc_path))
                    # If the absolute path matches user_tht_root, rewrite
                    # a temporary environment pointing at tht_root instead
                    if abs_rsrc_path.startswith(user_tht_root):
                        new_rsrc_path = abs_rsrc_path.replace(user_tht_root,
                                                              tht_root)
                        self.log.debug("Rewriting %s %s path to %s"
                                       % (env_path, rsrc, new_rsrc_path))
                        env_registry[rsrc] = new_rsrc_path
                    else:
                        env_registry[rsrc] = abs_rsrc_path
                env_map['resource_registry'] = env_registry
                f_name = os.path.basename(os.path.splitext(abs_env_path)[0])
                with tempfile.NamedTemporaryFile(dir=tht_root,
                                                 prefix="env-%s-" % f_name,
                                                 suffix=".yaml",
                                                 mode="w",
                                                 delete=cleanup) as f:
                    self.log.debug("Rewriting %s environment to %s"
                                   % (env_path, f.name))
                    f.write(yaml.safe_dump(env_map, default_flow_style=False))
                    f.flush()
                    files, env = template_utils.process_environment_and_files(
                        env_path=f.name)
            if files:
                self.log.debug("Adding files %s for %s" % (files, env_path))
                env_files.update(files)

            # 'env' can be a deeply nested dictionary, so a simple update is
            # not enough
            localenv = template_utils.deep_update(localenv, env)
        return env_files, localenv

    def _heat_deploy(self, stack, stack_name, template_path, parameters,
                     env_files, timeout, tht_root, env, update_plan_only,
                     run_validations, skip_deploy_identifier):
        """Verify the Baremetal nodes are available and do a stack update"""

        clients = self.app.client_manager
        workflow_client = clients.workflow_engine

        if stack:
            update.add_breakpoints_cleanup_into_env(env)

        self.log.debug("Getting template contents from plan %s" % stack_name)
        # We need to reference the plan here, not the local
        # tht root, as we need template_object to refer to
        # the rendered overcloud.yaml, not the tht_root overcloud.j2.yaml
        # FIXME(shardy) we need to move more of this into mistral actions
        plan_yaml_path = os.path.relpath(template_path, tht_root)

        # heatclient template_utils needs a function that can
        # retrieve objects from a container by name/path
        objectclient = clients.tripleoclient.object_store

        def do_object_request(method='GET', object_path=None):
            obj = objectclient.get_object(stack_name, object_path)
            return obj and obj[1]

        template_files, template = template_utils.get_template_contents(
            template_object=plan_yaml_path,
            object_request=do_object_request)

        files = dict(list(template_files.items()) + list(env_files.items()))

        number_controllers = int(parameters.get('ControllerCount', 0))
        if number_controllers > 1:
            if not env.get('parameter_defaults').get('NtpServer'):
                raise exceptions.InvalidConfiguration(
                    'Specify --ntp-server as parameter or NtpServer in '
                    'environments when using multiple controllers '
                    '(with HA).')

        clients = self.app.client_manager

        moved_files = self._upload_missing_files(
            stack_name, objectclient, files, tht_root)
        self._process_and_upload_environment(
            stack_name, objectclient, env, moved_files, tht_root,
            workflow_client)

        if not update_plan_only:
            deployment.deploy_and_wait(
                self.log, clients, stack, stack_name,
                self.app_args.verbose_level,
                timeout=timeout,
                run_validations=run_validations,
                skip_deploy_identifier=skip_deploy_identifier)

    def _load_environment_directories(self, directories):
        if os.environ.get('TRIPLEO_ENVIRONMENT_DIRECTORY'):
            directories.append(os.environ.get('TRIPLEO_ENVIRONMENT_DIRECTORY'))

        environments = []
        for d in directories:
            if os.path.exists(d) and d != '.':
                self.log.debug("Environment directory: %s" % d)
                for f in sorted(glob.glob(os.path.join(d, '*.yaml'))):
                    self.log.debug("Environment directory file: %s" % f)
                    if os.path.isfile(f):
                        environments.append(f)
        return environments

    def _process_and_upload_environment(self, container_name, swift_client,
                                        env, moved_files, tht_root, mistral):
        """Process the environment and upload to Swift

        The environment at this point should be the result of the merged
        custom user environments. We need to look at the paths in the
        environment and update any that changed when they were uploaded to
        swift.
        """

        file_prefix = "file://"

        if 'resource_registry' in env:
            for name, path in env['resource_registry'].items():
                if not isinstance(path, six.string_types):
                    continue
                if path in moved_files:
                    new_path = moved_files[path]
                    env['resource_registry'][name] = new_path
                elif path.startswith(file_prefix):
                    path = path[len(file_prefix):]
                    if path.startswith(tht_root):
                        path = path[len(tht_root):]
                    # We want to make sure all the paths are relative.
                    if path.startswith("/"):
                        path = path[1:]
                    env['resource_registry'][name] = path

        # Parameters are removed from the environment and sent to the update
        # parameters action, this stores them in the Mistral environment and
        # means the UI can find them.
        if 'parameter_defaults' in env:
            params = env.pop('parameter_defaults')
            workflow_params.update_parameters(
                mistral, container=container_name, parameters=params)

        contents = yaml.safe_dump(env)

        # Until we have a well defined plan update workflow in tripleo-common
        # we need to manually add an environment in swift and mistral for users
        # custom environments passed to the deploy command.
        # See bug: https://bugs.launchpad.net/tripleo/+bug/1623431
        swift_path = "user-environment.yaml"
        swift_client.put_object(container_name, swift_path, contents)

        mistral_env = mistral.environments.get(container_name)
        user_env = {'path': swift_path}
        if user_env not in mistral_env.variables['environments']:
            mistral_env.variables['environments'].append(user_env)
            mistral.environments.update(
                name=container_name,
                variables=mistral_env.variables
            )

    def _upload_missing_files(self, container_name, swift_client, files_dict,
                              tht_root):
        """Find the files referenced in custom environments and upload them

        Heat environments can be passed to be included in the deployment, these
        files can include references to other files anywhere on the local
        file system. These need to be discovered and uploaded to Swift. When
        they have been uploaded to Swift the path to them will be different,
        the new paths are store din the file_relocation dict, which is returned
        and used by _process_and_upload_environment which will merge the
        environment and update paths to the relative Swift path.
        """

        file_relocation = {}
        file_prefix = "file://"

        # select files files for relocation & upload
        for fullpath in files_dict.keys():

            if not fullpath.startswith(file_prefix):
                continue

            path = fullpath[len(file_prefix):]

            if path.startswith(tht_root):
                # This should already be uploaded.
                continue

            file_relocation[fullpath] = "user-files/{}".format(path[1:])

        # make sure links within files point to new locations, and upload them
        for orig_path, reloc_path in file_relocation.items():
            link_replacement = utils.relative_link_replacement(
                file_relocation, os.path.dirname(reloc_path))
            contents = utils.replace_links_in_template_contents(
                files_dict[orig_path], link_replacement)
            swift_client.put_object(container_name, reloc_path, contents)

        return file_relocation

    def _download_missing_files_from_plan(self, tht_dir, plan_name):
        # get and download missing files into tmp directory
        clients = self.app.client_manager
        objectclient = clients.tripleoclient.object_store
        plan_list = objectclient.get_container(plan_name)
        plan_filenames = [f['name'] for f in plan_list[1]]
        added_files = {}
        for pf in plan_filenames:
            file_path = os.path.join(tht_dir, pf)
            if not os.path.isfile(file_path):
                self.log.debug("Missing in templates directory, downloading \
                               %s from swift into %s" % (pf, file_path))
                if not os.path.exists(os.path.dirname(file_path)):
                    os.makedirs(os.path.dirname(file_path))
                with open(file_path, 'w') as f:
                    f.write(objectclient.get_object(plan_name, pf)[1])
                added_files[pf] = file_path
        self.log.debug("added_files = %s" % added_files)
        return added_files

    def _deploy_tripleo_heat_templates_tmpdir(self, stack, parsed_args):
        # copy tht_root to temporary directory because we need to
        # download any missing (e.g j2 rendered) files from the plan
        tht_root = os.path.abspath(parsed_args.templates)
        tht_tmp = tempfile.mkdtemp(prefix='tripleoclient-')
        new_tht_root = "%s/tripleo-heat-templates" % tht_tmp
        self.log.debug("Creating temporary templates tree in %s"
                       % new_tht_root)
        try:
            shutil.copytree(tht_root, new_tht_root, symlinks=True)
            self._deploy_tripleo_heat_templates(stack, parsed_args,
                                                new_tht_root, tht_root)
        finally:
            if parsed_args.no_cleanup:
                self.log.warning("Not cleaning temporary directory %s"
                                 % tht_tmp)
            else:
                shutil.rmtree(tht_tmp)

    def _deploy_tripleo_heat_templates(self, stack, parsed_args,
                                       tht_root, user_tht_root):
        """Deploy the fixed templates in TripleO Heat Templates"""
        clients = self.app.client_manager
        network_client = clients.network
        workflow_client = clients.workflow_engine

        parameters = self._update_parameters(
            parsed_args, network_client, stack)

        plans = plan_management.list_deployment_plans(workflow_client)
        generate_passwords = not parsed_args.disable_password_generation

        # TODO(d0ugal): We need to put a more robust strategy in place here to
        #               handle updating plans.
        if parsed_args.stack in plans:
            # Upload the new plan templates to swift to replace the existing
            # templates.
            plan_management.update_plan_from_templates(
                clients, parsed_args.stack, tht_root, parsed_args.roles_file,
                generate_passwords)
        else:
            plan_management.create_plan_from_templates(
                clients, parsed_args.stack, tht_root, parsed_args.roles_file,
                generate_passwords)

        # Get any missing (e.g j2 rendered) files from the plan to tht_root
        added_files = self._download_missing_files_from_plan(
            tht_root, parsed_args.stack)

        print("Deploying templates in the directory {0}".format(
            os.path.abspath(tht_root)))

        self.log.debug("Creating Environment files")
        env = {}
        created_env_files = []

        if parsed_args.environment_directories:
            created_env_files.extend(self._load_environment_directories(
                parsed_args.environment_directories))
        env.update(self._create_parameters_env(parameters))

        if parsed_args.rhel_reg:
            reg_env_files, reg_env = self._create_registration_env(parsed_args)
            created_env_files.extend(reg_env_files)
            template_utils.deep_update(env, reg_env)
        if parsed_args.environment_files:
            created_env_files.extend(parsed_args.environment_files)

        self.log.debug("Processing environment files %s" % created_env_files)
        env_files, localenv = self._process_multiple_environments(
            created_env_files, added_files, tht_root, user_tht_root,
            cleanup=not parsed_args.no_cleanup)
        template_utils.deep_update(env, localenv)

        self._try_overcloud_deploy_with_compat_yaml(
            tht_root, stack, parsed_args.stack, parameters, env_files,
            parsed_args.timeout, env, parsed_args.update_plan_only,
            parsed_args.run_validations, parsed_args.skip_deploy_identifier)

    def _try_overcloud_deploy_with_compat_yaml(self, tht_root, stack,
                                               stack_name, parameters,
                                               env_files, timeout,
                                               env, update_plan_only,
                                               run_validations,
                                               skip_deploy_identifier):
        overcloud_yaml = os.path.join(tht_root, constants.OVERCLOUD_YAML_NAME)
        try:
            self._heat_deploy(stack, stack_name, overcloud_yaml,
                              parameters, env_files, timeout,
                              tht_root, env, update_plan_only,
                              run_validations, skip_deploy_identifier)
        except ClientException as e:
            messages = 'Failed to deploy: %s' % str(e)
            raise ValueError(messages)

    def _is_tls_enabled(self, overcloud_endpoint):
        return overcloud_endpoint.startswith('https')

    def _get_password(self, stack_name, password_name):
        # NOTE(d0ugal): This method is only used during the post-deploy config
        # steps that are now deprecated. It should be removed when they are.
        if self._password_cache is None:
            self._password_cache = workflow_params.get_overcloud_passwords(
                self.app.client_manager,
                container=stack_name,
                queue_name=str(uuid.uuid4()))

        return self._password_cache[password_name]

    def _keystone_init(self, overcloud_endpoint, overcloud_ip_or_fqdn,
                       parsed_args, stack):
        keystone_admin_ip = utils.get_endpoint('KeystoneAdmin', stack)
        keystone_admin_ip = utils.unbracket_ipv6(keystone_admin_ip)
        keystone_internal_ip = utils.get_endpoint('KeystoneInternal', stack)
        keystone_internal_ip = utils.unbracket_ipv6(keystone_internal_ip)
        tls_enabled = self._is_tls_enabled(overcloud_endpoint)
        keystone_tls_host = None
        if tls_enabled:
            # NOTE(jaosorior): This triggers set up the keystone endpoint with
            # the https protocol and the required port set in
            # keystone.initialize.
            keystone_tls_host = overcloud_ip_or_fqdn

        keystone_client = occ_clients.get_keystone_client(
            'admin',
            self._get_password(stack.stack_name, "AdminPassword"),
            'admin',
            overcloud_endpoint)

        services = {}
        for service, data in six.iteritems(constants.SERVICE_LIST):
            try:
                keystone_client.services.find(name=service)
            except kscexc.NotFound:
                service_data = self._set_service_data(service, data, stack)
                if service_data:
                    services.update({service: service_data})

        if services:
            # This was deprecated in Newton.  The deprecation message and
            # os-cloud-config keystone init should remain until at least the
            # Pike release to ensure users have a chance to update their
            # templates, including ones for the previous release.
            self.log.warning('DEPRECATED: '
                             'It appears Keystone was not initialized by '
                             'Puppet. Will do initialization via '
                             'os-cloud-config, but this behavior is '
                             'deprecated. Please update your templates to a '
                             'version that has Puppet initialization of '
                             'Keystone.'
                             )
            # NOTE(jaosorior): These ports will be None if the templates
            # don't support the EndpointMap as an output yet. And so the
            # default values will be taken.
            public_port = None
            admin_port = None
            internal_port = None
            endpoint_map = utils.get_endpoint_map(stack)
            if endpoint_map:
                public_port = endpoint_map.get('KeystonePublic').get('port')
                admin_port = endpoint_map.get('KeystoneAdmin').get('port')
                internal_port = endpoint_map.get(
                    'KeystoneInternal').get('port')

            # TODO(rbrady): check usages of get_password
            keystone.initialize(
                keystone_admin_ip,
                self._get_password(stack.stack_name, "AdminToken"),
                'admin@example.com',
                self._get_password(stack.stack_name, "AdminPassword"),
                ssl=keystone_tls_host,
                public=overcloud_ip_or_fqdn,
                user=parsed_args.overcloud_ssh_user,
                admin=keystone_admin_ip,
                internal=keystone_internal_ip,
                public_port=public_port,
                admin_port=admin_port,
                internal_port=internal_port)

            if not tls_enabled:
                # NOTE(bcrochet): Bad hack. Remove the ssl_port info from the
                # os_cloud_config.SERVICES dictionary
                for service_name, data in keystone.SERVICES.items():
                    data.pop('ssl_port', None)

            keystone.setup_endpoints(
                services,
                client=keystone_client,
                os_auth_url=overcloud_endpoint,
                public_host=overcloud_ip_or_fqdn)
        # End of deprecated Keystone init

    def _set_service_data(self, service, data, stack):
        self.log.debug("Setting data for service '%s'" % service)
        service_data = data.copy()
        service_data.pop('password_field', None)

        endpoint_map = utils.get_endpoint_map(stack)
        try:
            service_data.update(
                self._get_base_service_data(service, data, stack))
        except KeyError:
            output_source = "service IPs"
            if endpoint_map:
                output_source = "endpoint map"
            self.log.debug(
                ("Skipping \"{}\" postconfig because it wasn't found in the "
                 "{} output").format(service, output_source))
            return None
        if not endpoint_map:
            return service_data
        service_data.update(self._get_endpoint_data(service, endpoint_map,
                                                    stack))
        return service_data

    def _get_base_service_data(self, service, data, stack):
        service_data = {}
        password_field = data.get('password_field')
        if password_field:
            service_data['password'] = self._get_password(
                stack.stack_name,
                password_field)

        # Set internal endpoint
        service_name_internal = self._format_endpoint_name(service, 'internal')
        service_data['internal_host'] = utils.get_endpoint(
            service_name_internal, stack)
        return service_data

    def _get_endpoint_data(self, service, endpoint_map, stack):
        endpoint_data = {}
        # Set standard port
        service_name_internal = self._format_endpoint_name(service, 'internal')
        endpoint_data['port'] = endpoint_map[service_name_internal]['port']

        # Set public endpoint
        service_name_public = self._format_endpoint_name(service, 'public')
        public_endpoint_data = endpoint_map.get(service_name_public)
        endpoint_data['public_host'] = public_endpoint_data['host']

        # Set SSL port
        if public_endpoint_data['uri'].startswith('https'):
            endpoint_data['ssl_port'] = public_endpoint_data['port']
        return endpoint_data

    def _format_endpoint_name(self, service, interface):
        return re.sub('v[0-9]+', '',
                      service.capitalize() + interface.capitalize())

    def _endpoints_managed(self, stack):
        for output in stack.to_dict().get('outputs', {}):
            if output['output_key'] == 'ManagedEndpoints':
                # NOTE(jaosorior): We don't really care about the value as
                # long as the key is there.
                return output['output_value']
        return False

    def _deploy_postconfig(self, stack, parsed_args):
        self.log.debug("_deploy_postconfig(%s)" % parsed_args)

        overcloud_endpoint = utils.get_overcloud_endpoint(stack)
        # NOTE(jaosorior): The overcloud endpoint can contain an IP address or
        # an FQDN depending on how what it's configured to output in the
        # tripleo-heat-templates. Such a configuration can be done by
        # overriding the EndpointMap through parameter_defaults.
        overcloud_ip_or_fqdn = six.moves.urllib.parse.urlparse(
            overcloud_endpoint).hostname

        keystone_admin_ip = utils.get_endpoint('KeystoneAdmin', stack)
        no_proxy = os.environ.get('no_proxy', overcloud_ip_or_fqdn)
        no_proxy_list = map(utils.bracket_ipv6,
                            [no_proxy, overcloud_ip_or_fqdn,
                             keystone_admin_ip])
        os.environ['no_proxy'] = ','.join(
            [x for x in no_proxy_list if x is not None])

        utils.remove_known_hosts(overcloud_ip_or_fqdn)

        if not self._endpoints_managed(stack):
            self._keystone_init(overcloud_endpoint, overcloud_ip_or_fqdn,
                                parsed_args, stack)
        else:
            self.log.debug("Keystone endpoints and services are managed by "
                           "puppet. Skipping post-config.")

    def _validate_args(self, parsed_args):
        if parsed_args.templates is None and parsed_args.answers_file is None:
            raise oscexc.CommandError(
                "You must specify either --templates or --answers-file")

        if parsed_args.environment_files:
            nonexisting_envs = []
            jinja2_envs = []
            for env_file in parsed_args.environment_files:

                if env_file.endswith(".j2.yaml"):
                    jinja2_envs.append(env_file)
                elif not os.path.isfile(env_file):
                    # Tolerate missing file if there's a j2.yaml file that will
                    # be rendered in the plan but not available locally (yet)
                    if not os.path.isfile(env_file.replace(".yaml",
                                                           ".j2.yaml")):
                        nonexisting_envs.append(env_file)
            if jinja2_envs:
                rewritten_paths = [e.replace(".j2.yaml", ".yaml")
                                   for e in jinja2_envs]
                raise oscexc.CommandError(
                    "Error: The following jinja2 files were provided: -e "
                    "{}. Did you mean -e {}?".format(
                        ' -e '.join(jinja2_envs),
                        ' -e '.join(rewritten_paths)))
            if nonexisting_envs:
                raise oscexc.CommandError(
                    "Error: The following files were not found: {0}".format(
                        ", ".join(nonexisting_envs)))

        # Check if disable_upgrade_deployment is set once
        self.log.debug("Checking that the disable_upgrade_deployment flag "
                       "is set at least once in the roles file")
        if parsed_args.roles_file:
            roles_data = yaml.safe_load(open(parsed_args.roles_file).read())
            disable_upgrade_deployment_set = False
            for r in roles_data:
                if r.get("disable_upgrade_deployment"):
                    disable_upgrade_deployment_set = True
                    break
            if not disable_upgrade_deployment_set:
                self.log.warning(
                    "The disable_upgrade_deployment flag is not set in the "
                    "roles file. This flag is expected when you have a "
                    "nova-compute or swift-storage role. Please check the "
                    "contents of the roles file: %s" % roles_data)
                if parsed_args.validation_warnings_fatal:
                    raise exceptions.InvalidConfiguration()

    def _get_default_role_counts(self, parsed_args):

        if parsed_args.roles_file:
            roles_data = yaml.safe_load(open(parsed_args.roles_file).read())
        else:
            # Assume default role counts
            return {
                'ControllerCount': 1,
                'ComputeCount': 1,
                'ObjectStorageCount': 0,
                'BlockStorageCount': 0,
                'CephStorageCount': 0
            }

        default_role_counts = {}
        for r in roles_data:
            count_default = r.get('CountDefault', 0)
            default_role_counts.setdefault(
                "%sCount" % r['name'],
                count_default)

        return default_role_counts

    def _predeploy_verify_capabilities(self, stack, parameters, parsed_args):
        self.predeploy_errors = 0
        self.predeploy_warnings = 0
        self.log.debug("Starting _pre_verify_capabilities")

        bm_client = self.app.client_manager.baremetal

        self._check_boot_images()

        flavors = self._collect_flavors(parsed_args)

        self._check_ironic_boot_configuration(bm_client)

        errors, warnings = utils.assign_and_verify_profiles(
            bm_client, flavors,
            assign_profiles=False,
            dry_run=parsed_args.dry_run
        )
        self.predeploy_errors += errors
        self.predeploy_warnings += warnings

        compute_client = self.app.client_manager.compute

        self.log.debug("Checking hypervisor stats")
        if utils.check_hypervisor_stats(compute_client) is None:
            self.log.error("Expected hypervisor stats not met")
            self.predeploy_errors += 1

        self.log.debug("Checking nodes count")
        default_role_counts = self._get_default_role_counts(parsed_args)
        enough_nodes, count, ironic_nodes_count = utils.check_nodes_count(
            bm_client,
            stack,
            parameters,
            default_role_counts
        )
        if not enough_nodes:
            self.log.error(
                "Not enough nodes - available: {0}, requested: {1}".format(
                    ironic_nodes_count, count))
            self.predeploy_errors += 1

        return self.predeploy_errors, self.predeploy_warnings

    __kernel_id = None
    __ramdisk_id = None

    def _image_ids(self):
        if self.__kernel_id is not None and self.__ramdisk_id is not None:
            return self.__kernel_id, self.__ramdisk_id

        image_client = self.app.client_manager.image
        kernel_id, ramdisk_id = None, None
        try:
            kernel_id = osc_utils.find_resource(
                image_client.images, 'bm-deploy-kernel').id
        except AttributeError:
            self.log.exception("Please make sure there is only one image "
                               "named 'bm-deploy-kernel' in glance.")
        except oscexc.CommandError:
            # kernel_id=None will be returned and an error will be logged from
            # self._check_boot_images
            pass

        try:
            ramdisk_id = osc_utils.find_resource(
                image_client.images, 'bm-deploy-ramdisk').id
        except AttributeError:
            self.log.exception("Please make sure there is only one image "
                               "named 'bm-deploy-ramdisk' in glance.")
        except oscexc.CommandError:
            # ramdisk_id=None will be returned and an error will be logged from
            # self._check_boot_images
            pass

        self.log.debug("Using kernel ID: {0} and ramdisk ID: {1}".format(
            kernel_id, ramdisk_id))

        self.__kernel_id = kernel_id
        self.__ramdisk_id = ramdisk_id
        return kernel_id, ramdisk_id

    def _check_boot_images(self):
        kernel_id, ramdisk_id = self._image_ids()
        message = ("No image with the name '{}' found - make "
                   "sure you've uploaded boot images")
        if kernel_id is None:
            self.predeploy_errors += 1
            self.log.error(message.format('bm-deploy-kernel'))
        if ramdisk_id is None:
            self.predeploy_errors += 1
            self.log.error(message.format('bm-deploy-ramdisk'))

    def _collect_flavors(self, parsed_args):
        """Validate and collect nova flavors in use.

        Ensure that selected flavors (--ROLE-flavor) are valid in nova.
        Issue a warning of local boot is not set for a flavor.

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
                flavor, old_scale = result[flavor_name]
            except KeyError:
                pass
            else:
                result[flavor_name] = (flavor, old_scale + scale)
                continue

            try:
                flavor = flavors[flavor_name]
            except KeyError:
                self.predeploy_errors += 1
                self.log.error(message.format(target, flavor_name))
                continue

            if flavor.get_keys().get('capabilities:boot_option', '') \
                    != 'local':
                self.predeploy_warnings += 1
                self.log.warning(
                    'Flavor %s "capabilities:boot_option" is not set to '
                    '"local". Nodes must have ability to PXE boot from '
                    'deploy image.', flavor_name)
                self.log.warning(
                    'Recommended solution: openstack flavor set --property '
                    '"cpu_arch"="x86_64" --property '
                    '"capabilities:boot_option"="local" ' + flavor_name)

            result[flavor_name] = (flavor, scale)

        return result

    def _check_ironic_boot_configuration(self, bm_client):
        for node in bm_client.node.list(detail=True, maintenance=False):
            self.log.debug("Checking config for Node {0}".format(node.uuid))
            self._check_node_boot_configuration(node)

    def _check_node_boot_configuration(self, node):
        kernel_id, ramdisk_id = self._image_ids()
        self.log.debug("Doing boot checks for {}".format(node.uuid))
        message = ("Node uuid={uuid} has an incorrectly configured "
                   "{property}. Expected \"{expected}\" but got "
                   "\"{actual}\".")
        if node.driver_info.get('deploy_ramdisk') != ramdisk_id:
            self.predeploy_errors += 1
            self.log.error(message.format(
                uuid=node.uuid,
                property='driver_info/deploy_ramdisk',
                expected=ramdisk_id,
                actual=node.driver_info.get('deploy_ramdisk')
            ))
        if node.driver_info.get('deploy_kernel') != kernel_id:
            self.predeploy_errors += 1
            self.log.error(message.format(
                uuid=node.uuid,
                property='driver_info/deploy_kernel',
                expected=kernel_id,
                actual=node.driver_info.get('deploy_kernel')
            ))
        if 'boot_option:local' not in node.properties.get('capabilities', ''):
            self.predeploy_warnings += 1
            self.log.warning(message.format(
                uuid=node.uuid,
                property='properties/capabilities',
                expected='boot_option:local',
                actual=node.properties.get('capabilities')
            ))

    def get_parser(self, prog_name):
        # add_help doesn't work properly, set it to False:
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            prog=prog_name,
            add_help=False
        )
        parser.add_argument(
            '--templates', nargs='?', const=constants.TRIPLEO_HEAT_TEMPLATES,
            help=_("The directory containing the Heat templates to deploy"),
        )
        parser.add_argument('--stack',
                            help=_("Stack name to create or update"),
                            default='overcloud')
        parser.add_argument('--timeout', '-t', metavar='<TIMEOUT>',
                            type=int, default=240,
                            help=_('Deployment timeout in minutes.'))
        utils.add_deployment_plan_arguments(parser, mark_as_depr=True)
        parser.add_argument('--libvirt-type',
                            choices=['kvm', 'qemu'],
                            help=_('Libvirt domain type.'))
        parser.add_argument('--ntp-server',
                            help=_('The NTP for overcloud nodes. '))
        parser.add_argument(
            '--no-proxy',
            default=os.environ.get('no_proxy', ''),
            help=_('A comma separated list of hosts that should not be '
                   'proxied.')
        )
        parser.add_argument(
            '--overcloud-ssh-user',
            default='heat-admin',
            help=_('User for ssh access to overcloud nodes')
        )
        parser.add_argument(
            '--environment-file', '-e', metavar='<HEAT ENVIRONMENT FILE>',
            action='append', dest='environment_files',
            help=_('Environment files to be passed to the heat stack-create '
                   'or heat stack-update command. (Can be specified more than '
                   'once.)')
        )
        parser.add_argument(
            '--environment-directory', metavar='<HEAT ENVIRONMENT DIRECTORY>',
            action='append', dest='environment_directories',
            default=[os.path.join(os.environ.get('HOME', ''), '.tripleo',
                     'environments')],
            help=_('Environment file directories that are automatically '
                   ' added to the heat stack-create or heat stack-update'
                   ' commands. Can be specified more than once. Files in'
                   ' directories are loaded in ascending sort order.')
        )
        parser.add_argument(
            '--roles-file', '-r', dest='roles_file',
            help=_('Roles file, overrides the default %s in the --templates '
                   'directory') % constants.OVERCLOUD_ROLES_FILE
        )
        parser.add_argument(
            '--no-cleanup', action='store_true',
            help=_('Don\'t cleanup temporary files, just log their location')
        )
        parser.add_argument(
            '--update-plan-only',
            action='store_true',
            help=_('Only update the plan. Do not perform the actual '
                   'deployment. NOTE: Will move to a discrete command  in a '
                   'future release.')
        )
        parser.add_argument(
            '--validation-errors-nonfatal',
            dest='validation_errors_fatal',
            action='store_false',
            default=True,
            help=_('Allow the deployment to continue in spite of validation '
                   'errors. Note that attempting deployment while errors '
                   'exist is likely to fail.')
        )
        parser.add_argument(
            '--validation-warnings-fatal',
            action='store_true',
            default=False,
            help=_('Exit if there are warnings from the configuration '
                   'pre-checks.')
        )
        parser.add_argument(
            '--disable-validations',
            action='store_true',
            default=False,
            help=_('Disable the pre-deployment validations entirely. These '
                   'validations are the built-in pre-deployment validations. '
                   'To enable external validations from tripleo-validations, '
                   'use the --run-validations flag.'))
        parser.add_argument(
            '--dry-run',
            action='store_true',
            default=False,
            help=_('Only run validations, but do not apply any changes.')
        )
        parser.add_argument(
            '--run-validations',
            action='store_true',
            default=False,
            help=_('Run external validations from the tripleo-validations '
                   'project.'))
        parser.add_argument(
            '--skip-postconfig',
            action='store_true',
            default=False,
            help=_('Skip the overcloud post-deployment configuration.')
        )
        parser.add_argument(
            '--force-postconfig',
            action='store_true',
            default=False,
            help=_('Force the overcloud post-deployment configuration.')
        )
        parser.add_argument(
            '--skip-deploy-identifier',
            action='store_true',
            default=False,
            help=_('Skip generation of a unique identifier for the '
                   'DeployIdentifier parameter. The software configuration '
                   'deployment steps will only be triggered if there is an '
                   'actual change to the configuration. This option should '
                   'be used with Caution, and only if there is confidence '
                   'that the software configuration does not need to be '
                   'run, such as when scaling out certain roles.')
        )
        reg_group = parser.add_argument_group('Registration Parameters')
        reg_group.add_argument(
            '--rhel-reg',
            action='store_true',
            help=_('Register overcloud nodes to the customer portal or a '
                   'satellite.')
        )
        reg_group.add_argument(
            '--reg-method',
            choices=['satellite', 'portal'],
            default='satellite',
            help=_('RHEL registration method to use for the overcloud nodes.')
        )
        reg_group.add_argument(
            '--reg-org',
            default='',
            help=_('Organization key to use for registration.')
        )
        reg_group.add_argument(
            '--reg-force',
            action='store_true',
            help=_('Register the system even if it is already registered.')
        )
        reg_group.add_argument(
            '--reg-sat-url',
            default='',
            help=_('Satellite server to register overcloud nodes.')
        )
        reg_group.add_argument(
            '--reg-activation-key',
            default='',
            help=_('Activation key to use for registration.')
        )
        parser.add_argument(
            '--answers-file',
            help=_('Path to a YAML file with arguments and parameters.')
        )
        parser.add_argument(
            '--disable-password-generation',
            action='store_true',
            default=False,
            help=_('Disable password generation.')
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        # Swiftclient logs things like 404s at error level, which is a problem
        # because we use EAFP to check for the existence of files.  Turn off
        # most swiftclient logging to avoid cluttering up our output with
        # pointless tracebacks.
        sc_logger = logging.getLogger("swiftclient")
        sc_logger.setLevel(logging.CRITICAL)

        self._validate_args(parsed_args)

        clients = self.app.client_manager
        orchestration_client = clients.orchestration

        stack = utils.get_stack(orchestration_client, parsed_args.stack)

        if stack and stack.stack_status == 'IN_PROGRESS':
            raise exceptions.StackInProgress(
                "Unable to deploy as the stack '{}' status is '{}'".format(
                    stack.stack_name, stack.stack_status))

        parameters = self._update_parameters(
            parsed_args, clients.network, stack)

        if not parsed_args.disable_validations:
            errors, warnings = self._predeploy_verify_capabilities(
                stack, parameters, parsed_args)
            if errors > 0:
                self.log.error(
                    "Configuration has %d errors, fix them before "
                    "proceeding. Ignoring these errors is likely to lead to "
                    "a failed deploy.",
                    errors)
                if parsed_args.validation_warnings_fatal or \
                        parsed_args.validation_errors_fatal:
                    raise exceptions.InvalidConfiguration()
            if warnings > 0:
                self.log.error(
                    "Configuration has %d warnings, fix them before "
                    "proceeding.",
                    warnings)
                if parsed_args.validation_warnings_fatal:
                    raise exceptions.InvalidConfiguration()
            else:
                self.log.info("SUCCESS: No warnings or errors in deploy "
                              "configuration, proceeding.")

        stack_create = stack is None
        if stack_create:
            self.log.info("No stack found, will be doing a stack create")
        else:
            self.log.info("Stack found, will be doing a stack update")

        if parsed_args.rhel_reg:
            if parsed_args.reg_method == 'satellite':
                sat_required_args = (parsed_args.reg_org and
                                     parsed_args.reg_sat_url and
                                     parsed_args.reg_activation_key)
                if not sat_required_args:
                    raise exceptions.DeploymentError(
                        "ERROR: In order to use satellite registration, "
                        "you must specify --reg-org, --reg-sat-url, and "
                        "--reg-activation-key.")
            else:
                portal_required_args = (parsed_args.reg_org and
                                        parsed_args.reg_activation_key)
                if not portal_required_args:
                    raise exceptions.DeploymentError(
                        "ERROR: In order to use portal registration, you "
                        "must specify --reg-org, and "
                        "--reg-activation-key.")

        if parsed_args.dry_run:
            print("Validation Finished")
            return

        self._deploy_tripleo_heat_templates_tmpdir(stack, parsed_args)

        # Get a new copy of the stack after stack update/create. If it was
        # a create then the previous stack object would be None.
        stack = utils.get_stack(orchestration_client, parsed_args.stack)

        if parsed_args.update_plan_only:
            # If we are only updating the plan, then we either wont have a
            # stack yet or there wont be any changes and the following code
            # wont do anything.
            return

        # Force fetching of attributes
        stack.get()

        overcloudrcs = deployment.overcloudrc(
            clients.workflow_engine, container=stack.stack_name,
            no_proxy=parsed_args.no_proxy)

        utils.write_overcloudrc(stack.stack_name, overcloudrcs)
        utils.create_tempest_deployer_input()

        # Run postconfig on create or force. Use force to makes sure endpoints
        # are created with deploy reruns and upgrades
        if (stack_create or parsed_args.force_postconfig
                and not parsed_args.skip_postconfig):
            self._deploy_postconfig(stack, parsed_args)

        overcloud_endpoint = utils.get_overcloud_endpoint(stack)
        print("Overcloud Endpoint: {0}".format(overcloud_endpoint))
        print("Overcloud Deployed")
