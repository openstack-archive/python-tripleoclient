#   Copyright 2019 Red Hat, Inc.
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

"""Plugin action implementation"""

import json
import logging
import os
import shutil
import sys

from cryptography import x509

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from jinja2 import Environment
from jinja2 import FileSystemLoader

from osc_lib.i18n import _
from oslo_config import cfg
from tripleo_common.image import kolla_builder

from tripleoclient.config.minion import load_global_config
from tripleoclient.config.minion import MinionConfig
from tripleoclient import constants
from tripleoclient import exceptions
from tripleoclient import utils
from tripleoclient.v1 import undercloud_preflight


# Provides mappings for some of the instack_env tags to minion heat
# params or minion.conf opts known here (as a fallback), needed to maintain
# feature parity with instack net config override templates.
# TODO(bogdando): all of the needed mappings should be wired-in, eventually
# NOTE(aschultz): this is used by the custom netconfig still, even though
# the minion config is new.
INSTACK_NETCONF_MAPPING = {
    'LOCAL_INTERFACE': 'minion_local_interface',
    'LOCAL_IP': 'minion_local_ip',
    'LOCAL_MTU': 'UndercloudMinionLocalMtu',
    'PUBLIC_INTERFACE_IP': 'minion_local_ip',  # can't be 'CloudName'
    'UNDERCLOUD_NAMESERVERS': 'minion_nameservers',
    'SUBNETS_STATIC_ROUTES': 'ControlPlaneStaticRoutes',
}


PARAMETER_MAPPING = {
    'minion_debug': 'Debug',
    'minion_local_mtu': 'UndercloudMinionLocalMtu',
    'container_healthcheck_disabled': 'ContainerHealthcheckDisabled',
    'minion_local_interface': 'NeutronPublicInterface',
}

SUBNET_PARAMETER_MAPPING = {
    'cidr': 'NetworkCidr',
    'gateway': 'NetworkGateway',
    'host_routes': 'HostRoutes'
}

THT_HOME = os.environ.get('THT_HOME',
                          "/usr/share/openstack-tripleo-heat-templates/")

USER_HOME = os.environ.get('HOME', '')

CONF = cfg.CONF

# When adding new options to the lists below, make sure to regenerate the
# sample config by running "tox -e genconfig" in the project root.
ci_defaults = kolla_builder.container_images_prepare_defaults()

config = MinionConfig()

# Routed subnets
_opts = config.get_opts()
load_global_config()


LOG = logging.getLogger(__name__ + ".minion_config")


def _get_jinja_env_source(f):
    path, filename = os.path.split(f)
    env = Environment(loader=FileSystemLoader(path))
    src = env.loader.get_source(env, filename)[0]
    return (env, src)


def _process_undercloud_output(templates_dir, output_file_path):
    """copy the undercloud output file to our work dir"""
    output_file = os.path.join(constants.MINION_OUTPUT_DIR, output_file_path)
    env_file = os.path.join(templates_dir, 'tripleo-undercloud-base.yaml')
    if os.path.exists(output_file):
        src_file = output_file
    elif os.path.exists(output_file_path):
        src_file = output_file_path
    else:
        raise exceptions.DeploymentError('Cannot locate undercloud output '
                                         'file {}'.format(output_file_path))

    try:
        shutil.copy(os.path.abspath(src_file), env_file)
    except Exception:
        msg = _('Cannot copy undercloud output file %s into a '
                'tempdir!') % src_file
        LOG.error(msg)
        raise exceptions.DeploymentError(msg)
    return env_file


def _process_undercloud_passwords(src_file, dest_file):
    try:
        shutil.copy(os.path.abspath(src_file), dest_file)
    except Exception:
        msg = _('Cannot copy undercloud password file %(src)s to '
                '%(dest)s') % {'src': src_file, 'dest': dest_file}
        LOG.error(msg)
        raise exceptions.DeploymentError(msg)


def prepare_minion_deploy(upgrade=False, no_validations=False,
                          verbose_level=1, yes=False,
                          force_stack_update=False, dry_run=False):
    """Prepare Minion deploy command based on minion.conf"""

    env_data = {}
    registry_overwrites = {}
    deploy_args = []
    # Fetch configuration and use its log file param to add logging to a file
    utils.load_config(CONF, constants.MINION_CONF_PATH)
    utils.configure_logging(LOG, verbose_level, CONF['minion_log_file'])

    # NOTE(bogdando): the generated env files are stored another path then
    # picked up later.
    # NOTE(aschultz): We copy this into the tht root that we save because
    # we move any user provided environment files into this root later.
    tempdir = os.path.join(os.path.abspath(CONF['output_dir']),
                           'tripleo-config-generated-env-files')
    utils.makedirs(tempdir)

    env_data['PythonInterpreter'] = sys.executable

    env_data['ContainerImagePrepareDebug'] = CONF['minion_debug']

    for param_key, param_value in PARAMETER_MAPPING.items():
        if param_key in CONF.keys():
            env_data[param_value] = CONF[param_key]

    # Parse the minion.conf options to include necessary args and
    # yaml files for minion deploy command

    if CONF.get('minion_enable_selinux'):
        env_data['SELinuxMode'] = 'enforcing'
    else:
        env_data['SELinuxMode'] = 'permissive'

    if CONF.get('minion_ntp_servers', None):
        env_data['NtpServer'] = CONF['minion_ntp_servers']

    if CONF.get('minion_timezone', None):
        env_data['TimeZone'] = CONF['minion_timezone']
    else:
        env_data['TimeZone'] = utils.get_local_timezone()

    # TODO(aschultz): fix this logic, look it up out of undercloud-outputs.yaml
    env_data['DockerInsecureRegistryAddress'] = [
        '%s:8787' % CONF['minion_local_ip'].split('/')[0]]
    env_data['DockerInsecureRegistryAddress'].extend(
        CONF['container_insecure_registries'])

    env_data['ContainerCli'] = CONF['container_cli']

    if CONF.get('container_registry_mirror', None):
        env_data['DockerRegistryMirror'] = CONF['container_registry_mirror']

    # This parameter the IP address used to bind the local container registry
    env_data['LocalContainerRegistry'] = CONF['minion_local_ip'].split('/')[0]

    if CONF.get('minion_local_ip', None):
        deploy_args.append('--local-ip=%s' % CONF['minion_local_ip'])

    if CONF.get('templates', None):
        tht_templates = CONF['templates']
        deploy_args.append('--templates=%s' % tht_templates)
    else:
        tht_templates = THT_HOME
        deploy_args.append('--templates=%s' % THT_HOME)

    if CONF.get('roles_file', constants.MINION_ROLES_FILE):
        deploy_args.append('--roles-file=%s' % CONF['roles_file'])

    if CONF.get('networks_file'):
        deploy_args.append('--networks-file=%s' % CONF['networks_file'])
    else:
        deploy_args.append('--networks-file=%s' %
                           constants.UNDERCLOUD_NETWORKS_FILE)

    if yes:
        deploy_args += ['-y']

    # copy the undercloud output file into our working dir and include it
    output_file = _process_undercloud_output(
            tempdir, CONF['minion_undercloud_output_file'])
    deploy_args += ['-e', output_file]

    # copy undercloud password file (the configuration is minion_password_file
    # to the place that triple deploy looks for it
    # tripleo-<stack name>-passwords.yaml)
    _process_undercloud_passwords(CONF['minion_password_file'],
                                  'tripleo-minion-passwords.yaml')
    if upgrade:
        # TODO(aschultz): validate minion upgrade, should be the same as the
        # undercloud one.
        deploy_args += [
            '--upgrade',
            '-e', os.path.join(
                tht_templates,
                "environments/lifecycle/undercloud-upgrade-prepare.yaml")]

    if not CONF.get('heat_native', False):
        deploy_args.append('--heat-native=False')
    else:
        deploy_args.append('--heat-native')

    if CONF.get('heat_container_image'):
        deploy_args.append('--heat-container-image=%s'
                           % CONF['heat_container_image'])

    # These should be loaded first so we can override all the bits later
    deploy_args += [
        "-e", os.path.join(tht_templates,
                           'environments/undercloud/undercloud-minion.yaml'),
        '-e', os.path.join(tht_templates, 'environments/use-dns-for-vips.yaml')
        ]

    # TODO(aschultz): remove when podman is actual default
    deploy_args += [
        '-e', os.path.join(tht_templates, 'environments/podman.yaml')
        ]

    # If a container images file is used, copy it into the tempdir to make it
    # later into other deployment artifacts and user-provided files.
    _container_images_config(CONF, deploy_args, env_data, tempdir)

    if CONF.get('enable_heat_engine'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/heat-engine.yaml")]
    if CONF.get('enable_ironic_conductor'):
        deploy_args += ['-e', os.path.join(
            tht_templates, "environments/services/ironic-conductor.yaml")]

    if CONF.get('minion_service_certificate'):
        # We assume that the certificate is trusted
        env_data['InternalTLSCAFile'] = ''
        env_data.update(
            _get_public_tls_parameters(
                CONF.get('minion_service_certificate')))

    u = CONF.get('deployment_user') or utils.get_deployment_user()
    env_data['DeploymentUser'] = u
    # TODO(cjeanner) drop that once using oslo.privsep
    deploy_args += ['--deployment-user', u]

    deploy_args += ['--output-dir=%s' % CONF['output_dir']]
    utils.makedirs(CONF['output_dir'])

    # TODO(aschultz): move this to a central class
    if CONF.get('net_config_override', None):
        data_file = CONF['net_config_override']
        if os.path.abspath(data_file) != data_file:
            data_file = os.path.join(USER_HOME, data_file)

        if not os.path.exists(data_file):
            msg = _("Could not find net_config_override file '%s'") % data_file
            LOG.error(msg)
            raise RuntimeError(msg)

        # NOTE(bogdando): Process templated net config override data:
        # * get a list of used instack_env j2 tags (j2 vars, like {{foo}}),
        # * fetch values for the tags from the known mappins,
        # * raise, if there is unmatched tags left
        # * render the template into a JSON dict
        net_config_env, template_source = _get_jinja_env_source(data_file)

        # Create rendering context from the known to be present mappings for
        # identified instack_env tags to generated in env_data minion heat
        # params. Fall back to config opts, when env_data misses a param.
        context = {}
        for tag in INSTACK_NETCONF_MAPPING.keys():
            mapped_value = INSTACK_NETCONF_MAPPING[tag]
            if mapped_value in env_data.keys() or mapped_value in CONF.keys():
                try:
                    context[tag] = CONF[mapped_value]
                except cfg.NoSuchOptError:
                    context[tag] = env_data.get(mapped_value, None)

        # this returns a unicode string, convert it in into json
        net_config_str = net_config_env.get_template(
            os.path.split(data_file)[-1]).render(context).replace(
                "'", '"').replace('&quot;', '"')
        try:
            net_config_json = json.loads(net_config_str)
        except ValueError:
            net_config_json = json.loads("{%s}" % net_config_str)

        if 'network_config' not in net_config_json:
            msg = ('Unsupported data format in net_config_override '
                   'file %s: %s' % (data_file, net_config_str))
            LOG.error(msg)
            raise exceptions.DeploymentError(msg)

        env_data['UndercloudNetConfigOverride'] = net_config_json

    params_file = os.path.join(tempdir, 'minion_parameters.yaml')
    utils.write_env_file(env_data, params_file, registry_overwrites)
    deploy_args += ['-e', params_file]

    if CONF.get('hieradata_override', None):
        data_file = CONF['hieradata_override']
        if os.path.abspath(data_file) != data_file:
            data_file = os.path.join(USER_HOME, data_file)

        if not os.path.exists(data_file):
            msg = _("Could not find hieradata_override file '%s'") % data_file
            LOG.error(msg)
            raise RuntimeError(msg)

        deploy_args += ['--hieradata-override=%s' % data_file]

    if CONF.get('minion_hostname'):
        utils.set_hostname(CONF.get('minion_hostname'))

    if CONF.get('minion_enable_validations') and not no_validations:
        undercloud_preflight.minion_check(verbose_level, upgrade)

    if CONF.get('custom_env_files'):
        for custom_file in CONF['custom_env_files']:
            deploy_args += ['-e', custom_file]

    if verbose_level > 1:
        deploy_args.append('--debug')

    deploy_args.append('--log-file=%s' % CONF['minion_log_file'])

    # Always add a drop-in for the ephemeral minion heat stack
    # virtual state tracking (the actual file will be created later)
    stack_vstate_dropin = os.path.join(
        tht_templates, 'minion-stack-vstate-dropin.yaml')
    deploy_args += ["-e", stack_vstate_dropin]
    if force_stack_update:
        deploy_args += ["--force-stack-update"]

    roles_file = os.path.join(tht_templates, constants.MINION_ROLES_FILE)
    cmd = ["sudo", "--preserve-env", "openstack", "tripleo", "deploy",
           "--standalone", "--standalone-role", "UndercloudMinion", "--stack",
           "minion", "-r", roles_file]
    cmd += deploy_args[:]

    # In dry-run, also report the expected heat stack virtual state/action
    if dry_run:
        stack_update_mark = os.path.join(
            constants.STANDALONE_EPHEMERAL_STACK_VSTATE,
            'update_mark_minion')
        if os.path.isfile(stack_update_mark) or force_stack_update:
            LOG.warning(_('The heat stack minion virtual state/action '
                          ' would be UPDATE'))

    return cmd


def _get_public_tls_parameters(service_certificate_path):
    with open(service_certificate_path, "rb") as pem_file:
        pem_data = pem_file.read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=None,
            backend=default_backend())

        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        return {
            'SSLCertificate': cert_pem,
            'SSLKey': key_pem
        }


def _container_images_config(conf, deploy_args, env_data, tempdir):
    if conf.container_images_file:
        deploy_args += ['-e', conf.container_images_file]
        try:
            shutil.copy(os.path.abspath(conf.container_images_file), tempdir)
        except Exception:
            msg = _('Cannot copy a container images'
                    'file %s into a tempdir!') % conf.container_images_file
            LOG.error(msg)
            raise exceptions.DeploymentError(msg)
    else:
        # no images file was provided. Set a default ContainerImagePrepare
        # parameter to trigger the preparation of the required container list
        cip = kolla_builder.CONTAINER_IMAGE_PREPARE_PARAM
        env_data['ContainerImagePrepare'] = cip
