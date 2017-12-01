# Copyright 2017 Red Hat Inc.
#
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

import json
import logging
import netaddr
import netifaces
import os
import subprocess
import sys

from oslo_utils import netutils
import psutil

from oslo_config import cfg


class FailedValidation(Exception):
    pass

CONF = cfg.CONF

# We need 8 GB, leave a little room for variation in what 8 GB means on
# different platforms.
REQUIRED_MB = 7680
PASSWORD_PATH = os.path.expanduser('~/undercloud-passwords.conf')
LOG = logging.getLogger(__name__ + ".UndercloudSetup")


def _run_command(args, env=None, name=None):
    """Run the command defined by args and return its output

    :param args: List of arguments for the command to be run.
    :param env: Dict defining the environment variables. Pass None to use
        the current environment.
    :param name: User-friendly name for the command being run. A value of
        None will cause args[0] to be used.
    """
    if name is None:
        name = args[0]
    try:
        return subprocess.check_output(args,
                                       stderr=subprocess.STDOUT,
                                       env=env).decode('utf-8')
    except subprocess.CalledProcessError as e:
        LOG.error('%s failed: %s', name, e.output)
        raise


def _run_live_command(args, env=None, name=None):
    """Run the command defined by args and log its output

    Takes the same arguments as _run_command, but runs the process
    asynchronously so the output can be logged while the process is still
    running.
    """
    if name is None:
        name = args[0]
    process = subprocess.Popen(args, env=env,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    while True:
        line = process.stdout.readline().decode('utf-8')
        if line:
            LOG.info(line.rstrip())
        if line == '' and process.poll() is not None:
            break
    if process.returncode != 0:
        raise RuntimeError('%s failed. See log for details.' % name)


def _check_hostname():
    """Check system hostname configuration

    Rabbit and Puppet require pretty specific hostname configuration. This
    function ensures that the system hostname settings are valid before
    continuing with the installation.
    """
    if CONF.undercloud_hostname is not None:
        args = ['sudo', 'hostnamectl', 'set-hostname',
                CONF.undercloud_hostname]
        _run_command(args, name='hostnamectl')

    LOG.info('Checking for a FQDN hostname...')
    args = ['sudo', 'hostnamectl', '--static']
    detected_static_hostname = _run_command(args, name='hostnamectl').rstrip()
    LOG.info('Static hostname detected as %s', detected_static_hostname)
    args = ['sudo', 'hostnamectl', '--transient']
    detected_transient_hostname = _run_command(args,
                                               name='hostnamectl').rstrip()
    LOG.info('Transient hostname detected as %s', detected_transient_hostname)
    if detected_static_hostname != detected_transient_hostname:
        LOG.error('Static hostname "%s" does not match transient hostname '
                  '"%s".', detected_static_hostname,
                  detected_transient_hostname)
        LOG.error('Use hostnamectl to set matching hostnames.')
        raise RuntimeError('Static and transient hostnames do not match')
    with open('/etc/hosts') as hosts_file:
        for line in hosts_file:
            if (not line.lstrip().startswith('#') and
                    detected_static_hostname in line.split()):
                break
        else:
            short_hostname = detected_static_hostname.split('.')[0]
            if short_hostname == detected_static_hostname:
                raise RuntimeError('Configured hostname is not fully '
                                   'qualified.')
            sed_cmd = ('sed -i "s/127.0.0.1\(\s*\)/127.0.0.1\\1%s %s /" '
                       '/etc/hosts' %
                       (detected_static_hostname, short_hostname))
            args = ['sudo', '/bin/bash', '-c', sed_cmd]
            _run_command(args, name='hostname-to-etc-hosts')
            LOG.info('Added hostname %s to /etc/hosts',
                     detected_static_hostname)


def _check_memory():
    """Check system memory

    The undercloud will not run properly in less than 8 GB of memory.
    This function verifies that at least that much is available before
    proceeding with install.
    """
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    total_mb = (mem.total + swap.total) / 1024 / 1024
    if total_mb < REQUIRED_MB:
        LOG.error('At least %d MB of memory is required for undercloud '
                  'installation.  A minimum of 8 GB is recommended. '
                  'Only detected %d MB' % (REQUIRED_MB, total_mb))
        raise RuntimeError('Insufficient memory available')


def _check_ipv6_enabled():
    """Test if IPv6 is enabled

    If /proc/net/if_inet6 exist ipv6 sysctl settings are available.
    """
    return os.path.isfile('/proc/net/if_inet6')


def _wrap_ipv6(ip):
    """Wrap a IP address in square brackets if IPv6

    """
    if netutils.is_valid_ipv6(ip):
        return "[%s]" % ip
    return ip


def _check_sysctl():
    """Check sysctl option availability

    The undercloud will not install properly if some of the expected sysctl
    values are not available to be set.
    """
    options = ['net.ipv4.ip_forward', 'net.ipv4.ip_nonlocal_bind']
    if _check_ipv6_enabled():
        options.append('net.ipv6.ip_nonlocal_bind')

    not_available = []
    for option in options:
        path = '/proc/sys/{opt}'.format(opt=option.replace('.', '/'))
        if not os.path.isfile(path):
            not_available.append(option)

    if not_available:
        LOG.error('Required sysctl options are not available. Check '
                  'that your kernel is up to date. Missing: {options}'
                  ' '.format(options=", ".join(not_available)))
        raise RuntimeError('Missing sysctl options')


def _validate_ips():
    def is_ip(value, param_name):
        try:
            netaddr.IPAddress(value)
        except netaddr.core.AddrFormatError:
            msg = '%s "%s" must be a valid IP address' % \
                  (param_name, value)
            raise FailedValidation(msg)
    for ip in CONF['undercloud_nameservers']:
        is_ip(ip, 'undercloud_nameservers')


def _validate_value_formats():
    """Validate format of some values

    Certain values have a specific format that must be maintained in order to
    work properly.  For example, local_ip must be in CIDR form, and the
    hostname must be a FQDN.
    """
    try:
        local_ip = netaddr.IPNetwork(CONF['local_ip'])
        if local_ip.prefixlen == 32:
            raise netaddr.AddrFormatError('Invalid netmask')
        # If IPv6 the ctlplane network uses the EUI-64 address format,
        # which requires the prefix to be /64
        if local_ip.version == 6 and local_ip.prefixlen != 64:
            raise netaddr.AddrFormatError('Prefix must be 64 for IPv6')
    except netaddr.core.AddrFormatError as e:
        message = ('local_ip "%s" not valid: "%s" '
                   'Value must be in CIDR format.' %
                   (CONF['local_ip'], str(e)))
        raise FailedValidation(message)
    hostname = CONF['undercloud_hostname']
    if hostname is not None and '.' not in hostname:
        message = 'Hostname "%s" is not fully qualified.' % hostname
        raise FailedValidation(message)


def _validate_in_cidr():
    cidr = netaddr.IPNetwork(CONF['network_cidr'])

    def validate_addr_in_cidr(addr, pretty_name=None, require_ip=True):
        try:
            if netaddr.IPAddress(addr) not in cidr:
                message = ('Config option %s "%s" not in defined CIDR "%s"' %
                           (pretty_name, addr, cidr))
                raise FailedValidation(message)
        except netaddr.core.AddrFormatError:
            if require_ip:
                message = 'Invalid IP address: %s' % addr
                raise FailedValidation(message)

    just_local_ip = CONF['local_ip'].split('/')[0]
    # What is this about?  They have invalidated the configuration
    # specification here..  - imain
    #
    # undercloud.conf uses inspection_iprange, the configuration wizard
    # tool passes the values separately.
    # if 'inspection_iprange' in CONF:
    # inspection_iprange = CONF['inspection_iprange'].split(',')
    # CONF['inspection_start'] = inspection_iprange[0]
    # CONF['inspection_end'] = inspection_iprange[1]
    validate_addr_in_cidr(just_local_ip, 'local_ip')
    validate_addr_in_cidr(CONF['network_gateway'], 'network_gateway')
    # NOTE(bnemec): The ui needs to be externally accessible, which means in
    # many cases we can't have the public vip on the provisioning network.
    # In that case users are on their own to ensure they've picked valid
    # values for the VIP hosts.
    if ((CONF['undercloud_service_certificate'] or
            CONF['generate_service_certificate']) and
            not CONF['enable_ui']):
        validate_addr_in_cidr(CONF['undercloud_public_host'],
                              'undercloud_public_host',
                              require_ip=False)
        validate_addr_in_cidr(CONF['undercloud_admin_host'],
                              'undercloud_admin_host',
                              require_ip=False)
    validate_addr_in_cidr(CONF['dhcp_start'], 'dhcp_start')
    validate_addr_in_cidr(CONF['dhcp_end'], 'dhcp_end')
    # validate_addr_in_cidr(CONF, 'inspection_start', 'Inspection range start')
    # validate_addr_in_cidr(CONF, 'inspection_end', 'Inspection range end')


def _validate_dhcp_range():
    dhcp_start = netaddr.IPAddress(CONF['dhcp_start'])
    dhcp_end = netaddr.IPAddress(CONF['dhcp_end'])
    if dhcp_start >= dhcp_end:
        message = ('Invalid dhcp range specified, dhcp_start "%s" does '
                   'not come before dhcp_end "%s"' %
                   (dhcp_start, dhcp_end))
        raise FailedValidation(message)


def _validate_inspection_range():
    inspection_start = netaddr.IPAddress(CONF['inspection_start'])
    inspection_end = netaddr.IPAddress(CONF['inspection_end'])
    if inspection_start >= inspection_end:
        message = ('Invalid inspection range specified, inspection_start '
                   '"%s" does not come before inspection_end "%s"' %
                   (inspection_start, inspection_end))
        raise FailedValidation(message)


def _validate_no_overlap():
    """Validate the provisioning and inspection ip ranges do not overlap"""
    dhcp_set = netaddr.IPSet(netaddr.IPRange(CONF['dhcp_start'],
                                             CONF['dhcp_end']))
    inspection_set = netaddr.IPSet(netaddr.IPRange(CONF['inspection_start'],
                                                   CONF['inspection_end']))
    # If there is any intersection of the two sets then we have a problem
    if dhcp_set & inspection_set:
        message = ('Inspection DHCP range "%s-%s" overlaps provisioning '
                   'DHCP range "%s-%s".' %
                   (CONF['inspection_start'], CONF['inspection_end'],
                    CONF['dhcp_start'], CONF['dhcp_end']))
        raise FailedValidation(message)


def _validate_interface_exists():
    """Validate the provided local interface exists"""
    local_interface = CONF['local_interface']
    net_override = CONF['net_config_override']
    if not net_override and local_interface not in netifaces.interfaces():
        message = ('Invalid local_interface specified. %s is not available.' %
                   local_interface)
        raise FailedValidation(message)


def _validate_no_ip_change():
    """Disallow provisioning interface IP changes

    Changing the provisioning network IP causes a number of issues, so we
    need to disallow it early in the install before configurations start to
    be changed.
    """
    os_net_config_file = '/etc/os-net-config/config.json'
    # Nothing to do if we haven't already installed
    if not os.path.isfile(
            os.path.expanduser(os_net_config_file)):
        return
    with open(os_net_config_file) as f:
        network_config = json.loads(f.read())
    try:
        ctlplane = [i for i in network_config.get('network_config', [])
                    if i['name'] == 'br-ctlplane'][0]
    except IndexError:
        # Nothing to check if br-ctlplane wasn't configured
        return
    existing_ip = ctlplane['addresses'][0]['ip_netmask']
    if existing_ip != CONF.local_ip:
        message = ('Changing the local_ip is not allowed.  Existing IP: '
                   '%s, Configured IP: %s') % (existing_ip,
                                               CONF.network_cidr)
        LOG.error(message)
        raise FailedValidation(message)


def _validate_passwords_file():
    """Disallow updates if the passwords file is missing

    If the undercloud was already deployed, the passwords file needs to be
    present so passwords that can't be changed are persisted.  If the file
    is missing it will break the undercloud, so we should fail-fast and let
    the user know about the problem.
    """
    if (os.path.isfile(os.path.expanduser('~/stackrc')) and
            not os.path.isfile(PASSWORD_PATH)):
        message = ('The %s file is missing.  This will cause all service '
                   'passwords to change and break the existing undercloud. ' %
                   PASSWORD_PATH)
        raise FailedValidation(message)


def _run_yum_clean_all(instack_env):
    args = ['sudo', 'yum', 'clean', 'all']
    LOG.info('Running yum clean all')
    _run_live_command(args, instack_env, 'yum-clean-all')
    LOG.info('yum-clean-all completed successfully')


def _run_yum_update(instack_env):
    args = ['sudo', 'yum', 'update', '-y']
    LOG.info('Running yum update')
    _run_live_command(args, instack_env, 'yum-update')
    LOG.info('yum-update completed successfully')


def check():

    # data = {opt.name: CONF[opt.name] for opt in _opts}
    try:
        # Other validations
        _check_hostname()
        _check_memory()
        _check_sysctl()
        _validate_passwords_file()
        # Networking validations
        _validate_value_formats()
        _validate_in_cidr()
        _validate_dhcp_range()
        # _validate_inspection_range()
        # _validate_no_overlap()
        _validate_ips()
        _validate_interface_exists()
        _validate_no_ip_change()
    except KeyError as e:
        LOG.error('Key error in configuration: {error}\n'
                  'Value is missing in configuration.'.format(error=e))
        sys.exit(1)
    except FailedValidation as e:
        LOG.error('An error occurred during configuration '
                  'validation, please check your host '
                  'configuration and try again.\nError '
                  'message: {error}'.format(error=e))
        sys.exit(1)
    except RuntimeError as e:
        LOG.error('An error occurred during configuration '
                  'validation, please check your host '
                  'configuration and try again. Error '
                  'message: {error}'.format(error=e))
        sys.exit(1)
