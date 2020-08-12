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


import json
import logging
import os
import re
import sys
import yaml

from osc_lib.i18n import _

from tripleo_common import constants as tripleo_common_constants
from tripleoclient import constants
from tripleoclient import utils as oooutils


LOG = logging.getLogger(__name__ + ".utils")


def export_passwords(swift, stack, excludes=True):
    # Export the passwords from swift
    obj = 'plan-environment.yaml'
    container = stack
    try:
        resp_headers, content = swift.get_object(container, obj)
    except Exception as e:
        LOG.error("An error happened while exporting the password "
                  "file from swift: %s", str(e))
        sys.exit(1)

    data = yaml.load(content)
    # The "passwords" key in plan-environment.yaml are generated passwords,
    # they are not necessarily the actual password values used during the
    # deployment.
    generated_passwords = data["passwords"]
    # parameter_defaults will contain any user defined password values
    parameters = data["parameter_defaults"]

    passwords = {}

    # For each password, check if it's excluded, then check if there's a user
    # defined value from parameter_defaults, and if not use the value from the
    # generated passwords.
    def exclude_password(password):
        for pattern in constants.EXPORT_PASSWORD_EXCLUDE_PATTERNS:
            return re.match(pattern, password, re.I)

    for password in tripleo_common_constants.PASSWORD_PARAMETER_NAMES:
        if exclude_password(password):
            continue
        if password in parameters:
            passwords[password] = parameters[password]
        elif password in generated_passwords:
            passwords[password] = generated_passwords[password]
        else:
            LOG.warning("No password value found for %s", password)

    return passwords


def export_stack(heat, stack, should_filter=False,
                 config_download_dir='/var/lib/mistral/overcloud'):

    # data to export
    # parameter: Parameter to be exported
    # file:   IF file specified it is taken as source instead of heat
    #         output.File is relative to <config-download-dir>/stack.
    # filter: in case only specific settings should be
    #         exported from parameter data.
    export_data = {
        "EndpointMap": {
            "parameter": "EndpointMapOverride",
        },
        "HostsEntry": {
            "parameter": "ExtraHostFileEntries",
        },
        "GlobalConfig": {
            "parameter": "GlobalConfigExtraMapData",
        },
        "AllNodesConfig": {
            "file": "group_vars/overcloud.json",
            "parameter": "AllNodesExtraMapData",
            "filter": ["oslo_messaging_notify_short_bootstrap_node_name",
                       "oslo_messaging_notify_node_names",
                       "oslo_messaging_rpc_node_names",
                       "memcached_node_ips",
                       "ovn_dbs_vip",
                       "redis_vip"]},
    }

    data = {}
    heat_stack = oooutils.get_stack(heat, stack)

    for export_key, export_param in export_data.items():
        param = export_param["parameter"]
        if "file" in export_param:
            # get file data
            file = os.path.join(config_download_dir,
                                export_param["file"])
            with open(file, 'r') as ff:
                try:
                    export_data = json.load(ff)
                except Exception as e:
                    LOG.error(
                        _('Could not read file %s') % file)
                    LOG.error(e)

        else:
            # get stack data
            export_data = oooutils.get_stack_output_item(
                            heat_stack, export_key)

        if export_data:
            # When we export information from a cell controller stack
            # we don't want to filter.
            if "filter" in export_param and should_filter:
                for filter_key in export_param["filter"]:
                    if filter_key in export_data:
                        element = {filter_key: export_data[filter_key]}
                        data.setdefault(param, {}).update(element)
            else:
                data[param] = export_data

        else:
            raise Exception(
                "No data returned to export %s from." % param)

    return data
