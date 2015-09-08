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


def generate_overcloud_passwords_mock():
    passwords = (
        "OVERCLOUD_ADMIN_PASSWORD",
        "OVERCLOUD_ADMIN_TOKEN",
        "OVERCLOUD_CEILOMETER_PASSWORD",
        "OVERCLOUD_CEILOMETER_SECRET",
        "OVERCLOUD_CINDER_PASSWORD",
        "OVERCLOUD_DEMO_PASSWORD",
        "OVERCLOUD_GLANCE_PASSWORD",
        "OVERCLOUD_HEAT_PASSWORD",
        "OVERCLOUD_HEAT_STACK_DOMAIN_PASSWORD",
        "OVERCLOUD_NEUTRON_PASSWORD",
        "OVERCLOUD_NOVA_PASSWORD",
        "OVERCLOUD_SWIFT_HASH",
        "OVERCLOUD_SWIFT_PASSWORD",
    )

    return dict((password, 'password') for password in passwords)
