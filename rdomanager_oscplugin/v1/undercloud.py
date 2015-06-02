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

"""Plugin action implementation"""

import logging

from cliff import command
from instack_undercloud import undercloud


class InstallPlugin(command.Command):
    """Install and setup the undercloud"""

    auth_required = False
    log = logging.getLogger(__name__ + ".InstallPlugin")

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        # TODO(trown): Make the location of the instack root dir configurable
        undercloud.install('.')

        return
