#   Copyright 2018 Red Hat, Inc.
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
from oslo_config import cfg
from oslo_log import log as logging

from tripleoclient import constants
from tripleoclient.exceptions import UndercloudUpgradeNotConfirmed
from tripleoclient import utils
from tripleoclient.v1.tripleo_deploy import Deploy

CONF = cfg.CONF
logging.register_options(CONF)
logging.setup(CONF, '')


class Upgrade(Deploy):
    """Upgrade TripleO"""

    log = logging.getLogger(__name__ + ".Upgrade")

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        if (not parsed_args.yes
                and not utils.prompt_user_for_confirmation(
                    constants.UPGRADE_PROMPT, self.log)):
            raise UndercloudUpgradeNotConfirmed(constants.UPGRADE_NO)

        parsed_args.standalone = True
        parsed_args.upgrade = True
        super(Upgrade, self).take_action(parsed_args)
