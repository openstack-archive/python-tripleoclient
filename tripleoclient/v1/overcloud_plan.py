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

import json
import logging

from cliff import lister


class ListPlans(lister.Lister):
    """List overcloud deployment plans"""

    log = logging.getLogger(__name__ + ".ListPlans")

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)

        workflow_client = self.app.client_manager.workflow_engine
        execution = workflow_client.action_executions.create(
            'tripleo.list_plans')

        try:
            json_results = json.loads(execution.output)['result']
        except Exception:
            self.log.exception("Error parsing JSON %s", execution.output)
            json_results = []

        result = []
        for r in json_results:
            result.append((r,))

        return (("Plan Name",), result)
