#   Copyright 2013 Nebula Inc.
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

"""Exception definitions"""


class Timeout(Exception):
    """An operation timed out"""


class WorkflowServiceError(Exception):
    """The service type is unknown"""


class WebSocketTimeout(Exception):
    """Timed out waiting for messages on the websocket"""


class NotFound(Exception):
    """Resource not found"""


class DeploymentError(RuntimeError):
    """Deployment failed"""


class PlanEnvWorkflowError(RuntimeError):
    """Plan Environment workflow has failed"""


class StackInProgress(RuntimeError):
    """Unable to deploy as the stack is busy"""


class RootUserExecution(Exception):
    """Command was executed by a root user"""


class InvalidConfiguration(ValueError):
    """Invalid parameters were specified for the deployment"""


class IntrospectionError(RuntimeError):
    """Introspection failed"""


class RegisterOrUpdateError(WorkflowServiceError):
    """Introspection failed"""


class NodeProvideError(WorkflowServiceError):
    """Node Provide failed."""


class NodeConfigurationError(WorkflowServiceError):
    """Node Configuration failed."""


class StateTransitionFailed(Exception):
    """Ironic node state transition failed"""


class ProfileMatchingError(Exception):
    """Failed to validate or assign node profiles"""


class PlanCreationError(Exception):
    """Plan creation failed"""


class PlanExportError(Exception):
    """Plan export failed"""


class WorkflowActionError(Exception):
    """Workflow action failed"""
    msg_format = "Action {} execution failed: {}"

    def __init__(self, action='', output=''):
        message = self.msg_format.format(action, output)
        super(WorkflowActionError, self).__init__(message)


class DownloadError(Exception):
    """Download attempt failed"""


class LogFetchError(Exception):
    """Fetching logs failed"""


class ContainerDeleteFailed(Exception):
    """Container deletion failed"""
