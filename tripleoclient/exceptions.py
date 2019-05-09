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


class Base(Exception):
    """Base TripleO exception."""


class Timeout(Base):
    """An operation timed out"""


class WorkflowServiceError(Base):
    """The service type is unknown"""


class WebSocketTimeout(Base):
    """Timed out waiting for messages on the websocket"""


class WebSocketConnectionClosed(Base):
    """Websocket connection is closed before wait for messages"""


class NotFound(Base):
    """Resource not found"""


class LookupError(Base):
    """Lookup Error"""


class DeploymentError(Base):
    """Deployment failed"""


class PlanEnvWorkflowError(Base):
    """Plan Environment workflow has failed"""


class StackInProgress(Base):
    """Unable to deploy as the stack is busy"""


class RootUserExecution(Base):
    """Command was executed by a root user"""


class InvalidConfiguration(Base, ValueError):
    """Invalid parameters were specified for the deployment"""


class IntrospectionError(Base):
    """Introspection failed"""


class RegisterOrUpdateError(WorkflowServiceError):
    """Introspection failed"""


class NodeProvideError(WorkflowServiceError):
    """Node Provide failed."""


class NodeConfigurationError(WorkflowServiceError):
    """Node Configuration failed."""


class StateTransitionFailed(Base):
    """Ironic node state transition failed"""


class ProfileMatchingError(Base):
    """Failed to validate or assign node profiles"""


class PlanCreationError(Base):
    """Plan creation failed"""


class PlanExportError(Base):
    """Plan export failed"""


class WorkflowActionError(Base):
    """Workflow action failed"""
    msg_format = "Action {} execution failed: {}"

    def __init__(self, action='', output=''):
        message = self.msg_format.format(action, output)
        super(WorkflowActionError, self).__init__(message)


class DownloadError(Base):
    """Download attempt failed"""


class LogFetchError(Base):
    """Fetching logs failed"""


class ContainerDeleteFailed(Base):
    """Container deletion failed"""


class UndercloudUpgradeNotConfirmed(Base):
    """Undercloud upgrade security question not confirmed."""
