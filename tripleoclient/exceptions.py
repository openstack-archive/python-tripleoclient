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


class ConfigDownloadInProgress(Base):
    """Unable to deploy as config download already in progress"""

    msg_format = ("Config download already in progress with "
                  "execution id {} for stack {}")

    def __init__(self, execution_id='', stack=''):
        message = self.msg_format.format(execution_id, stack)
        super(ConfigDownloadInProgress, self).__init__(message)


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


class OvercloudUpdateNotConfirmed(Base):
    """Overcloud Update security question not confirmed."""


class OvercloudUpgradeNotConfirmed(Base):
    """Overcloud Update security question not confirmed."""


class CellExportError(Base):
    """Cell export failed"""


class BannedParameters(Base):
    """Some of the environment parameters provided should be removed"""
