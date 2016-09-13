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
    pass


class NotFound(Exception):
    """Resource not found"""


class DeploymentError(RuntimeError):
    """Deployment failed"""


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


class PasswordFileNotFound(Exception):
    """Password file for the Heat stack not found in the current working dir"""


class RootDeviceDetectionError(Exception):
    """Failed to detect the root device"""


class PlanCreationError(Exception):
    """Plan creation failed"""
