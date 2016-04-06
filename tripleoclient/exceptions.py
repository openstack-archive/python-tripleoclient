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


class UnsupportedVersion(Exception):
    """The user is trying to use an unsupported version of the API"""
    pass


class Timeout(Exception):
    """An operation timed out"""
    pass


class UnknownService(Exception):
    """The service type is unknown"""
    pass


class NotFound(Exception):
    """Resource not found"""
    pass


class DeploymentError(RuntimeError):
    """Deployment failed"""
    pass


class RootUserExecution(Exception):
    """Command was executed by a root user"""


class InvalidConfiguration(ValueError):
    """Invalid parameters were specified for the deployment"""
    pass


class IntrospectionError(RuntimeError):
    """Introspection failed"""


class StateTransitionFailed(Exception):
    """Ironic node state transition failed"""


class ProfileMatchingError(Exception):
    """Failed to validate or assign node profiles"""


class PasswordFileNotFound(Exception):
    """Password file for the Heat stack not found in the current working dir"""


class RootDeviceDetectionError(Exception):
    """Failed to detect the root device"""
