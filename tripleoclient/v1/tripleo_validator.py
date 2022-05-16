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
import logging
from tripleoclient import constants

from validations_libs.cli.community import CommunityValidationInit
from validations_libs.cli.history import GetHistory
from validations_libs.cli.history import ListHistory
from validations_libs.cli.lister import ValidationList
from validations_libs.cli.run import Run
from validations_libs.cli.show import Show
from validations_libs.cli.show import ShowGroup
from validations_libs.cli.show import ShowParameter


LOG = logging.getLogger(__name__)


class TripleOValidatorList(ValidationList):
    """List the available validations"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(TripleOValidatorList, self).get_parser(parser)
        return parser


class TripleOValidatorShow(Show):
    """Display detailed information about a Validation"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(TripleOValidatorShow, self).get_parser(parser)
        return parser


class TripleOValidatorGroupInfo(ShowGroup):
    """Display detailed information about a Group"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(TripleOValidatorGroupInfo, self).get_parser(parser)
        return parser


class TripleOValidatorShowParameter(ShowParameter):
    """Display Validations Parameters"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(TripleOValidatorShowParameter, self).get_parser(parser)
        return parser


class TripleOValidatorRun(Run):
    """Run the available validations"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(TripleOValidatorRun, self).get_parser(parser)
        default = {'validation_log_dir': constants.VALIDATIONS_LOG_BASEDIR}
        parser.set_defaults(**default)
        return parser


class TripleOValidatorCommunityInit(CommunityValidationInit):
    """Create the paths and infrastructure to create a community validation"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(
            TripleOValidatorCommunityInit, self).get_parser(parser)
        return parser


class TripleOValidatorShowHistory(ListHistory):
    """Display Validations execution history"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(TripleOValidatorShowHistory, self).get_parser(parser)
        default = {'validation_log_dir': constants.VALIDATIONS_LOG_BASEDIR}
        parser.set_defaults(**default)
        return parser


class TripleOValidatorShowRun(GetHistory):
    """Display details about a Validation execution"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(TripleOValidatorShowRun, self).get_parser(parser)
        default = {'validation_log_dir': constants.VALIDATIONS_LOG_BASEDIR}
        parser.set_defaults(**default)
        return parser
