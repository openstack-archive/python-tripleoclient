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


class DeprecatedTripleOValidatorList(TripleOValidatorList):
    """[DEPRECATED]: List the available validations.

    Please use "validation list --help" instead.
    """

    log = logging.getLogger('deprecated')

    def take_action(self, parsed_args):
        self.log.warning(
            'This command has been deprecated. '
            'Please use "validation list" instead.'
        )
        return super(
            DeprecatedTripleOValidatorList, self
        ).take_action(parsed_args)


class TripleOValidatorShow(Show):
    """Display detailed information about a Validation"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(TripleOValidatorShow, self).get_parser(parser)
        return parser


class DeprecatedTripleOValidatorShow(TripleOValidatorShow):
    """[DEPRECATED]: Display detailed information about a Validation.

    Please use "validation show --help" instead.
    """

    log = logging.getLogger('deprecated')

    def take_action(self, parsed_args):
        self.log.warning(
            'This command has been deprecated. '
            'Please use "validation show" instead.'
        )
        return super(
            DeprecatedTripleOValidatorShow, self
        ).take_action(parsed_args)


class TripleOValidatorGroupInfo(ShowGroup):
    """Display detailed information about a Group"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(TripleOValidatorGroupInfo, self).get_parser(parser)
        return parser


class DeprecatedTripleOValidatorGroupInfo(TripleOValidatorGroupInfo):
    """[DEPRECATED]: Display detailed information about a Group.

    Please use "validation show group --help" instead.
    """

    log = logging.getLogger('deprecated')

    def take_action(self, parsed_args):
        self.log.warning(
            'This command has been deprecated. '
            'Please use "validation show group" instead.'
        )
        return super(
            DeprecatedTripleOValidatorGroupInfo, self
        ).take_action(parsed_args)


class TripleOValidatorShowParameter(ShowParameter):
    """Display Validations Parameters"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(TripleOValidatorShowParameter, self).get_parser(parser)
        return parser


class DeprecatedTripleOValidatorShowParameter(TripleOValidatorShowParameter):
    """[DEPRECATED]: Display Validations Parameters.

    Please use "validation show parameter --help" instead.
    """

    log = logging.getLogger('deprecated')

    def take_action(self, parsed_args):
        self.log.warning(
            'This command has been deprecated. '
            'Please use "validation show parameter" instead.'
        )
        return super(
            DeprecatedTripleOValidatorShowParameter, self
        ).take_action(parsed_args)


class TripleOValidatorRun(Run):
    """Run the available validations"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(TripleOValidatorRun, self).get_parser(parser)
        default = {'validation_log_dir': constants.VALIDATIONS_LOG_BASEDIR}
        parser.set_defaults(**default)
        return parser


class DeprecatedTripleOValidatorRun(TripleOValidatorRun):
    """[DEPRECATED]: Run the available validations.

    Please use "validation run --help" instead.
    """

    log = logging.getLogger('deprecated')

    def take_action(self, parsed_args):
        self.log.warning(
            'This command has been deprecated. '
            'Please use "validation run" instead.'
        )
        return super(
            DeprecatedTripleOValidatorRun, self
        ).take_action(parsed_args)


class TripleOValidatorShowHistory(ListHistory):
    """Display Validations execution history"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(TripleOValidatorShowHistory, self).get_parser(parser)
        default = {'validation_log_dir': constants.VALIDATIONS_LOG_BASEDIR}
        parser.set_defaults(**default)
        return parser


class DeprecatedTripleOValidatorShowHistory(TripleOValidatorShowHistory):
    """[DEPRECATED]: Display Validations execution history.

    Please use "validation history list --help" instead.
    """

    log = logging.getLogger('deprecated')

    def take_action(self, parsed_args):
        self.log.warning(
            'This command has been deprecated. '
            'Please use "validation history list" instead.'
        )
        return super(
            DeprecatedTripleOValidatorShowHistory, self
        ).take_action(parsed_args)


class TripleOValidatorShowRun(GetHistory):
    """Display details about a Validation execution"""

    auth_required = False

    def get_parser(self, parser):
        parser = super(TripleOValidatorShowRun, self).get_parser(parser)
        default = {'validation_log_dir': constants.VALIDATIONS_LOG_BASEDIR}
        parser.set_defaults(**default)
        return parser


class DeprecatedTripleOValidatorShowRun(TripleOValidatorShowRun):
    """[DEPRECATED]: Display details about a Validation execution.

    Please use "validation history get --help" instead.
    """

    log = logging.getLogger('deprecated')

    def take_action(self, parsed_args):
        self.log.warning(
            'This command has been deprecated. '
            'Please use "validation history get" instead.'
        )
        return super(
            DeprecatedTripleOValidatorShowRun, self
        ).take_action(parsed_args)
