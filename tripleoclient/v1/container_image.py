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

import logging

from osc_lib.command import command
from osc_lib.i18n import _

from tripleo_common.image import image_uploader


class UploadImage(command.Command):
    """Push overcloud container images to registries."""
    log = logging.getLogger(__name__ + ".UploadImage")

    def get_parser(self, prog_name):
        parser = super(UploadImage, self).get_parser(prog_name)
        parser.add_argument(
            "--config-file",
            dest="config_files",
            metavar='<yaml config file>',
            default=[],
            action="append",
            help=_("YAML config file specifying the image build. May be "
                   "specified multiple times. Order is preserved, and later "
                   "files will override some options in previous files. "
                   "Other options will append."),
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)" % parsed_args)
        uploader = image_uploader.ImageUploadManager(
            parsed_args.config_files)
        uploader.upload()
