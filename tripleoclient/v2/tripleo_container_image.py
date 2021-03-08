#   Copyright 2020 Red Hat, Inc.
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

import collections
import logging
import os
import re
import sys
import uuid
import yaml

import six

from osc_lib.i18n import _

from tripleo_common.exception import NotFound
from tripleo_common.image.builder import buildah

from tripleoclient import command
from tripleoclient import utils


BASE_PATH = os.path.join(
    sys.prefix, "share", "tripleo-common", "container-images"
)
# NOTE(cloudnull): This will ensure functionality even when running in a venv.
if sys.prefix != "/usr" and not os.path.isdir(BASE_PATH):
    BASE_PATH = os.path.join(
        "/usr", "share", "tripleo-common", "container-images"
    )
DEFAULT_AUTHFILE = "{}/containers/auth.json".format(
    os.environ.get("XDG_RUNTIME_DIR", os.path.expanduser("~"))
)
DEFAULT_ENV_AUTHFILE = os.environ.get("REGISTRY_AUTH_FILE", DEFAULT_AUTHFILE)
DEFAULT_CONFIG = "tripleo_containers.yaml"
DEFAULT_TCIB_CONFIG_BASE = "tcib"
SUPPORTED_RHEL_MODULES = ['container-tools', 'mariadb', 'redis', 'virt']


class Build(command.Command):
    """Build tripleo container images with tripleo-ansible."""

    auth_required = False
    log = logging.getLogger(__name__ + ".Build")
    identified_images = list()
    image_parents = collections.OrderedDict()
    image_paths = dict()

    def get_parser(self, prog_name):
        parser = super(Build, self).get_parser(prog_name)
        parser.add_argument(
            "--authfile",
            dest="authfile",
            metavar="<authfile>",
            default=DEFAULT_ENV_AUTHFILE,
            help=_(
                "Path of the authentication file. Use REGISTRY_AUTH_FILE "
                "environment variable to override. (default: %(default)s)"
            ),
        )
        parser.add_argument(
            "--base",
            dest="base",
            metavar="<base-image>",
            default="ubi8",
            help=_(
                "Base image name, with optional version. Can be 'centos:8', "
                "base name image will be 'centos' but 'centos:8' will be "
                "pulled to build the base image. (default: %(default)s)"
            ),
        )
        parser.add_argument(
            "--config-file",
            dest="config_file",
            metavar="<config-file>",
            default=DEFAULT_CONFIG,
            help=_(
                "YAML config file specifying the images to build. "
                "(default: %(default)s)"
            ),
        )
        parser.add_argument(
            "--config-path",
            dest="config_path",
            metavar="<config-path>",
            default=BASE_PATH,
            help=_(
                "Base configuration path. This is the base path for all "
                "container-image files. The defined containers must reside "
                "within a 'tcib' folder that is in this path.  If this option "
                "is set, the default path for <config-file> will be modified. "
                "(default: %(default)s)"
            ),
        )
        parser.add_argument(
            "--distro",
            dest="distro",
            default="centos",
            metavar="<distro>",
            help=_(
                "Distro name, if undefined the system will build using the "
                "host distro. (default: %(default)s)"
            ),
        )
        parser.add_argument(
            "--exclude",
            dest="excludes",
            metavar="<container-name>",
            default=[],
            action="append",
            help=_(
                "Name of one container to match against the list of "
                "containers to be built to skip. Should be specified "
                "multiple times when skipping multiple containers. "
                "(default: %(default)s)"
            ),
        )
        parser.add_argument(
            "--extra-config",
            dest="extra_config",
            metavar="<extra-config>",
            help=_(
                "Apply additional options from a given configuration YAML "
                "file. This will apply to all containers built. "
                "(default: %(default)s)"
            ),
        )
        parser.add_argument(
            "--namespace",
            dest="namespace",
            metavar="<registry-namespace>",
            default="tripleou",
            help=_("Container registry namespace (default: %(default)s)"),
        )
        parser.add_argument(
            "--registry",
            dest="registry",
            metavar="<registry-url>",
            default="localhost",
            help=_("Container registry URL (default: %(default)s)"),
        )
        parser.add_argument(
            "--skip-build",
            dest="skip_build",
            default=False,
            action="store_true",
            help=_(
                "Skip or not the build of the images (default: %(default)s)"
            ),
        )
        parser.add_argument(
            "--tag",
            dest="tag",
            metavar="<image-tag>",
            default="latest",
            help=_("Image tag (default: %(default)s)"),
        )
        parser.add_argument(
            "--prefix",
            dest="prefix",
            metavar="<image-prefix>",
            default="openstack",
            help=_("Image prefix. (default: %(default)s)"),
        )
        parser.add_argument(
            "--push",
            dest="push",
            default=False,
            action="store_true",
            help=_(
                "Enable image push to a given registry. "
                "(default: %(default)s)"
            ),
        )
        parser.add_argument(
            "--label",
            dest="labels",
            metavar="<label-data>",
            default=[],
            action="append",
            help=_(
                "Add labels to the containers. This option can be "
                "specified multiple times. Each label is a key=value "
                "pair."
            ),
        )
        parser.add_argument(
            "--volume",
            dest="volumes",
            metavar="<volume-path>",
            default=[
                "/etc/yum.repos.d:/etc/distro.repos.d:z",
                "/etc/pki/rpm-gpg:/etc/pki/rpm-gpg:z",
            ],
            action="append",
            help=_(
                "Container bind mount used when building the image. Should "
                "be specified multiple times if multiple volumes."
                "(default: %(default)s)"
            ),
        )
        parser.add_argument(
            "--work-dir",
            dest="work_dir",
            metavar="<work-directory>",
            default="/tmp/container-builds",
            help=_(
                "TripleO container builds directory, storing configs and "
                "logs for each image and its dependencies. "
                "(default: %(default)s)"
            ),
        )
        parser.add_argument(
            "--rhel-modules",
            dest="rhel_modules",
            metavar="<rhel-modules>",
            default=None,
            help=_("A comma separated list of RHEL modules to enable with "
                   "their version. Example: 'mariadb:10.3,virt:8.3'."),
        )
        return parser

    def imagename_to_regex(self, imagename):
        if not imagename:
            return
        # remove any namespace from the start
        imagename = imagename.split("/")[-1]

        # remove any tag from the end
        imagename = imagename.split(":")[0]

        # remove supported base names from the start
        imagename = re.sub(r"^(openstack|centos|rhel|ubi8)-", "", imagename)

        # remove install_type from the start
        imagename = re.sub(r"^(binary|source|rdo|rhos)-", "", imagename)

        # what results should be acceptable as a regex to build one image
        return imagename

    def build_tree(self, path, tree=""):
        content = []
        path = os.path.join(path, tree)

        (cur_path, children, _) = next(os.walk(path))
        for child in children:
            val = self.build_tree(cur_path, child)
            if val:
                content.append(val)

        if content:
            if tree:
                return {tree: content}
            else:
                return content

        return tree

    def index_images(self, path):
        for root, __, files in os.walk(path):
            if [i for i in files if i.endswith(("yaml", "yml"))]:
                self.identified_images.append(os.path.basename(root))

    def find_image(self, name, path, base_image):
        """Find an image and load its config.

        This will traverse a directory structure looking for an image
        directory, when found all configs will be loaded lexically and
        returned a single Dictionary.

        :param name: Container name.
        :type name: String.
        :param path: Directory path to traverse.
        :type path: String.
        :param base: Name of base container image.
        :type base: String.
        :returns: Dictionary
        """

        container_vars = dict()
        for root, dirs, files in os.walk(path):
            if os.path.basename(root) == name:
                for file_name in sorted(files):
                    if file_name.endswith(("yaml", "yml")):
                        _option_file = os.path.join(root, file_name)
                        self.log.debug(
                            "reading option file: {}".format(_option_file)
                        )
                        with open(_option_file) as f:
                            _options = yaml.safe_load(f)
                        if _options:
                            container_vars.update(_options)

                        base_dir = root
                        while base_dir != os.sep:
                            base_dir = os.path.dirname(base_dir)
                            base_files = [
                                i
                                for i in os.listdir(base_dir)
                                if i.endswith(("yaml", "yml"))
                            ]
                            if base_files:
                                self.image_parents[name] = os.path.basename(
                                    base_dir
                                )
                                break
                        else:
                            self.image_parents[name] = base_image
        else:
            return container_vars

    def rectify_excludes(self, images_to_prepare):
        """Build a dynamic exclude list.

        Using the identified images, we check against our expected images
        to build a dynamic exclusion list which will extend the user provided
        excludes.

        :param images_to_prepare: List of expected images.
        :type images_to_prepare: List.
        :returns: List
        """

        excludes = list()
        for image in self.identified_images:
            if image not in images_to_prepare:
                excludes.append(image)
        else:
            return excludes

    def make_dir_tree(self, tree, work_dir):
        """Walk the tree then create and catalog all directories.

        As the tree is walked, containers are identified, directories are
        created and the Containerfile image relationship is recorded for later
        lookup.

        :param tree: List of expected images.
        :type tree: List.
        :param work_dir: Work directory path.
        :type work_dir: String.
        """

        if isinstance(tree, list):
            for item in tree:
                self.make_dir_tree(tree=item, work_dir=work_dir)
        elif isinstance(tree, dict):
            for key, value in tree.items():
                self.image_paths[key] = os.path.join(work_dir, key)
                utils.makedirs(dir_path=self.image_paths[key])
                self.make_dir_tree(tree=value, work_dir=self.image_paths[key])
        elif isinstance(tree, six.string_types):
            self.image_paths[tree] = os.path.join(work_dir, tree)
            utils.makedirs(dir_path=self.image_paths[tree])

    def process_images(self, expected_images, parsed_args, image_configs):
        """Process all of expected images and ensure we have valid config.

        :param expected_images: List of expected images.
        :type expected_images: List.
        :param parsed_args: Parsed arguments.
        :type parsed_args: Object.
        :param image_configs: Hash of pre-processed images.
        :type image_configs: Dict.
        :returns List:
        """

        image_configs = collections.OrderedDict()
        config_path_base = os.path.basename(
            os.path.abspath(parsed_args.config_path))
        for image in expected_images:
            if (image != config_path_base and image not in image_configs):
                self.log.debug("processing image configs".format(image))
                image_config = self.find_image(
                    image,
                    self.tcib_config_path,
                    parsed_args.base
                )
                if not image_config:
                    self.log.error(
                        "Image processing failure: {}".format(image)
                    )
                    raise RuntimeError(
                        "Container image specified, but no"
                        " config was provided. Image: {}".format(image)
                    )
                image_configs[image] = image_config

        return image_configs

    def take_action(self, parsed_args):
        self.config_file = os.path.expanduser(parsed_args.config_file)
        self.config_path = os.path.expanduser(parsed_args.config_path)
        authfile = os.path.expanduser(parsed_args.authfile)
        if os.path.exists(authfile):
            os.environ["REGISTRY_AUTH_FILE"] = authfile
        else:
            try:
                del os.environ["REGISTRY_AUTH_FILE"]
            except KeyError:
                pass
        self.tcib_config_path = os.path.join(
            self.config_path, DEFAULT_TCIB_CONFIG_BASE
        )

        if not os.path.isdir(self.tcib_config_path):
            raise IOError(
                "Configuration directory {} was not found.".format(
                    self.tcib_config_path
                )
            )

        if not os.path.isfile(self.config_file):
            self.config_file = os.path.join(
                os.path.dirname(self.tcib_config_path),
                parsed_args.config_file,
            )

        self.log.debug("take_action({})".format(parsed_args))
        excludes = parsed_args.excludes
        images_to_prepare = list()

        # Generate an unique work directory so we can keep configs and logs
        # each time we run the command; they'll be stored in work_dir.
        work_dir = os.path.join(parsed_args.work_dir, str(uuid.uuid4()))

        # Build a tree of images which have a config; this tree will allow
        # to concurrently build images which share a common base.
        if not os.path.isdir(self.tcib_config_path):
            raise NotFound(
                "The path {path} does not exist".format(
                    path=self.tcib_config_path
                )
            )
        images_tree = self.build_tree(path=self.tcib_config_path)

        tree_file = "{tree_file}".format(
            tree_file=os.path.join(work_dir, "build-tree.yaml")
        )
        utils.makedirs(os.path.dirname(tree_file))
        with open(tree_file, "w") as f:
            yaml.safe_dump(
                images_tree, f, default_flow_style=False, width=4096
            )

        self.index_images(path=self.tcib_config_path)
        self.make_dir_tree(tree=images_tree, work_dir=work_dir)

        # Make sure the unique work directory exists
        if not os.path.exists(work_dir):
            self.log.debug(
                "Creating container builds workspace in: {}".format(work_dir)
            )
            os.makedirs(work_dir)

        if os.path.isfile(self.config_file):
            self.log.info(
                "Configuration file found: {}".format(self.config_file)
            )
            with open(self.config_file, "r") as f:
                containers_yaml = yaml.safe_load(f)

            for c in containers_yaml["container_images"]:
                entry = dict(c)
                if not entry.get("image_source", "") == "tripleo":
                    continue
                image = self.imagename_to_regex(entry.get("imagename"))
                if image and image not in excludes:
                    images_to_prepare.append(image)
        else:
            self.log.warning(
                "Configuration file not found: {}".format(self.config_file)
            )
            self.log.warning(
                "All identified images will be prepared: {}".format(
                    self.config_file
                )
            )
            images_to_prepare.extend(self.identified_images)

        # NOTE(cloudnull): Ensure all dependent images are in the build
        #                  tree. Once an image has been added to the
        #                  prepare array, we walk it back and ensure
        #                  dependencies are also part of the build
        #                  process.
        image_configs = collections.OrderedDict()  # hash
        image_configs.update(
            self.process_images(
                expected_images=images_to_prepare,
                parsed_args=parsed_args,
                image_configs=image_configs
            )
        )
        _parents = self.process_images(
            expected_images=list(self.image_parents.values()),
            parsed_args=parsed_args,
            image_configs=image_configs
        )
        for key, value in _parents.items():
            image_configs[key] = value
            image_configs.move_to_end(key, last=False)
            images_to_prepare.insert(0, key)

        if "os" in image_configs:  # Second image prepared if found
            image_configs.move_to_end("os", last=False)

        if "base" in image_configs:  # First image prepared if found
            image_configs.move_to_end("base", last=False)

        self.log.debug(
            "Images being prepared: {}".format(
                [i[0] for i in [(k, v) for k, v in image_configs.items()]]
            )
        )

        tcib_inventory = {"all": {"hosts": {}}}
        tcib_inventory_hosts = tcib_inventory["all"]["hosts"]
        for image, image_config in [(k, v) for k, v in image_configs.items()]:
            self.log.debug("processing image config {}".format(image))
            if image == "base":
                image_name = image_from = parsed_args.base
            else:
                image_name = self.image_parents.get(image, image)
                image_from = (
                    "{registry}/{namespace}"
                    "/{prefix}-{image}:{tag}".format(
                        registry=parsed_args.registry,
                        namespace=parsed_args.namespace,
                        prefix=parsed_args.prefix,
                        image=image_name,
                        tag=parsed_args.tag,
                    )
                )

            image_parsed_name = self.imagename_to_regex(imagename=image)

            # For each image we will generate Dockerfiles in the work_dir
            # following a specific directory structured per image
            image_config.update(
                {
                    "workdir": self.image_paths.get(image, work_dir),
                    "tcib_distro": parsed_args.distro,
                    "tcib_path": self.image_paths.get(image, work_dir),
                    "tcib_meta": {"name": image_parsed_name},
                    "ansible_connection": "local",
                }
            )

            if parsed_args.rhel_modules:
                rhel_modules = {}
                for module in parsed_args.rhel_modules.split(','):
                    try:
                        name, version = module.split(':', 1)
                    except Exception:
                        raise ValueError('Wrong format for --rhel-modules, '
                                         'must be a comma separated list of '
                                         '<module>:<version>')
                    if name not in SUPPORTED_RHEL_MODULES:
                        raise ValueError('{} is not part of supported modules'
                                         ' {}'.format(name,
                                                      SUPPORTED_RHEL_MODULES))
                    rhel_modules.update({name: version})
                image_config['tcib_rhel_modules'] = rhel_modules

            if parsed_args.labels:
                _desc = "OpenStack Platform {}".format(image_parsed_name)
                label_data = image_config['tcib_labels'] = {
                    "tcib_managed": True,
                    "maintainer": "OpenStack TripleO Team",
                    "description": _desc,
                    "summary": _desc,
                    "io.k8s.display-name": _desc,
                }
                for item in parsed_args.labels:
                    key, value = item.split("=", 1)
                    label_data[key] = value % dict(
                        registry=parsed_args.registry,
                        namespace=parsed_args.namespace,
                        prefix=parsed_args.prefix,
                        image=image_name,
                        tag=parsed_args.tag,
                        name=image_parsed_name,
                    )

            # NOTE(cloudnull): Check if the reference config has a valid
            #                  "from" option. If the reference "from"
            #                  option is valid, it will be used.
            image_config["tcib_from"] = image_config.get(
                "tcib_from", image_from
            )

            tcib_inventory_hosts[image_parsed_name] = image_config

            var_file = "{image_name}.yaml".format(
                image_name=os.path.join(
                    image_config["tcib_path"], image_parsed_name,
                )
            )
            utils.makedirs(os.path.dirname(var_file))
            with open(var_file, "w") as f:
                yaml.safe_dump(
                    image_config, f, default_flow_style=False, width=4096
                )

        with utils.TempDirs() as tmp:
            playbook = os.path.join(tmp, "tripleo-multi-playbook.yaml")
            playdata = [
                {
                    "name": "Generate localhost facts",
                    "connection": "local",
                    "hosts": "localhost",
                    "gather_facts": True,
                }
            ]
            generation_playbook = {
                "name": "Generate container file(s)",
                "connection": "local",
                "hosts": "all",
                "gather_facts": False,
                "roles": [{"role": "tripleo_container_image_build"}],
            }
            if parsed_args.extra_config:
                if not os.path.exists(parsed_args.extra_config):
                    raise IOError(
                        "The file provided by <options-apply> does not "
                        "exist, check you settings and try again."
                    )
                else:
                    with open(parsed_args.extra_config) as f:
                        generation_playbook["vars"] = yaml.safe_load(f)

            playdata.append(generation_playbook)

            with open(playbook, "w") as f:
                yaml.safe_dump(
                    playdata, f, default_flow_style=False, width=4096
                )

            utils.run_ansible_playbook(
                playbook=playbook,
                inventory=tcib_inventory,
                workdir=tmp,
                playbook_dir=tmp,
                extra_env_variables={
                    "ANSIBLE_FORKS": len(tcib_inventory_hosts.keys())
                },
                verbosity=utils.playbook_verbosity(self=self),
            )

        # Ensure anything not intended to be built is excluded
        excludes.extend(self.rectify_excludes(images_to_prepare))
        self.log.info("Images being excluded: {}".format(excludes))

        if not parsed_args.skip_build:
            bb = buildah.BuildahBuilder(
                work_dir=work_dir,
                deps=images_tree,
                base=parsed_args.prefix,
                img_type=False,
                tag=parsed_args.tag,
                namespace=parsed_args.namespace,
                registry_address=parsed_args.registry,
                push_containers=parsed_args.push,
                volumes=parsed_args.volumes,
                excludes=list(set(excludes)),
            )
            try:
                bb.build_all()
            except SystemError as exp:
                self.log.error(
                    "Buildah failed with the following error: {}".format(exp)
                )
                raise SystemError(exp)


class HotFix(command.Command):
    """Hotfix tripleo container images with tripleo-ansible."""

    def get_parser(self, prog_name):
        parser = super(HotFix, self).get_parser(prog_name)
        parser.add_argument(
            "--image",
            dest="images",
            metavar="<images>",
            default=[],
            action="append",
            required=True,
            help=_(
                "Fully qualified reference to the source image to be "
                "modified. Can be specified multiple times (one per "
                "image) (default: %(default)s)."
            ),
        )
        parser.add_argument(
            "--rpms-path",
            dest="rpms_path",
            metavar="<rpms-path>",
            required=True,
            help=_("Path containing RPMs to install (default: %(default)s)."),
        )
        parser.add_argument(
            "--tag",
            dest="tag",
            metavar="<image-tag>",
            default="latest",
            help=_("Image hotfix tag (default: %(default)s)"),
        )
        return parser

    def take_action(self, parsed_args):
        with utils.TempDirs() as tmp:
            tasks = list()
            for image in parsed_args.images:
                tasks.append(
                    {
                        "name": "include ansible-role-tripleo-modify-image",
                        "import_role": {"name": "tripleo-modify-image"},
                        "vars": {
                            "container_build_tool": "buildah",
                            "tasks_from": "rpm_install.yml",
                            "source_image": image,
                            "rpms_path": parsed_args.rpms_path,
                            "modified_append_tag": "-{}".format(
                                parsed_args.tag
                            ),
                            "modify_dir_path": tmp,
                        },
                    }
                )

            playbook = os.path.join(tmp, "tripleo-hotfix-playbook.yaml")
            playdata = {
                "name": "Generate hotfixs",
                "connection": "local",
                "hosts": "localhost",
                "gather_facts": False,
                "tasks": tasks,
            }

            with open(playbook, "w") as f:
                yaml.safe_dump(
                    [playdata], f, default_flow_style=False, width=4096
                )

            utils.run_ansible_playbook(
                playbook=playbook,
                inventory="localhost",
                workdir=tmp,
                playbook_dir=tmp,
                verbosity=utils.playbook_verbosity(self=self),
            )
