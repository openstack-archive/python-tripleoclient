#   Copyright 2016 Red Hat, Inc.
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

import mock
import sys

from tripleoclient.tests import fakes
from tripleoclient.tests.v1.overcloud_deploy import fakes as deploy_fakes
from tripleoclient.v2 import tripleo_container_image as tcib


IMAGE_YAML = """---
container_images:
  - image_source: "tripleo"
    imagename: "test/keystone:tag"
"""

MOCK_WALK = [
    ("", ["base"], [],),
    ("/base", ["memcached", "openstack"], ["config.yaml", "test.doc"],),
    ("/base/memcached", [], ["memcached.yaml"],),
    ("/base/openstack", ["glance", "keystone", "neutron", "nova"], [],),
    (
        "/base/openstack/glance",
        [],
        ["glance-registry.yaml", "glance-api.yaml"],
    ),
    ("/base/openstack/keystone", [], ["keystone.yaml"],),
    ("/base/openstack/neutron", ["api"], [],),
    ("/base/openstack/neutron/api", [], ["neutron-api.yml"],),
    ("/base/openstack/nova", [], [],),
]

if sys.version_info >= (3, 0):
    MOCK_OPEN_PATH = "builtins.open"
else:
    MOCK_OPEN_PATH = "tripleoclient.v2.tripleo_container_image.open"


class TestContainerImages(deploy_fakes.TestDeployOvercloud):
    def setUp(self):
        super(TestContainerImages, self).setUp()
        self.app = fakes.FakeApp()
        self.os_walk = mock.patch(
            "os.walk", autospec=True, return_value=iter(MOCK_WALK)
        )
        self.os_walk.start()
        self.addCleanup(self.os_walk.stop)
        self.os_listdir = mock.patch(
            "os.listdir", autospec=True, return_value=["config.yaml"]
        )
        self.os_listdir.start()
        self.addCleanup(self.os_listdir.stop)
        self.run_ansible_playbook = mock.patch(
            "tripleoclient.utils.run_ansible_playbook", autospec=True
        )
        self.run_ansible_playbook.start()
        self.addCleanup(self.run_ansible_playbook.stop)
        self.buildah_build_all = mock.patch(
            "tripleo_common.image.builder.buildah.BuildahBuilder.build_all",
            autospec=True,
        )
        self.mock_buildah = self.buildah_build_all.start()
        self.addCleanup(self.buildah_build_all.stop)
        self.cmd = tcib.Build(self.app, None)

    def _take_action(self, parsed_args):
        self.cmd.image_parents = {"keystone": "base"}
        mock_open = mock.mock_open(read_data=IMAGE_YAML)
        with mock.patch("os.path.isfile", autospec=True) as mock_isfile:
            mock_isfile.return_value = True
            with mock.patch("os.path.isdir", autospec=True) as mock_isdir:
                mock_isdir.return_value = True
                with mock.patch(MOCK_OPEN_PATH, mock_open):
                    with mock.patch(
                        "tripleoclient.v2.tripleo_container_image.Build"
                        ".find_image",
                        autospec=True,
                    ) as mock_find_image:
                        mock_find_image.return_value = {"tcib_option": "data"}
                        self.cmd.take_action(parsed_args)

    def test_find_image(self):
        mock_open = mock.mock_open(read_data='---\ntcib_option: "data"')
        with mock.patch(MOCK_OPEN_PATH, mock_open):
            image = self.cmd.find_image("keystone", "some/path", "base-image")
        self.assertEqual(image, {"tcib_option": "data"})

    def test_build_tree(self):
        image = self.cmd.build_tree("some/path")
        self.assertEqual(
            image,
            [
                {
                    "base": [
                        "memcached",
                        {
                            "openstack": [
                                "glance",
                                "keystone",
                                {"neutron": ["api"]},
                                "nova",
                            ]
                        },
                    ]
                }
            ],
        )

    def test_image_regex(self):
        image = self.cmd.imagename_to_regex("test/centos-binary-keystone:tag")
        self.assertEqual(image, "keystone")
        image = self.cmd.imagename_to_regex("test/rhel-binary-keystone:tag")
        self.assertEqual(image, "keystone")
        image = self.cmd.imagename_to_regex("test/rhel-source-keystone:tag")
        self.assertEqual(image, "keystone")
        image = self.cmd.imagename_to_regex("test/rhel-rdo-keystone:tag")
        self.assertEqual(image, "keystone")
        image = self.cmd.imagename_to_regex("test/rhel-rhos-keystone:tag")
        self.assertEqual(image, "keystone")
        image = self.cmd.imagename_to_regex("test/other-keystone:tag")
        self.assertEqual(image, "other-keystone")

    def test_rectify_excludes(self):
        self.cmd.identified_images = ["keystone", "nova", "glance"]
        excludes = self.cmd.rectify_excludes(images_to_prepare=["glance"])
        self.assertEqual(excludes, ["keystone", "nova"])

    def test_image_build_yaml(self):
        arglist = ["--config-file", "config.yaml"]
        verifylist = [("config_file", "config.yaml")]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self._take_action(parsed_args=parsed_args)

        assert self.mock_buildah.called

    def test_image_build_with_skip_build(self):
        arglist = ["--config-file", "config.yaml", "--skip-build"]
        verifylist = [("config_file", "config.yaml"), ("skip_build", True)]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self._take_action(parsed_args=parsed_args)

        assert not self.mock_buildah.called

    def test_image_build_with_push(self):
        arglist = ["--config-file", "config.yaml", "--push"]
        verifylist = [("config_file", "config.yaml"), ("push", True)]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self._take_action(parsed_args=parsed_args)

        assert self.mock_buildah.called

    def test_image_build_with_volume(self):
        arglist = ["--config-file", "config.yaml", "--volume", "bind/mount"]
        verifylist = [
            ("config_file", "config.yaml"),
            (
                "volumes",
                [
                    "/etc/yum.repos.d:/etc/distro.repos.d:z",
                    "/etc/pki/rpm-gpg:/etc/pki/rpm-gpg:z",
                    "bind/mount",
                ],
            ),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self._take_action(parsed_args=parsed_args)

        assert self.mock_buildah.called

    def test_image_build_with_exclude(self):
        arglist = ["--exclude", "image1"]
        verifylist = [
            ("excludes", ["image1"]),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self._take_action(parsed_args=parsed_args)

        assert self.mock_buildah.called

    def test_image_build_failure_no_config_file(self):
        arglist = ["--config-file", "not-a-file-config.yaml"]
        verifylist = [
            ("config_file", "not-a-file-config.yaml"),
        ]

        self.check_parser(self.cmd, arglist, verifylist)

    def test_image_build_config_dir(self):
        arglist = ["--config-file", "config.yaml", "--config-path", "/foo"]
        verifylist = [("config_file", "config.yaml"), ("config_path", "/foo")]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self._take_action(parsed_args=parsed_args)
        self.assertEqual(self.cmd.tcib_config_path, '/foo/tcib')

    def test_image_build_failure_no_config_dir(self):
        arglist = ["--config-path", "not-a-path"]
        verifylist = [
            ("config_path", "not-a-path"),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        with mock.patch("os.path.isfile", autospec=True) as mock_isfile:
            mock_isfile.return_value = True
            self.assertRaises(IOError, self.cmd.take_action, parsed_args)

    def test_process_images(self):
        rtn_value = {'yay': 'values'}
        arglist = ["--config-path", "foobar/"]
        verifylist = [
            ("config_path", "foobar/"),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        expected_images = ['foo', 'foobar']
        image_configs = {}
        self.cmd.tcib_config_path = '/foo/tcib'
        with mock.patch("tripleoclient.v2.tripleo_container_image.Build"
                        ".find_image", autospec=True) as mock_find_image:

            mock_find_image.return_value = rtn_value
            cfgs = self.cmd.process_images(expected_images, parsed_args,
                                           image_configs)
            mock_find_image.assert_called_once_with(self.cmd, 'foo',
                                                    '/foo/tcib', 'ubi8')
        self.assertEqual(cfgs, {'foo': rtn_value})


class TestContainerImagesHotfix(deploy_fakes.TestDeployOvercloud):
    def setUp(self):
        super(TestContainerImagesHotfix, self).setUp()
        self.run_ansible_playbook = mock.patch(
            "tripleoclient.utils.run_ansible_playbook", autospec=True
        )
        self.run_ansible_playbook.start()
        self.addCleanup(self.run_ansible_playbook.stop)
        self.cmd = tcib.HotFix(self.app, None)

    def _take_action(self, parsed_args):
        with mock.patch("os.path.isfile", autospec=True) as mock_isfile:
            mock_isfile.return_value = True
            self.cmd.take_action(parsed_args)

    def test_image_hotfix(self):
        arglist = ["--image", "container1", "--rpms-path", "/opt"]
        verifylist = [
            ("images", ["container1"]),
            ("rpms_path", "/opt"),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self._take_action(parsed_args=parsed_args)

    def test_image_hotfix_multi_image(self):
        arglist = [
            "--image",
            "container1",
            "--image",
            "container2",
            "--rpms-path",
            "/opt",
        ]
        verifylist = [
            ("images", ["container1", "container2"]),
            ("rpms_path", "/opt"),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        self._take_action(parsed_args=parsed_args)

    def test_image_hotfix_missing_args(self):
        arglist = []
        verifylist = []

        self.assertRaises(
            deploy_fakes.fakes.utils.ParserException,
            self.check_parser,
            self.cmd,
            arglist,
            verifylist,
        )
