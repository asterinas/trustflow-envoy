# Copyright 2024 Ant Group Co., Ltd.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This module contains build rules for project dependencies.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def trustflow_envoy_dependencies():
    _com_github_envoy()
    _com_github_sf_apis()
    _com_github_cppcodec()

def _com_github_envoy():
    maybe(
        http_archive,
        name = "envoy",
        urls = [
            "https://github.com/envoyproxy/envoy/archive/8a5d7b0241b419854a4dd1c16c382a9784cdca4a.tar.gz",
        ],
        strip_prefix = "envoy-8a5d7b0241b419854a4dd1c16c382a9784cdca4a",
        sha256 = "179665429e2e4dc81889e77c7dad9e7d444e8bd89b1ad38227bff4bc3ce3db12",
    )

def _com_github_sf_apis():
    maybe(
        http_archive,
        name = "sf_apis",
        urls = [
            "https://github.com/secretflow/secure-data-capsule-apis/archive/47a47f0f0096fdcc2c13c8ba3b86448d2795b829.tar.gz",
        ],
        strip_prefix = "secure-data-capsule-apis-47a47f0f0096fdcc2c13c8ba3b86448d2795b829",
        build_file = "@trustflow_envoy//bazel:sf_apis.BUILD",
        sha256 = "c7b52eb51be3b4f1f380b8fb7cdd80a101e59e9471ca01d7b6c3441bd463dc3b",
    )

def _com_github_cppcodec():
    maybe(
        http_archive,
        name = "cppcodec",
        build_file = "@trustflow_envoy//bazel:cppcodec.BUILD",
        urls = [
            "https://github.com/tplgy/cppcodec/archive/refs/tags/v0.2.tar.gz",
        ],
        strip_prefix = "cppcodec-0.2",
        sha256 = "0edaea2a9d9709d456aa99a1c3e17812ed130f9ef2b5c2d152c230a5cbc5c482",
        patches = ["@trustflow_envoy//bazel:patches/cppcodec.patch"],
        patch_args = ["-p1"],
    )
