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

FROM envoyproxy/envoy-build-ubuntu:f94a38f62220a2b017878b790b6ea98a0f6c5f9c AS builder

WORKDIR /home/admin/dev

COPY .bazelrc .bazelversion BUILD.bazel WORKSPACE ./
COPY bazel ./bazel
COPY trustflow_envoy ./trustflow_envoy
COPY build.sh ./build.sh

RUN bash build.sh

FROM ubuntu:22.04

COPY --from=builder /home/admin/dev/bazel-bin/envoy.stripped /home/trustflow_envoy/envoy

WORKDIR /home/trustflow_envoy/
