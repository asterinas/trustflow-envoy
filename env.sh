#!/bin/bash
#
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
#

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
image=envoyproxy/envoy-build-ubuntu:f94a38f62220a2b017878b790b6ea98a0f6c5f9c
DOCKER=docker
project=envoy-filter
if [[ $1 == 'enter' ]]; then
    $DOCKER exec -it ${project}-build-ubuntu-$(whoami) bash
else
    $DOCKER run --name ${project}-build-ubuntu-$(whoami) -td \
        --network=host \
        -v $DIR:$DIR \
        -v ${HOME}/${USER}-${project}-bazel-cache-test:/root/.cache/bazel \
        -w $DIR \
        -e ENVOY_SRCDIR=envoy \
        --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
        --cap-add=NET_RAW \
        --cap-add=NET_ADMIN \
        --privileged=true \
        ${image} 
fi
