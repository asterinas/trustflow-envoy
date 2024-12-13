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
export PATH=/opt/llvm/bin:$PATH
export ASAN_SYMBOLIZER_PATH=/opt/llvm/bin/llvm-symbolizer

export CC=clang
export CXX=clang++

bazel --output_base=target build -c opt --verbose_failures=true //:envoy.stripped --repository_cache=/tmp/bazel_repo_cache