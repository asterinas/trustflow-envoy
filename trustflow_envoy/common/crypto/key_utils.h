// Copyright 2024 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include "absl/status/statusor.h"
#include "absl/types/span.h"
#include "trustflow_envoy/common/crypto/openssl_wrapper.h"

namespace Envoy {
namespace Common {
namespace Crypto {

absl::StatusOr<std::string> LoadBufFromFile(const std::string& file_path);

absl::StatusOr<Openssl::UniquePkey> LoadPriKeyFromBuf(
    absl::Span<const uint8_t> buf);

absl::StatusOr<Openssl::UniquePkey> LoadPriKeyFromFile(
    const std::string& file_path);

absl::StatusOr<Openssl::UniquePkey> LoadPubKeyFromBuf(
    absl::Span<const uint8_t> buf);

absl::StatusOr<Openssl::UniquePkey> LoadPubKeyFromFile(
    const std::string& file_path);

absl::StatusOr<Openssl::UniquePkey> LoadX509CertPubKeyFromBuf(
    absl::Span<const uint8_t> buf);

absl::StatusOr<Openssl::UniquePkey> LoadX509CertPubKeyFromFile(
    const std::string& file_path);

}  // namespace Crypto
}  // namespace Common
}  // namespace Envoy