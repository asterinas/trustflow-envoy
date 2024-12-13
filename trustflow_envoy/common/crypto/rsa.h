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

class RsaEncryptor {
 public:
  explicit RsaEncryptor(Openssl::UniquePkey&& pk) : pk_(std::move(pk)) {}

  absl::StatusOr<std::vector<uint8_t>> Encrypt(
      absl::Span<const uint8_t> plaintext);

 private:
  // public key
  const Openssl::UniquePkey pk_;
};

class RsaDecryptor {
 public:
  explicit RsaDecryptor(Openssl::UniquePkey&& sk) : sk_(std::move(sk)) {}

  absl::StatusOr<std::vector<uint8_t>> Decrypt(
      absl::Span<const uint8_t> ciphertext);

 private:
  // private key
  const Openssl::UniquePkey sk_;
};

}  // namespace Crypto
}  // namespace Common
}  // namespace Envoy