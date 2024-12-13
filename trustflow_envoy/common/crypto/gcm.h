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

#include "absl/status/status.h"
#include "absl/types/span.h"

namespace Envoy {
namespace Common {
namespace Crypto {

class GcmCrypto {
 public:
  GcmCrypto(absl::Span<const uint8_t> key, absl::Span<const uint8_t> iv)
      : key_(key.begin(), key.end()), iv_(iv.begin(), iv.end()) {}

  // Encrypts `plaintext` into `ciphertext`.
  // For aes-128, mac size shall be 16 fixed size.
  absl::Status Encrypt(absl::Span<const uint8_t> plaintext,
                       absl::Span<const uint8_t> aad,
                       absl::Span<uint8_t> ciphertext,
                       absl::Span<uint8_t> mac) const;

  // Decrypts `ciphertext` into `plaintext`.
  absl::Status Decrypt(absl::Span<const uint8_t> ciphertext,
                       absl::Span<const uint8_t> aad,
                       absl::Span<const uint8_t> mac,
                       absl::Span<uint8_t> plaintext) const;

 private:
  const std::vector<uint8_t> key_;  // Symmetric key
  const std::vector<uint8_t> iv_;   // Initialize vector
};

}  // namespace Crypto
}  // namespace Common
}  // namespace Envoy