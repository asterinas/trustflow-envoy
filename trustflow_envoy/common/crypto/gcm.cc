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

#include "trustflow_envoy/common/crypto/gcm.h"

#include <memory>

#include "fmt/format.h"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "trustflow_envoy/common/crypto/openssl_wrapper.h"

namespace Envoy {
namespace Common {
namespace Crypto {

namespace {
constexpr size_t kAesMacSize = 16;
}  // namespace

absl::Status GcmCrypto::Encrypt(absl::Span<const uint8_t> plaintext,
                                absl::Span<const uint8_t> aad,
                                absl::Span<uint8_t> ciphertext,
                                absl::Span<uint8_t> mac) const {
  if (plaintext.size() != ciphertext.size()) {
    return absl::Status{
        absl::StatusCode::kInvalidArgument,
        fmt::format("plaintext's size {} != ciphertext's size {}",
                    plaintext.size(), ciphertext.size())};
  }
  if (mac.size() != kAesMacSize) {
    return absl::Status{absl::StatusCode::kInvalidArgument,
                        fmt::format("mac's size should be {}, but got {}",
                                    kAesMacSize, mac.size())};
  }

  // init openssl evp cipher context
  Openssl::UniqueCipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx == nullptr) {
    return absl::Status{absl::StatusCode::kInternal,
                        "Failed to new evp cipher context."};
  }

  // Explicit fetching const EVP_CIPHER*
  // We do not need to free this pointer.
  //
  // refer to
  // https://docs.openssl.org/master/man7/ossl-guide-libcrypto-introduction/#explicit-fetching
  // and
  // https://github.com/openssl/openssl/blob/master/test/evp_extra_test.c#L3682
  const EVP_CIPHER* evp_cipher = EVP_aes_128_gcm();

  if (key_.size() != static_cast<size_t>(EVP_CIPHER_key_length(evp_cipher))) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        fmt::format("key size should be {}, but got {}",
                    static_cast<size_t>(EVP_CIPHER_key_length(evp_cipher)),
                    key_.size()));
  }
  if (iv_.size() != static_cast<size_t>(EVP_CIPHER_iv_length(evp_cipher))) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        fmt::format("iv size should be {}, but got {}",
                    static_cast<size_t>(EVP_CIPHER_iv_length(evp_cipher)),
                    iv_.size()));
  }

  int ret = 0;
  ret = EVP_EncryptInit_ex(ctx.get(), evp_cipher, nullptr, key_.data(),
                           iv_.data());
  if (ret != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        fmt::format("EVP_EncryptInit_ex err code={}", ret));
  }

  // Provide AAD data if exist
  int out_length = 0;
  const auto aad_len = aad.size();
  if (aad_len > 0) {
    ret =
        EVP_EncryptUpdate(ctx.get(), nullptr, &out_length, aad.data(), aad_len);
    if (ret != 1) {
      return absl::Status(absl::StatusCode::kInternal,
                          fmt::format("EVP_EncryptInit_ex err code={}", ret));
    }
    if (static_cast<size_t>(out_length) != aad.size()) {
      return absl::Status(
          absl::StatusCode::kInternal,
          fmt::format(
              "Length err when update aad, out_length {} != aad length {}",
              out_length, aad.size()));
    }
  }
  ret = EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_length,
                          plaintext.data(), plaintext.size());
  if (ret != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        fmt::format("EVP_EncryptInit_ex err code={}", ret));
  }
  if (static_cast<size_t>(out_length) != plaintext.size()) {
    return absl::Status(absl::StatusCode::kInternal,
                        fmt::format("Length err when update plaintext, "
                                    "out_length {} != plaintext length {}",
                                    out_length, plaintext.size()));
  }

  // Note that get no output here as the data is always aligned for GCM.
  ret = EVP_EncryptFinal_ex(ctx.get(), nullptr, &out_length);
  if (ret != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        fmt::format("EVP_EncryptFinal_ex err code={}", ret));
  }
  ret = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kAesMacSize,
                            mac.data());
  if (ret != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        fmt::format("EVP_CIPHER_CTX_ctrl err code={}", ret));
  }

  return absl::Status{absl::StatusCode::kOk, "success"};
}

absl::Status GcmCrypto::Decrypt(absl::Span<const uint8_t> ciphertext,
                                absl::Span<const uint8_t> aad,
                                absl::Span<const uint8_t> mac,
                                absl::Span<uint8_t> plaintext) const {
  if (ciphertext.size() != plaintext.size()) {
    return absl::Status{
        absl::StatusCode::kInvalidArgument,
        fmt::format("ciphertext's size {} != plaintext's size {}",
                    ciphertext.size(), plaintext.size())};
  }
  if (mac.size() != kAesMacSize) {
    return absl::Status{absl::StatusCode::kInvalidArgument,
                        fmt::format("mac's size should be {}, but got {}",
                                    kAesMacSize, mac.size())};
  }

  // init openssl evp cipher context
  Openssl::UniqueCipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx == nullptr) {
    return absl::Status{absl::StatusCode::kInternal,
                        "Failed to new evp cipher context."};
  }

  // Explicit fetching const EVP_CIPHER*
  // We do not need to free this pointer.
  //
  // refer to
  // https://docs.openssl.org/master/man7/ossl-guide-libcrypto-introduction/#explicit-fetching
  // and
  // https://github.com/openssl/openssl/blob/master/test/evp_extra_test.c#L3682
  const EVP_CIPHER* evp_cipher = EVP_aes_128_gcm();
  if (key_.size() != static_cast<size_t>(EVP_CIPHER_key_length(evp_cipher))) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        fmt::format("key size should be {}, but got {}",
                    static_cast<size_t>(EVP_CIPHER_key_length(evp_cipher)),
                    key_.size()));
  }
  if (iv_.size() != static_cast<size_t>(EVP_CIPHER_iv_length(evp_cipher))) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        fmt::format("iv size should be {}, but got {}",
                    static_cast<size_t>(EVP_CIPHER_iv_length(evp_cipher)),
                    iv_.size()));
  }

  int ret = 0;
  ret = EVP_DecryptInit_ex(ctx.get(), evp_cipher, nullptr, key_.data(),
                           iv_.data());
  if (ret != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        fmt::format("EVP_DecryptInit_ex err code={}", ret));
  }

  // Provide AAD data if exist
  int out_length = 0;
  const auto aad_len = aad.size();
  if (aad_len > 0) {
    ret =
        EVP_DecryptUpdate(ctx.get(), nullptr, &out_length, aad.data(), aad_len);
    if (ret != 1) {
      return absl::Status(absl::StatusCode::kInternal,
                          fmt::format("EVP_DecryptUpdate err code={}", ret));
    }
    if (static_cast<size_t>(out_length) != aad.size()) {
      return absl::Status(
          absl::StatusCode::kInternal,
          fmt::format(
              "Length err when update aad, out_length {} != aad length {}",
              out_length, aad.size()));
    }
  }

  ret = EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_length,
                          ciphertext.data(), ciphertext.size());
  if (ret != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        fmt::format("EVP_DecryptUpdate err code={}", ret));
  }
  if (static_cast<size_t>(out_length) != ciphertext.size()) {
    return absl::Status(absl::StatusCode::kInternal,
                        fmt::format("Length err when update ciphertext, "
                                    "out_length {} != ciphertext length {}",
                                    out_length, ciphertext.size()));
  }

  ret = EVP_CIPHER_CTX_ctrl(
      ctx.get(), EVP_CTRL_GCM_SET_TAG, kAesMacSize,
      const_cast<void*>(reinterpret_cast<const void*>(mac.data())));
  if (ret != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        fmt::format("EVP_CIPHER_CTX_ctrl err code={}", ret));
  }

  // Note that get no output here as the data is always aligned for GCM.
  ret = EVP_DecryptFinal_ex(ctx.get(), nullptr, &out_length);
  if (ret != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        fmt::format("EVP_DecryptFinal_ex err code={}", ret));
  }

  return absl::Status{absl::StatusCode::kOk, "success"};
}

}  // namespace Crypto
}  // namespace Common
}  // namespace Envoy