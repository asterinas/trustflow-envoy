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

#include "trustflow_envoy/common/crypto/rsa.h"

namespace Envoy {
namespace Common {
namespace Crypto {

absl::StatusOr<std::vector<uint8_t>> RsaEncryptor::Encrypt(
    absl::Span<const uint8_t> plaintext) {
  auto ctx = Openssl::UniquePkeyCtx(
      EVP_PKEY_CTX_new(pk_.get(), /* engine = default */ nullptr),
      EVP_PKEY_CTX_free);
  if (ctx == nullptr) {
    return absl::Status{absl::StatusCode::kInternal,
                        "failed to create pkey context"};
  }
  int ret = 0;
  // init context
  ret = EVP_PKEY_encrypt_init(ctx.get());
  if (ret != 1) {
    return absl::Status{absl::StatusCode::kInternal,
                        "failed to init pkey context"};
  }

  // make sure to use OAEP_PADDING
  ret = EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING);
  if (ret != 1) {
    return absl::Status{absl::StatusCode::kInternal,
                        "failed to set rsa padding"};
  }

  ret = EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256());
  if (ret != 1) {
    return absl::Status{absl::StatusCode::kInternal,
                        "failed to set rsa sha256 oaep md"};
  }

  ret = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256());
  if (ret != 1) {
    return absl::Status{absl::StatusCode::kInternal,
                        "failed to set rsa sha256 mgf1 md"};
  }

  // first, get output length
  size_t outlen = 0;
  ret = EVP_PKEY_encrypt(ctx.get(), /* empty input */ nullptr, &outlen,
                         plaintext.data(), plaintext.size());
  if (ret != 1) {
    return absl::Status{absl::StatusCode::kInternal,
                        "failed to get output length"};
  }

  // then encrypt
  std::vector<uint8_t> out(outlen);
  ret = EVP_PKEY_encrypt(ctx.get(), out.data(), &outlen, plaintext.data(),
                         plaintext.size());
  if (ret != 1) {
    return absl::Status{absl::StatusCode::kInternal, "failed to encrypt"};
  }

  out.resize(outlen); /* important */

  return out;
}

absl::StatusOr<std::vector<uint8_t>> RsaDecryptor::Decrypt(
    absl::Span<const uint8_t> ciphertext) {
  auto ctx = Openssl::UniquePkeyCtx(
      EVP_PKEY_CTX_new(sk_.get(), /* engine = default */ nullptr),
      EVP_PKEY_CTX_free);
  if (ctx == nullptr) {
    return absl::Status{absl::StatusCode::kInternal,
                        "failed to create pkey context"};
  }
  int ret = 0;
  // init context
  ret = EVP_PKEY_decrypt_init(ctx.get());
  if (ret != 1) {
    return absl::Status{absl::StatusCode::kInternal,
                        "failed to init pkey context"};
  }

  // make sure to use OAEP_PADDING
  ret = EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING);
  if (ret != 1) {
    return absl::Status{absl::StatusCode::kInternal,
                        "failed to set rsa padding"};
  }

  ret = EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256());
  if (ret != 1) {
    return absl::Status{absl::StatusCode::kInternal,
                        "failed to set rsa sha256 oaep md"};
  }

  ret = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256());
  if (ret != 1) {
    return absl::Status{absl::StatusCode::kInternal,
                        "failed to set rsa sha256 mgf1 md"};
  }

  // first, get output length
  size_t outlen = 0;
  ret = EVP_PKEY_decrypt(ctx.get(), /* empty input */ nullptr, &outlen,
                         ciphertext.data(), ciphertext.size());
  if (ret != 1) {
    return absl::Status{absl::StatusCode::kInternal,
                        "failed to get output length"};
  }

  // then decrypt
  std::vector<uint8_t> out(outlen);
  ret = EVP_PKEY_decrypt(ctx.get(), out.data(), &outlen, ciphertext.data(),
                         ciphertext.size());
  if (ret != 1) {
    return absl::Status{absl::StatusCode::kInternal, "failed to decrypt"};
  }

  out.resize(outlen); /* important */

  return out;
}

}  // namespace Crypto
}  // namespace Common
}  // namespace Envoy