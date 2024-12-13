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

#include "trustflow_envoy/common/crypto/key_utils.h"

#include <fstream>
#include <sstream>

#include "fmt/format.h"

namespace Envoy {
namespace Common {
namespace Crypto {

absl::StatusOr<std::string> LoadBufFromFile(const std::string& file_path) {
  std::ifstream ifs(file_path, std::ios::binary);
  if (!ifs.is_open()) {
    return absl::InvalidArgumentError(
        fmt::format("failed to open file {}", file_path));
  }
  std::stringstream ss;
  ss << ifs.rdbuf();
  // Ifstream's destructor will automatically call close when it goes out of
  // scope. Manually calling close() here ensures that the file is properly
  // closed even in cases where the program exits before the destructor is
  // called. refer to:
  // https://stackoverflow.com/questions/748014/do-i-need-to-manually-close-an-ifstream
  ifs.close();
  return ss.str();
}

absl::StatusOr<Openssl::UniquePkey> LoadPriKeyFromBuf(
    absl::Span<const uint8_t> buf) {
  auto bio =
      Openssl::UniqueBio(BIO_new_mem_buf(buf.data(), buf.size()), BIO_free);
  if (bio == nullptr) {
    return absl::InvalidArgumentError("failed to create bio");
  }

  auto pkey = Openssl::UniquePkey(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr),
      EVP_PKEY_free);
  if (pkey == nullptr) {
    return absl::InvalidArgumentError("failed to load private key");
  }

  return pkey;
}

absl::StatusOr<Openssl::UniquePkey> LoadPriKeyFromFile(
    const std::string& file_path) {
  auto load_ret = LoadBufFromFile(file_path);
  if (!load_ret.ok()) {
    return load_ret.status();
  }

  return LoadPriKeyFromBuf(absl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(load_ret.value().data()),
      load_ret.value().size()));
}

absl::StatusOr<Openssl::UniquePkey> LoadPubKeyFromBuf(
    absl::Span<const uint8_t> buf) {
  auto bio =
      Openssl::UniqueBio(BIO_new_mem_buf(buf.data(), buf.size()), BIO_free);
  if (bio == nullptr) {
    return absl::InvalidArgumentError("failed to create bio");
  }

  auto pkey = Openssl::UniquePkey(
      PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
  if (pkey == nullptr) {
    return absl::InvalidArgumentError("failed to load public key");
  }

  return pkey;
}

absl::StatusOr<Openssl::UniquePkey> LoadPubKeyFromFile(
    const std::string& file_path) {
  auto load_ret = LoadBufFromFile(file_path);
  if (!load_ret.ok()) {
    return load_ret.status();
  }

  std::string content = std::move(load_ret).value();

  return LoadPubKeyFromBuf(absl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(content.data()), content.size()));
}

absl::StatusOr<Openssl::UniquePkey> LoadX509CertPubKeyFromBuf(
    absl::Span<const uint8_t> buf) {
  auto bio =
      Openssl::UniqueBio(BIO_new_mem_buf(buf.data(), buf.size()), BIO_free);
  if (bio == nullptr) {
    return absl::InvalidArgumentError("failed to create bio");
  }

  auto x509 = Openssl::UniqueX509(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free);
  if (x509 == nullptr) {
    return absl::InvalidArgumentError("failed to load x509");
  }

  auto pkey = Openssl::UniquePkey(X509_get_pubkey(x509.get()), EVP_PKEY_free);
  if (pkey == nullptr) {
    return absl::InvalidArgumentError("failed to get public key from x509");
  }

  return pkey;
}

absl::StatusOr<Openssl::UniquePkey> LoadX509CertPubKeyFromFile(
    const std::string& file_path) {
  auto load_ret = LoadBufFromFile(file_path);
  if (!load_ret.ok()) {
    return load_ret.status();
  }

  std::string content = std::move(load_ret).value();

  return LoadX509CertPubKeyFromBuf(absl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(content.data()), content.size()));
}

}  // namespace Crypto
}  // namespace Common
}  // namespace Envoy