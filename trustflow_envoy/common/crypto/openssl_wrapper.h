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

#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

namespace Envoy {
namespace Common {
namespace Crypto {

namespace Openssl {

using UniqueCipherCtx =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

using UniqueBio = std::unique_ptr<BIO, decltype(&BIO_free)>;
using UniqueX509 = std::unique_ptr<X509, decltype(&X509_free)>;

using UniquePkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using UniquePkeyCtx =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

}  // namespace Openssl

}  // namespace Crypto
}  // namespace Common
}  // namespace Envoy