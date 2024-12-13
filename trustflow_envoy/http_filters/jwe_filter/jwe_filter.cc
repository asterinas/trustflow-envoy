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

#include "trustflow_envoy/http_filters/jwe_filter/jwe_filter.h"

#include <iostream>
#include <string>

#include "cppcodec/base64_url_unpadded.hpp"
#include "fmt/format.h"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "spdlog/spdlog.h"
#include "src/google/protobuf/util/json_util.h"
#include "trustflow_envoy/common/crypto/gcm.h"
#include "trustflow_envoy/common/crypto/rsa.h"

#include "envoy/common/exception.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/http/headers.h"

#include "secretflowapis/v2/sdc/jwt.pb.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Jwe {
namespace {
// TODO support more algorithms
constexpr uint8_t kIvBytes = 12;
constexpr char kRsaOaep256[] = "RSA-OAEP-256";
constexpr char kAes128Gcm[] = "A128GCM";
constexpr uint8_t kMacBytes = 16;
}  // namespace

std::string JweFilterConfig::LoadBufFromFile(const std::string& file_path) {
  auto buf = Common::Crypto::LoadBufFromFile(file_path);
  if (!buf.ok()) {
    SPDLOG_ERROR("load buf from file failed: {}", buf.status().message());
    throw EnvoyException(buf.status().ToString());
  }

  return std::move(buf).value();
}

Http::FilterHeadersStatus JweFilter::decodeHeaders(
    Http::RequestHeaderMap& headers, bool end_stream) {
  request_headers_ = &headers;
  if (end_stream) {
    return Http::FilterHeadersStatus::Continue;
  }
  return Http::FilterHeadersStatus::StopIteration;
}

// From filter.h:
/**
 * * injectDecodedDataToFilterChain: When using this callback, filters should
 * generally only return FilterDataStatus::StopIterationNoBuffer from their
 * decodeData() call, since use of this method indicates that a filter does not
 * wish to participate in standard HTTP connection manager buffering and
 * continuation and will perform any necessary buffering and continuation on its
 * own.
 */
Http::FilterDataStatus JweFilter::decodeData(Buffer::Instance& data,
                                             bool end_stream) {
  SPDLOG_INFO("Decoding Data, input data size: {}", data.length());
  try {
    request_buffer_.move(data);
    if (end_stream) {
      ::secretflowapis::v2::sdc::Jwe jwe;

      // parse json to pb
      ::google::protobuf::util::JsonParseOptions options;
      auto pb_status = ::google::protobuf::util::JsonStringToMessage(
          request_buffer_.toString(), &jwe, options);
      if (!pb_status.ok()) {
        SPDLOG_INFO("Get plain text request. StreamId={}",
                    decoder_callbacks_->streamId());
        decoder_callbacks_->injectDecodedDataToFilterChain(request_buffer_,
                                                           end_stream);
      } else {
        is_jwe_ = true;
        SPDLOG_INFO("Get jwe request. StreamId={}",
                    decoder_callbacks_->streamId());
        // parse jwe
        const auto encrypted_key =
            cppcodec::base64_url_unpadded::decode(jwe.encrypted_key());
        const auto iv = cppcodec::base64_url_unpadded::decode(jwe.iv());
        const auto cipher =
            cppcodec::base64_url_unpadded::decode(jwe.ciphertext());
        const auto tag = cppcodec::base64_url_unpadded::decode(jwe.tag());
        const auto aad = cppcodec::base64_url_unpadded::decode(jwe.aad());

        // decrypt encrypted_key
        auto cek = Common::Crypto::RsaDecryptor(
                       std::move(Common::Crypto::LoadPriKeyFromBuf(
                                     absl::Span<const uint8_t>(
                                         reinterpret_cast<const uint8_t*>(
                                             config_->GetSk().data()),
                                         config_->GetSk().size())))
                           .value())
                       .Decrypt(encrypted_key);
        if (!cek.ok()) {
          SPDLOG_ERROR("decrypt encrypted_key failed: {}. StreamID={}",
                       cek.status().message(), decoder_callbacks_->streamId());
          decoder_callbacks_->sendLocalReply(
              Http::Code::BadRequest, "decrypt encrypted_key failed", nullptr,
              absl::nullopt,
              fmt::format("decrypt encrypted_key failed. StreamId={}",
                          decoder_callbacks_->streamId()));
          return Http::FilterDataStatus::StopIterationNoBuffer;
        }

        cek_ = std::move(cek).value();

        std::vector<uint8_t> plain(cipher.size());
        auto gcm_status = Common::Crypto::GcmCrypto(cek_, iv).Decrypt(
            cipher, aad, tag, absl::Span<uint8_t>(plain));
        if (!gcm_status.ok()) {
          SPDLOG_ERROR("decrypt request failed: {}. StreamID={}",
                       gcm_status.message(), decoder_callbacks_->streamId());
          decoder_callbacks_->sendLocalReply(
              Http::Code::BadRequest, "decrypt request failed", nullptr,
              absl::nullopt,
              fmt::format("decrypt request failed. StreamId={}",
                          decoder_callbacks_->streamId()));
          return Http::FilterDataStatus::StopIterationNoBuffer;
        }

        Buffer::OwnedImpl request_data =
            Buffer::OwnedImpl(plain.data(), plain.size());
        request_headers_->setContentLength(request_data.length());
        decoder_callbacks_->injectDecodedDataToFilterChain(request_data,
                                                           end_stream);
      }
    }
    return Http::FilterDataStatus::StopIterationNoBuffer;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("{} StreamID={}", e.what(), decoder_callbacks_->streamId());
    decoder_callbacks_->sendLocalReply(
        Http::Code::BadRequest, e.what(), nullptr, absl::nullopt,
        fmt::format("{}. StreamID={}", e.what(),
                    decoder_callbacks_->streamId()));
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }
}

Http::FilterTrailersStatus JweFilter::decodeTrailers(Http::RequestTrailerMap&) {
  return Http::FilterTrailersStatus::Continue;
}

Http::FilterHeadersStatus JweFilter::encodeHeaders(
    Http::ResponseHeaderMap& headers, bool end_stream) {
  response_headers_ = &headers;
  if (end_stream) {
    return Http::FilterHeadersStatus::Continue;
  }
  return Http::FilterHeadersStatus::StopIteration;
}

Http::FilterDataStatus JweFilter::encodeData(Buffer::Instance& data,
                                             bool end_stream) {
  SPDLOG_INFO("Encoding Data, input data size: {}. StreamID={}", data.length(),
              encoder_callbacks_->streamId());

  try {
    response_buffer_.move(data);
    if (end_stream) {
      if (!is_jwe_) {
        SPDLOG_INFO("Plain text response. StreamID={}",
                    encoder_callbacks_->streamId());
        encoder_callbacks_->injectEncodedDataToFilterChain(response_buffer_,
                                                           end_stream);
      } else {
        SPDLOG_INFO("Jwe response. StreamID={}",
                    encoder_callbacks_->streamId());
        ::secretflowapis::v2::sdc::Jwe jwe;

        ::secretflowapis::v2::sdc::Jwe::JoseHeader jwe_header;
        jwe_header.set_alg(kRsaOaep256);
        jwe_header.set_enc(kAes128Gcm);
        std::string jwe_header_str;
        ::google::protobuf::util::JsonPrintOptions options;
        options.preserve_proto_field_names = false;
        options.always_print_fields_with_no_presence = true;
        auto pb_status = ::google::protobuf::util::MessageToJsonString(
            jwe_header, &jwe_header_str, options);
        if (!pb_status.ok()) {
          SPDLOG_ERROR("jwe_header to json failed: {}. StreamID={}",
                       pb_status.ToString().c_str(),
                       encoder_callbacks_->streamId());
          encoder_callbacks_->sendLocalReply(
              Http::Code::BadRequest, "jwe_header to json failed", nullptr,
              absl::nullopt,
              fmt::format("jwe_header to json failed. StreamID={}",
                          encoder_callbacks_->streamId()));
          return Http::FilterDataStatus::StopIterationNoBuffer;
        }
        jwe.set_protected_header(
            cppcodec::base64_url_unpadded::encode(jwe_header_str));
        // encrypted_key not set,
        // use cek_ which provied by client to encrypt response

        std::vector<uint8_t> iv(kIvBytes);
        RAND_bytes(iv.data(), iv.size());
        jwe.set_iv(cppcodec::base64_url_unpadded::encode(iv));

        std::string plain = response_buffer_.toString();
        std::vector<uint8_t> aad;
        std::vector<uint8_t> cipher(plain.size());
        std::vector<uint8_t> tag(kMacBytes);
        auto gcm_status = Common::Crypto::GcmCrypto(cek_, iv).Encrypt(
            absl::Span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(plain.data()), plain.size()),
            aad, absl::Span<uint8_t>(cipher), absl::Span<uint8_t>(tag));
        if (!gcm_status.ok()) {
          SPDLOG_ERROR("encrypt response failed: {}. StreamID={}",
                       gcm_status.message(), encoder_callbacks_->streamId());
          encoder_callbacks_->sendLocalReply(
              Http::Code::BadRequest, "encrypt response failed", nullptr,
              absl::nullopt,
              fmt::format("encrypt response failed. StreamID={}",
                          encoder_callbacks_->streamId()));
          return Http::FilterDataStatus::StopIterationNoBuffer;
        }
        jwe.set_ciphertext(cppcodec::base64_url_unpadded::encode(cipher));
        jwe.set_tag(cppcodec::base64_url_unpadded::encode(tag));
        jwe.set_aad("");

        std::string jwe_str;
        pb_status = ::google::protobuf::util::MessageToJsonString(jwe, &jwe_str,
                                                                  options);
        if (!pb_status.ok()) {
          SPDLOG_ERROR("jwe to json failed: {}. StreamID={}",
                       pb_status.ToString().c_str(),
                       encoder_callbacks_->streamId());
          encoder_callbacks_->sendLocalReply(
              Http::Code::BadRequest, "jwe to json failed", nullptr,
              absl::nullopt,
              fmt::format("jwe to json failed. StreamID={}",
                          encoder_callbacks_->streamId()));
          return Http::FilterDataStatus::StopIterationNoBuffer;
        }

        Buffer::OwnedImpl response_data =
            Buffer::OwnedImpl(jwe_str.data(), jwe_str.size());
        response_headers_->setContentLength(response_data.length());
        encoder_callbacks_->injectEncodedDataToFilterChain(response_data,
                                                           end_stream);
      }
    }
    return Http::FilterDataStatus::StopIterationNoBuffer;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("{}. StreamID={}", e.what(), encoder_callbacks_->streamId());
    decoder_callbacks_->sendLocalReply(
        Http::Code::BadRequest, e.what(), nullptr, absl::nullopt,
        fmt::format("{}. StreamID={}", e.what(),
                    encoder_callbacks_->streamId()));
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }
}

Http::FilterTrailersStatus JweFilter::encodeTrailers(
    Http::ResponseTrailerMap&) {
  return Http::FilterTrailersStatus::Continue;
}

}  // namespace Jwe
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
