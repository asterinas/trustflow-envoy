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

#include <string>

#include "trustflow_envoy/common/crypto/key_utils.h"
#include "trustflow_envoy/common/crypto/openssl_wrapper.h"

#include "envoy/http/filter.h"

#include "source/common/buffer/buffer_impl.h"

#include "trustflow_envoy/http_filters/jwe_filter/jwe_filter.pb.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Jwe {

class JweFilterConfig {
 public:
  JweFilterConfig(
      const envoy::extensions::filters::http::jwe::v1::JweConfig& proto_config)
      : pk_(LoadBufFromFile(proto_config.cert_path())),
        sk_(LoadBufFromFile(proto_config.private_key_path())) {
    // check
    if (!Common::Crypto::LoadX509CertPubKeyFromBuf(
             absl::Span<const uint8_t>(
                 reinterpret_cast<const uint8_t*>(pk_.data()), pk_.size()))
             .ok()) {
      SPDLOG_ERROR("load public key from {} failed", proto_config.cert_path());
      throw EnvoyException("load public key failed");
    }
    if (!Common::Crypto::LoadPriKeyFromBuf(
             absl::Span<const uint8_t>(
                 reinterpret_cast<const uint8_t*>(sk_.data()), sk_.size()))
             .ok()) {
      SPDLOG_ERROR("load private key from {} failed",
                   proto_config.private_key_path());
      throw EnvoyException("load private key failed");
    }
  }

  std::string GetPk() { return pk_; }
  std::string GetSk() { return sk_; }

 private:
  std::string LoadBufFromFile(const std::string& file_path);
  // public_key
  const std::string pk_;
  // private_key
  const std::string sk_;
};

using JweFilterConfigSharedPtr = std::shared_ptr<JweFilterConfig>;

class JweFilter : public Http::StreamFilter {
 public:
  JweFilter(const JweFilterConfigSharedPtr& config_shared_ptr)
      : config_(config_shared_ptr) {};

  // Http::StreamFilterBase
  void onDestroy() override {}

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data,
                                    bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override;
  void setDecoderFilterCallbacks(
      Http::StreamDecoderFilterCallbacks& callbacks) override {
    decoder_callbacks_ = &callbacks;
  }

  // Http::StreamEncoderFilter
  Http::Filter1xxHeadersStatus encode1xxHeaders(
      Http::ResponseHeaderMap&) override {
    return Http::Filter1xxHeadersStatus::Continue;
  }
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance& data,
                                    bool end_stream) override;
  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap&) override;
  Http::FilterMetadataStatus encodeMetadata(Http::MetadataMap&) override {
    return Http::FilterMetadataStatus::Continue;
  }
  void setEncoderFilterCallbacks(
      Http::StreamEncoderFilterCallbacks& callbacks) override {
    encoder_callbacks_ = &callbacks;
  }

 private:
  const JweFilterConfigSharedPtr config_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{};
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_{};

  Http::RequestHeaderMap* request_headers_{};
  Envoy::Buffer::OwnedImpl request_buffer_;
  bool is_jwe_ = false;
  std::vector<uint8_t> cek_;
  Http::ResponseHeaderMap* response_headers_{};
  Envoy::Buffer::OwnedImpl response_buffer_;
};

}  // namespace Jwe
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
