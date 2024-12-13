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

#include <string>

#include "trustflow_envoy/http_filters/jwe_filter/jwe_filter.h"

#include "source/extensions/filters/http/common/factory_base.h"

#include "trustflow_envoy/http_filters/jwe_filter/jwe_filter.pb.h"
#include "trustflow_envoy/http_filters/jwe_filter/jwe_filter.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Jwe {

class JweFilterConfigFactory
    : public Common::FactoryBase<
          envoy::extensions::filters::http::jwe::v1::JweConfig> {
 public:
  JweFilterConfigFactory() : FactoryBase("envoy.filters.http.jwe") {}

 private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::jwe::v1::JweConfig& proto_config,
      const std::string&, Server::Configuration::FactoryContext&) override;
};

}  // namespace Jwe
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
