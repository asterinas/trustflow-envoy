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

#include "trustflow_envoy/http_filters/jwe_filter/config.h"

#include "envoy/registry/registry.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Jwe {

Http::FilterFactoryCb JweFilterConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::jwe::v1::JweConfig& proto_config,
    const std::string&, Server::Configuration::FactoryContext&) {
  JweFilterConfigSharedPtr config =
      std::make_shared<JweFilterConfig>(proto_config);

  return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamFilter(std::make_shared<JweFilter>(config));
  };
}

REGISTER_FACTORY(JweFilterConfigFactory,
                 Server::Configuration::NamedHttpFilterConfigFactory);

}  // namespace Jwe
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy