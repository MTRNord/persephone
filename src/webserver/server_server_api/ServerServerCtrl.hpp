#pragma once

#include "utils/config.hpp"
#include "utils/utils.hpp"
#include <drogon/HttpController.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <functional>
#include <utility>
#ifdef __GNUC__
// Ignore false positives (see https://github.com/nlohmann/json/issues/3808)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include "nlohmann/json.hpp"
#pragma GCC diagnostic pop
#else
#include <nlohmann/json.hpp>
#endif

using namespace drogon;

namespace server_server_api {
class ServerServerCtrl final
    : public drogon::HttpController<ServerServerCtrl, false> {
public:
  METHOD_LIST_BEGIN
  ADD_METHOD_TO(ServerServerCtrl::version, "/_matrix/federation/v1/version",
                Get);
  ADD_METHOD_TO(ServerServerCtrl::server_key, "/_matrix/key/v2/server", Get);
  METHOD_LIST_END

  explicit ServerServerCtrl(Config config, VerifyKeyData verify_key_data)
      : _config(std::move(config)),
        _verify_key_data(std::move(verify_key_data)) {}

protected:
  static void version(const HttpRequestPtr &,
                      std::function<void(const HttpResponsePtr &)> &&callback);

  void
  server_key(const HttpRequestPtr &,
             std::function<void(const HttpResponsePtr &)> &&callback) const;

private:
  Config _config;
  VerifyKeyData _verify_key_data;
};
} // namespace server_server_api
