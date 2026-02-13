#pragma once

#include "utils/config.hpp"
#include "utils/utils.hpp"
#include <drogon/HttpController.h>
#include <drogon/HttpFilter.h>
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

namespace server_server_api {
// Needed for drogon macros (Get, Put, etc.) and drogon types in declarations
using namespace drogon;

/// Filter for verifying X-Matrix Authorization headers on federation endpoints.
/// This filter verifies that incoming requests are properly signed by the
/// origin server.
class FederationAuthFilter final
    : public drogon::HttpFilter<FederationAuthFilter> {
public:
  FederationAuthFilter() = default;

  void doFilter(const HttpRequestPtr &req, FilterCallback &&callback,
                FilterChainCallback &&chain_callback) override;

  /// Set the server name for all filter instances (call once at startup)
  static void setServerName(std::string name);

private:
  static std::string _server_name;
};
class ServerServerCtrl final
    : public drogon::HttpController<ServerServerCtrl, false> {
public:
  METHOD_LIST_BEGIN
  // These endpoints do NOT require X-Matrix auth
  ADD_METHOD_TO(ServerServerCtrl::version, "/_matrix/federation/v1/version",
                Get);
  ADD_METHOD_TO(ServerServerCtrl::server_key, "/_matrix/key/v2/server", Get);
  // These endpoints require X-Matrix auth
  ADD_METHOD_TO(ServerServerCtrl::make_join,
                "/_matrix/federation/v1/make_join/{1:roomId}/{2:userId}", Get,
                "server_server_api::FederationAuthFilter");
  ADD_METHOD_TO(ServerServerCtrl::send_join,
                "/_matrix/federation/v2/send_join/{1:roomId}/{2:eventId}", Put,
                "server_server_api::FederationAuthFilter");
  ADD_METHOD_TO(ServerServerCtrl::get_event,
                "/_matrix/federation/v1/event/{1:eventId}", Get,
                "server_server_api::FederationAuthFilter");
  ADD_METHOD_TO(ServerServerCtrl::get_state_ids,
                "/_matrix/federation/v1/state_ids/{1:roomId}", Get,
                "server_server_api::FederationAuthFilter");
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

  void make_join(const HttpRequestPtr &req,
                 std::function<void(const HttpResponsePtr &)> &&callback,
                 const std::string &roomId, const std::string &userId) const;

  void send_join(const HttpRequestPtr &req,
                 std::function<void(const HttpResponsePtr &)> &&callback,
                 const std::string &roomId,
                 const std::string &eventId) const;

  void get_event(const HttpRequestPtr &req,
                 std::function<void(const HttpResponsePtr &)> &&callback,
                 const std::string &eventId) const;

  void get_state_ids(const HttpRequestPtr &req,
                     std::function<void(const HttpResponsePtr &)> &&callback,
                     const std::string &roomId) const;

private:
  Config _config;
  VerifyKeyData _verify_key_data;
};
} // namespace server_server_api
