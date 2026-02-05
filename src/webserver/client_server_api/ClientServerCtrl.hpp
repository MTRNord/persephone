#pragma once

#include "database/database.hpp"
#include "utils/config.hpp"
#include "webserver/json.hpp"
#include <cstddef>
#include <drogon/HttpController.h>
#include <drogon/HttpFilter.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <drogon/drogon_callbacks.h>
#include <functional>
#include <optional>
#include <utility>
#include <vector>
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

// Define our default room version globally
static constexpr std::string default_room_version = "11";

namespace client_server_api {
class AccessTokenFilter final : public drogon::HttpFilter<AccessTokenFilter> {
public:
  void doFilter(const HttpRequestPtr &req, FilterCallback &&callback,
                FilterChainCallback &&chain_callback) override;
};

struct UserValidData {
  bool isValid;
  std::optional<Database::UserInfo> userInfo;
};

class ClientServerCtrl final
    : public drogon::HttpController<ClientServerCtrl, false> {
public:
  METHOD_LIST_BEGIN
  ADD_METHOD_TO(ClientServerCtrl::versions, "/_matrix/client/versions", Get,
                Options);
  ADD_METHOD_TO(ClientServerCtrl::whoami, "/_matrix/client/v3/account/whoami",
                Get, Options, "client_server_api::AccessTokenFilter");
  ADD_METHOD_TO(ClientServerCtrl::user_available,
                "/_matrix/client/v3/register/available?username={1}", Get,
                Options);
  ADD_METHOD_TO(ClientServerCtrl::login_get, "/_matrix/client/v3/login", Get,
                Options);
  ADD_METHOD_TO(ClientServerCtrl::login_post, "/_matrix/client/v3/login", Post,
                Options);
  ADD_METHOD_TO(ClientServerCtrl::register_user, "/_matrix/client/v3/register",
                Post, Options);

  // PushRules
  ADD_METHOD_TO(ClientServerCtrl::getPushrules, "/_matrix/client/v3/pushrules/",
                Get, Options, "client_server_api::AccessTokenFilter");

  // Room directory
  ADD_METHOD_TO(ClientServerCtrl::directoryLookupRoomAlias,
                "/_matrix/client/v3/directory/room/{1:roomAlias}", Get, Options,
                "client_server_api::AccessTokenFilter");

  // Room joining
  ADD_METHOD_TO(ClientServerCtrl::joinRoomIdOrAlias,
                "/_matrix/client/v3/join/{1:roomIdOrAlias}", Post, Options,
                "client_server_api::AccessTokenFilter");

  // Room creation
  ADD_METHOD_TO(ClientServerCtrl::createRoom, "/_matrix/client/v3/createRoom",
                Post, Options, "client_server_api::AccessTokenFilter");

  // Room state
  ADD_METHOD_TO(
      ClientServerCtrl::state,
      "/_matrix/client/v3/rooms/{1:roomId}/state/{2:eventType}/{3:stateKey}",
      Get, Options, "client_server_api::AccessTokenFilter");

  // Filters
  ADD_METHOD_TO(ClientServerCtrl::setFilter,
                "/_matrix/client/v3/user/{1:userId}/filter", Post, Options,
                "client_server_api::AccessTokenFilter");
  ADD_METHOD_TO(ClientServerCtrl::getFilter,
                "/_matrix/client/v3/user/{1:userId}/filter/{2:filterId}", Get,
                Options, "client_server_api::AccessTokenFilter");
  METHOD_LIST_END

  explicit ClientServerCtrl(Config config) : _config(std::move(config)) {}

protected:
  /// Get user info from access token in Authorization header or query parameter.
  /// Supports deprecated ?access_token= query parameter (deprecated in v1.11).
  drogon::Task<UserValidData> getUserInfo(
      const HttpRequestPtr &req,
      const std::function<void(const HttpResponsePtr &)> &callback) const;

  void versions(const HttpRequestPtr &,
                std::function<void(const HttpResponsePtr &)> &&callback) const;

  void whoami(const HttpRequestPtr &req,
              std::function<void(const HttpResponsePtr &)> &&callback) const;

  void user_available(const HttpRequestPtr &,
                      std::function<void(const HttpResponsePtr &)> &&callback,
                      const std::string &username) const;

  void login_get(const HttpRequestPtr &,
                 std::function<void(const HttpResponsePtr &)> &&callback) const;
  void
  login_post(const HttpRequestPtr &req,
             std::function<void(const HttpResponsePtr &)> &&callback) const;

  void
  register_user(const HttpRequestPtr &req,
                std::function<void(const HttpResponsePtr &)> &&callback) const;

  void
  getPushrules(const HttpRequestPtr &req,
               std::function<void(const HttpResponsePtr &)> &&callback) const;

  void directoryLookupRoomAlias(
      const HttpRequestPtr &req,
      std::function<void(const HttpResponsePtr &)> &&callback,
      const std::string &roomAlias) const;

  void
  joinRoomIdOrAlias(const HttpRequestPtr &req,
                    std::function<void(const HttpResponsePtr &)> &&callback,
                    const std::string &roomIdOrAlias) const;

  void
  createRoom(const HttpRequestPtr &req,
             std::function<void(const HttpResponsePtr &)> &&callback) const;

  void state(const HttpRequestPtr &req,
             std::function<void(const HttpResponsePtr &)> &&callback,
             const std::string &roomId, const std::string &eventType,
             const std::optional<std::string> &state_key) const;

  void setFilter(const HttpRequestPtr &req,
                 std::function<void(const HttpResponsePtr &)> &&callback,
                 const std::string &userId) const;

  void getFilter(const HttpRequestPtr &req,
                 std::function<void(const HttpResponsePtr &)> &&callback,
                 const std::string &userId, const std::string &filterId) const;

private:
  Config _config;
};
} // namespace client_server_api