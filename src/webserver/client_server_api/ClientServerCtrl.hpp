#pragma once

#include "database/database.hpp"
#include "utils/config.hpp"
#include "webserver/json.hpp"
#include <drogon/HttpController.h>
#include <drogon/HttpFilter.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <drogon/drogon_callbacks.h>
#include <functional>
#include <optional>
#include <utility>

using namespace drogon;

namespace client_server_api {
class AccessTokenFilter final : public drogon::HttpFilter<AccessTokenFilter> {
public:
  void doFilter(const HttpRequestPtr &req, FilterCallback &&callback,
                FilterChainCallback &&chain_callback) override;
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

  // Room joining
  ADD_METHOD_TO(ClientServerCtrl::joinRoomIdOrAlias,
                "_matrix/client/v3/join/{1:roomIdOrAlias}", Post, Options,
                "client_server_api::AccessTokenFilter");

  // Room creation
  ADD_METHOD_TO(ClientServerCtrl::createRoom, "_matrix/client/v3/createRoom",
                Post, Options, "client_server_api::AccessTokenFilter");

  // Room state
  ADD_METHOD_TO(
      ClientServerCtrl::state,
      "_matrix/client/v3/rooms/{1:roomId}/state/{2:eventType}/{3:stateKey}",
      Get, Options, "client_server_api::AccessTokenFilter");
  METHOD_LIST_END

  explicit ClientServerCtrl(Config config) : _config(std::move(config)) {}

protected:
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

  [[nodiscard]] json get_powerlevels_pdu(
      const std::string &room_version, const std::string &sender,
      const std::string &room_id,
      const std::optional<client_server_json::PowerLevelEventContent>
          &power_level_override) const;

private:
  Config _config;
};
} // namespace client_server_api
