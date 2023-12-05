#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

namespace client_server_api {
class ClientServerCtrl : public drogon::HttpController<ClientServerCtrl> {
public:
  METHOD_LIST_BEGIN
  ADD_METHOD_TO(ClientServerCtrl::versions, "/_matrix/client/versions", Get);
  ADD_METHOD_TO(ClientServerCtrl::whoami, "/_matrix/client/v3/account/whoami",
                Get);
  ADD_METHOD_TO(ClientServerCtrl::user_available,
                "/_matrix/client/v3/register/available?username={1}", Get);
  ADD_METHOD_TO(ClientServerCtrl::login, "/_matrix/client/v3/login", Get);
  ADD_METHOD_TO(ClientServerCtrl::register_user, "/_matrix/client/v3/register",
                Post, Options);
  METHOD_LIST_END

protected:
  void versions(const HttpRequestPtr &,
                std::function<void(const HttpResponsePtr &)> &&callback) const;
  void whoami(const HttpRequestPtr &req,
              std::function<void(const HttpResponsePtr &)> &&callback) const;
  void user_available(const HttpRequestPtr &,
                      std::function<void(const HttpResponsePtr &)> &&callback,
                      const std::string &username) const;
  void login(const HttpRequestPtr &,
             std::function<void(const HttpResponsePtr &)> &&callback) const;
  void
  register_user(const HttpRequestPtr &req,
                std::function<void(const HttpResponsePtr &)> &&callback) const;
};
} // namespace client_server_api
