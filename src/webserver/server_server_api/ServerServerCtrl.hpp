#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

namespace server_server_api {
class ServerServerCtrl : public drogon::HttpController<ServerServerCtrl> {
public:
  METHOD_LIST_BEGIN
  ADD_METHOD_TO(ServerServerCtrl::version, "/_matrix/federation/v1/version",
                Get);
  ADD_METHOD_TO(ServerServerCtrl::server_key, "/_matrix/key/v2/server", Get);
  METHOD_LIST_END

protected:
  void version(const HttpRequestPtr &,
               std::function<void(const HttpResponsePtr &)> &&callback) const;
  void
  server_key(const HttpRequestPtr &,
             std::function<void(const HttpResponsePtr &)> &&callback) const;
};
} // namespace server_server_api
