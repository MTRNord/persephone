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

/**
 * Check if a localpard is valid according to
 * https://spec.matrix.org/v1.8/appendices/#user-identifiers
 *
 * ```
 * user_id_localpart = 1*user_id_char
 * user_id_char = DIGIT
 *              / %x61-7A                   ; a-z
 *              / "-" / "." / "=" / "_" / "/" / "+"
 * ```
 *
 * We also need to check that it not exceeds 255 chars when containing `@`, a
 * colon and the domain.
 *
 * @param localpart The localpart to check
 * @return true if the localpart is valid, false otherwise
 */
bool is_valid_localpart(std::string const &localpart, std::string server_name) {
  for (auto const &c : localpart) {
    if (std::isdigit(c)) {
      continue;
    }
    if (c >= 'a' && c <= 'z') {
      continue;
    }
    if (c == '-' || c == '.' || c == '=' || c == '_' || c == '/' || c == '+') {
      continue;
    }
    return false;
  }

  // Check if the localpart is too long
  if (std::format("@{}:{}", localpart, server_name).length() > 255) {
    return false;
  }

  return true;
}
} // namespace client_server_api
