#pragma once

#include "database/database.hpp"
#include "utils/config.hpp"
#include <drogon/HttpController.h>
#include <drogon/HttpFilter.h>

using namespace drogon;

namespace client_server_api {
    class AccessTokenFilter final : public drogon::HttpFilter<AccessTokenFilter> {
    public:
        void doFilter(const HttpRequestPtr &req, FilterCallback &&cb,
                      FilterChainCallback &&ccb) override;
    };

    class ClientServerCtrl final
            : public drogon::HttpController<ClientServerCtrl, false> {
    public:
        METHOD_LIST_BEGIN
            ADD_METHOD_TO(ClientServerCtrl::versions, "/_matrix/client/versions", Get, Options);
            ADD_METHOD_TO(ClientServerCtrl::whoami, "/_matrix/client/v3/account/whoami",
                          Get, Options, "client_server_api::AccessTokenFilter");
            ADD_METHOD_TO(ClientServerCtrl::user_available,
                          "/_matrix/client/v3/register/available?username={1}", Get, Options);
            ADD_METHOD_TO(ClientServerCtrl::login, "/_matrix/client/v3/login", Get, Post, Options);
            ADD_METHOD_TO(ClientServerCtrl::register_user, "/_matrix/client/v3/register",
                          Post, Options);

            // Room joining
            ADD_METHOD_TO(ClientServerCtrl::joinRoomIdOrAlias,
                          "_matrix/client/v3/join/{1:roomIdOrAlias}", Post, Options,
                          "client_server_api::AccessTokenFilter");

            // Room creation
            ADD_METHOD_TO(ClientServerCtrl::createRoom, "_matrix/client/v3/createRoom",
                          Post, Options, "client_server_api::AccessTokenFilter");
        METHOD_LIST_END

        explicit ClientServerCtrl(Config config, Database db)
            : _config(std::move(config)), _db(db) {
        }

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

        void
        joinRoomIdOrAlias(const HttpRequestPtr &req,
                          std::function<void(const HttpResponsePtr &)> &&callback,
                          const std::string &roomIdOrAlias) const;

        void
        createRoom(const HttpRequestPtr &req,
                   std::function<void(const HttpResponsePtr &)> &&callback) const;

    private:
        Config _config;
        Database _db;
    };
} // namespace client_server_api
