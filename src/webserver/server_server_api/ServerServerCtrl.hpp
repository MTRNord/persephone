#pragma once

#include "utils/config.hpp"
#include "utils/utils.hpp"
#include <drogon/HttpController.h>

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
              _verify_key_data(std::move(verify_key_data)) {
        }

    protected:
        void version(const HttpRequestPtr &,
                     std::function<void(const HttpResponsePtr &)> &&callback) const;

        void
        server_key(const HttpRequestPtr &,
                   std::function<void(const HttpResponsePtr &)> &&callback) const;

    private:
        Config _config;
        VerifyKeyData _verify_key_data;
    };
} // namespace server_server_api
