#include "webserver/json.hpp"
#include <map>
#include <snitch/snitch.hpp>
#include <string>
#include <vector>

using json = nlohmann::json;
using namespace std::string_view_literals;

// ============================================================================
// generic_json types
// ============================================================================

TEST_CASE("generic_json_error serialization", "[json_serialization]") {
  SECTION("Round-trip") {
    generic_json::generic_json_error err{.errcode = "M_NOT_FOUND",
                                         .error = "Not found"};
    json j = err;
    REQUIRE(j["errcode"] == "M_NOT_FOUND");
    REQUIRE(j["error"] == "Not found");

    auto deserialized = j.get<generic_json::generic_json_error>();
    REQUIRE(deserialized.errcode == "M_NOT_FOUND");
    REQUIRE(deserialized.error == "Not found");
  }
}

// ============================================================================
// server_server_json types
// ============================================================================

TEST_CASE("server_server_json::MakeJoinResp serialization",
          "[json_serialization]") {
  SECTION("With room_version") {
    json input = {{"event", {{"type", "m.room.member"}}},
                  {"room_version", "11"}};

    auto resp = input.get<server_server_json::MakeJoinResp>();
    REQUIRE(resp.room_version.has_value());
    REQUIRE(resp.room_version.value() == "11");
    REQUIRE(resp.event.contains("type"));

    json output = resp;
    REQUIRE(output["room_version"] == "11");
    REQUIRE(output["event"]["type"] == "m.room.member");
  }

  SECTION("Without room_version") {
    json input = {{"event", {{"type", "m.room.member"}}}};

    auto resp = input.get<server_server_json::MakeJoinResp>();
    REQUIRE_FALSE(resp.room_version.has_value());

    json output = resp;
    REQUIRE_FALSE(output.contains("room_version"));
    REQUIRE(output["event"]["type"] == "m.room.member");
  }
}

TEST_CASE("server_server_json::SendJoinResp serialization",
          "[json_serialization]") {
  SECTION("Full round-trip with all fields") {
    json input = {
        {"auth_chain",
         {{{"type", "m.room.create"},
           {"room_id", "!abc:example.com"},
           {"event_id", "$create"}}}},
        {"event",
         {{"type", "m.room.member"},
          {"state_key", "@alice:remote.com"},
          {"content", {{"membership", "join"}}}}},
        {"members_omitted", false},
        {"origin", "example.com"},
        {"servers_in_room", {"example.com", "remote.com", "third.com"}},
        {"state",
         {{{"type", "m.room.create"},
           {"content", {{"creator", "@admin:example.com"}}}}}}};

    auto resp = input.get<server_server_json::SendJoinResp>();
    REQUIRE(resp.auth_chain.size() == 1);
    REQUIRE(resp.auth_chain[0]["type"] == "m.room.create");
    REQUIRE(resp.event["type"] == "m.room.member");
    REQUIRE(resp.event["state_key"] == "@alice:remote.com");
    REQUIRE(resp.members_omitted == false);
    REQUIRE(resp.origin == "example.com");
    REQUIRE(resp.servers_in_room.size() == 3);
    REQUIRE(resp.servers_in_room[0] == "example.com");
    REQUIRE(resp.servers_in_room[1] == "remote.com");
    REQUIRE(resp.servers_in_room[2] == "third.com");
    REQUIRE(resp.state.size() == 1);
    REQUIRE(resp.state[0]["type"] == "m.room.create");

    json output = resp;
    REQUIRE(output["auth_chain"].size() == 1);
    REQUIRE(output["event"]["type"] == "m.room.member");
    REQUIRE(output["members_omitted"] == false);
    REQUIRE(output["origin"] == "example.com");
    REQUIRE(output["servers_in_room"].size() == 3);
    REQUIRE(output["state"].size() == 1);
  }

  SECTION("Without optional fields (origin, servers_in_room)") {
    json input = {{"auth_chain", json::array()},
                  {"event", {{"type", "m.room.member"}}},
                  {"state", json::array()}};

    auto resp = input.get<server_server_json::SendJoinResp>();
    REQUIRE(resp.auth_chain.empty());
    REQUIRE(resp.event["type"] == "m.room.member");
    REQUIRE(resp.members_omitted == false);
    REQUIRE(resp.origin.empty());
    REQUIRE(resp.servers_in_room.empty());
    REQUIRE(resp.state.empty());

    json output = resp;
    REQUIRE(output["auth_chain"].empty());
    REQUIRE(output["members_omitted"] == false);
    REQUIRE(output["origin"] == "");
    REQUIRE(output["servers_in_room"].empty());
  }

  SECTION("members_omitted defaults to false when missing") {
    json input = {{"auth_chain", json::array()},
                  {"event", {{"type", "m.room.member"}}},
                  {"state", json::array()}};

    auto resp = input.get<server_server_json::SendJoinResp>();
    REQUIRE(resp.members_omitted == false);
  }

  SECTION("members_omitted true") {
    json input = {{"auth_chain", json::array()},
                  {"event", {{"type", "m.room.member"}}},
                  {"members_omitted", true},
                  {"state", json::array()}};

    auto resp = input.get<server_server_json::SendJoinResp>();
    REQUIRE(resp.members_omitted == true);

    json output = resp;
    REQUIRE(output["members_omitted"] == true);
  }

  SECTION("Multiple auth chain and state events") {
    json input = {
        {"auth_chain",
         {{{"type", "m.room.create"}, {"event_id", "$1"}},
          {{"type", "m.room.power_levels"}, {"event_id", "$2"}},
          {{"type", "m.room.join_rules"}, {"event_id", "$3"}}}},
        {"event",
         {{"type", "m.room.member"}, {"content", {{"membership", "join"}}}}},
        {"origin", "matrix.org"},
        {"servers_in_room", {"matrix.org"}},
        {"state",
         {{{"type", "m.room.create"}},
          {{"type", "m.room.power_levels"}},
          {{"type", "m.room.join_rules"}}}}};

    auto resp = input.get<server_server_json::SendJoinResp>();
    REQUIRE(resp.auth_chain.size() == 3);
    REQUIRE(resp.state.size() == 3);
    REQUIRE(resp.origin == "matrix.org");
    REQUIRE(resp.servers_in_room.size() == 1);

    json output = resp;
    REQUIRE(output["auth_chain"].size() == 3);
    REQUIRE(output["state"].size() == 3);
  }
}

TEST_CASE("server_server_json::well_known serialization",
          "[json_serialization]") {
  SECTION("With m.server") {
    json input = {{"m.server", "matrix.example.com:443"}};
    auto wk = input.get<server_server_json::well_known>();
    REQUIRE(wk.m_server.has_value());
    REQUIRE(wk.m_server.value() == "matrix.example.com:443");

    json output = wk;
    REQUIRE(output["m.server"] == "matrix.example.com:443");
  }

  SECTION("Without m.server") {
    json input = json::object();
    auto wk = input.get<server_server_json::well_known>();
    REQUIRE_FALSE(wk.m_server.has_value());

    json output = wk;
    REQUIRE_FALSE(output.contains("m.server"));
  }
}

TEST_CASE("server_server_json::version serialization", "[json_serialization]") {
  SECTION("Round-trip") {
    json input = {{"server", {{"name", "Persephone"}, {"version", "0.1.0"}}}};
    auto ver = input.get<server_server_json::version>();
    REQUIRE(ver.server.name == "Persephone");
    REQUIRE(ver.server.version == "0.1.0");

    json output = ver;
    REQUIRE(output["server"]["name"] == "Persephone");
    REQUIRE(output["server"]["version"] == "0.1.0");
  }
}

TEST_CASE("server_server_json::keys serialization", "[json_serialization]") {
  SECTION("Round-trip") {
    json input = {
        {"server_name", "example.com"},
        {"valid_until_ts", 1234567890},
        {"old_verify_keys",
         {{"ed25519:old1", {{"key", "oldkeydata"}, {"expired_ts", 1000}}}}},
        {"verify_keys", {{"ed25519:abc", {{"key", "keydata"}}}}},
        {"signatures", {{"example.com", {{"ed25519:abc", "sigdata"}}}}}};

    auto keys = input.get<server_server_json::keys>();
    REQUIRE(keys.server_name == "example.com");
    REQUIRE(keys.valid_until_ts == 1234567890);
    REQUIRE(keys.verify_keys.at("ed25519:abc").key == "keydata");
    REQUIRE(keys.old_verify_keys.at("ed25519:old1").key == "oldkeydata");
    REQUIRE(keys.old_verify_keys.at("ed25519:old1").expired_ts == 1000);
    REQUIRE(keys.signatures.at("example.com").at("ed25519:abc") == "sigdata");

    json output = keys;
    REQUIRE(output["server_name"] == "example.com");
    REQUIRE(output["verify_keys"]["ed25519:abc"]["key"] == "keydata");
  }
}

TEST_CASE("server_server_json::directory_query serialization",
          "[json_serialization]") {
  SECTION("Round-trip") {
    json input = {{"room_id", "!abc:example.com"},
                  {"servers", {"example.com", "other.com"}}};
    auto dq = input.get<server_server_json::directory_query>();
    REQUIRE(dq.room_id == "!abc:example.com");
    REQUIRE(dq.servers.size() == 2);

    json output = dq;
    REQUIRE(output["room_id"] == "!abc:example.com");
    REQUIRE(output["servers"].size() == 2);
  }
}

// ============================================================================
// client_server_json types
// ============================================================================

TEST_CASE("client_server_json::StateEvent serialization",
          "[json_serialization]") {
  SECTION("Full event") {
    json input = {{"content", {{"membership", "join"}}},
                  {"state_key", "@alice:example.com"},
                  {"type", "m.room.member"},
                  {"event_id", "$abc123"}};

    auto se = input.get<client_server_json::StateEvent>();
    REQUIRE(se.type == "m.room.member");
    REQUIRE(se.state_key == "@alice:example.com");
    REQUIRE(se.event_id.has_value());
    REQUIRE(se.event_id.value() == "$abc123");
    REQUIRE(se.content.at("membership") == "join");

    json output = se;
    REQUIRE(output["type"] == "m.room.member");
    REQUIRE(output["state_key"] == "@alice:example.com");
    REQUIRE(output["event_id"] == "$abc123");
  }

  SECTION("Without event_id or state_key") {
    json input = {{"content", {{"body", "hello"}}}, {"type", "m.room.message"}};

    auto se = input.get<client_server_json::StateEvent>();
    REQUIRE(se.type == "m.room.message");
    REQUIRE(se.state_key == ""); // defaults to empty
    REQUIRE_FALSE(se.event_id.has_value());

    json output = se;
    REQUIRE_FALSE(output.contains("event_id"));
  }
}

TEST_CASE("client_server_json::PowerLevelEventContent serialization",
          "[json_serialization]") {
  SECTION("All fields set") {
    json input = {{"ban", 50},
                  {"events", {{"m.room.name", 50}}},
                  {"events_default", 0},
                  {"invite", 0},
                  {"kick", 50},
                  {"notifications", {{"room", 50}}},
                  {"redact", 50},
                  {"state_default", 50},
                  {"users", {{"@admin:example.com", 100}}},
                  {"users_default", 0}};

    auto pl = input.get<client_server_json::PowerLevelEventContent>();
    REQUIRE(pl.ban.value() == 50);
    REQUIRE(pl.events_default.value() == 0);
    REQUIRE(pl.invite.value() == 0);
    REQUIRE(pl.kick.value() == 50);
    REQUIRE(pl.redact.value() == 50);
    REQUIRE(pl.state_default.value() == 50);
    REQUIRE(pl.users_default.value() == 0);

    json output = pl;
    REQUIRE(output["ban"] == 50);
    REQUIRE(output["users"]["@admin:example.com"] == 100);
    REQUIRE(output["notifications"]["room"] == 50);
    REQUIRE(output["events"]["m.room.name"] == 50);
  }

  SECTION("No fields set") {
    json input = json::object();
    auto pl = input.get<client_server_json::PowerLevelEventContent>();
    REQUIRE_FALSE(pl.ban.has_value());
    REQUIRE_FALSE(pl.events.has_value());
    REQUIRE_FALSE(pl.users.has_value());

    json output = pl;
    // Empty object - no fields serialized
    REQUIRE_FALSE(output.contains("ban"));
    REQUIRE_FALSE(output.contains("events"));
  }
}

TEST_CASE("client_server_json::CreateRoomBody serialization",
          "[json_serialization]") {
  SECTION("Full body") {
    json input = {
        {"creation_content", {{"creator", "@alice:example.com"}}},
        {"initial_state",
         {{{"type", "m.room.topic"}, {"content", {{"topic", "hi"}}}}}},
        {"invite", {"@bob:example.com"}},
        {"name", "My Room"},
        {"topic", "A test room"},
        {"room_version", "11"},
        {"preset", "private_chat"},
        {"room_alias_name", "myroom"},
        {"visibility", "private"},
        {"is_direct", true}};

    auto body = input.get<client_server_json::CreateRoomBody>();
    REQUIRE(body.name.value() == "My Room");
    REQUIRE(body.topic.value() == "A test room");
    REQUIRE(body.room_version.value() == "11");
    REQUIRE(body.preset.value() == "private_chat");
    REQUIRE(body.room_alias_name.value() == "myroom");
    REQUIRE(body.visibility.value() == "private");
    REQUIRE(body.is_direct.value() == true);
    REQUIRE(body.invite->size() == 1);
    REQUIRE(body.initial_state->size() == 1);

    json output = body;
    REQUIRE(output["name"] == "My Room");
    REQUIRE(output["room_version"] == "11");
    REQUIRE(output["is_direct"] == true);
  }

  SECTION("Empty body") {
    json input = json::object();
    auto body = input.get<client_server_json::CreateRoomBody>();
    REQUIRE_FALSE(body.name.has_value());
    REQUIRE_FALSE(body.topic.has_value());
    REQUIRE_FALSE(body.invite.has_value());

    json output = body;
    REQUIRE_FALSE(output.contains("name"));
  }
}

TEST_CASE("client_server_json::AuthenticationData serialization",
          "[json_serialization]") {
  SECTION("With session") {
    json input = {{"type", "m.login.dummy"}, {"session", "abc123"}};
    auto auth = input.get<client_server_json::AuthenticationData>();
    REQUIRE(auth.type == "m.login.dummy");
    REQUIRE(auth.session.value() == "abc123");

    json output = auth;
    REQUIRE(output["type"] == "m.login.dummy");
    REQUIRE(output["session"] == "abc123");
  }

  SECTION("Without session") {
    json input = {{"type", "m.login.dummy"}};
    auto auth = input.get<client_server_json::AuthenticationData>();
    REQUIRE(auth.type == "m.login.dummy");
    REQUIRE_FALSE(auth.session.has_value());

    json output = auth;
    REQUIRE_FALSE(output.contains("session"));
  }
}

TEST_CASE("client_server_json::registration_body serialization",
          "[json_serialization]") {
  SECTION("Full body") {
    json input = {{"auth", {{"type", "m.login.dummy"}}},
                  {"device_id", "MYDEVICE"},
                  {"inhibit_login", false},
                  {"initial_device_display_name", "My Phone"},
                  {"password", "secret123"},
                  {"refresh_token", true},
                  {"username", "alice"}};

    auto body = input.get<client_server_json::registration_body>();
    REQUIRE(body.auth.has_value());
    REQUIRE(body.auth->type == "m.login.dummy");
    REQUIRE(body.device_id.value() == "MYDEVICE");
    REQUIRE(body.inhibit_login.value() == false);
    REQUIRE(body.initial_device_display_name.value() == "My Phone");
    REQUIRE(body.password.value() == "secret123");
    REQUIRE(body.refresh_token.value() == true);
    REQUIRE(body.username.value() == "alice");

    json output = body;
    REQUIRE(output["username"] == "alice");
    REQUIRE(output["password"] == "secret123");
  }

  SECTION("Minimal body") {
    json input = json::object();
    auto body = input.get<client_server_json::registration_body>();
    REQUIRE_FALSE(body.username.has_value());
    REQUIRE_FALSE(body.password.has_value());
  }
}

TEST_CASE("client_server_json::login_identifier serialization",
          "[json_serialization]") {
  SECTION("m.id.user") {
    json input = {{"type", "m.id.user"}, {"user", "alice"}};
    auto id = input.get<client_server_json::login_identifier>();
    REQUIRE(id.type == "m.id.user");
    REQUIRE(id.user.value() == "alice");
    REQUIRE_FALSE(id.medium.has_value());

    json output = id;
    REQUIRE(output["type"] == "m.id.user");
    REQUIRE(output["user"] == "alice");
  }

  SECTION("m.id.thirdparty") {
    json input = {
        {"type", "m.id.thirdparty"}, {"medium", "email"}, {"address", "a@b.c"}};
    auto id = input.get<client_server_json::login_identifier>();
    REQUIRE(id.type == "m.id.thirdparty");
    REQUIRE(id.medium.value() == "email");
    REQUIRE(id.address.value() == "a@b.c");

    json output = id;
    REQUIRE(output["medium"] == "email");
    REQUIRE(output["address"] == "a@b.c");
  }

  SECTION("m.id.phone") {
    json input = {
        {"type", "m.id.phone"}, {"country", "US"}, {"phone", "1234567890"}};
    auto id = input.get<client_server_json::login_identifier>();
    REQUIRE(id.type == "m.id.phone");
    REQUIRE(id.country.value() == "US");
    REQUIRE(id.phone.value() == "1234567890");

    json output = id;
    REQUIRE(output["country"] == "US");
    REQUIRE(output["phone"] == "1234567890");
  }
}

TEST_CASE("client_server_json::login_body serialization",
          "[json_serialization]") {
  SECTION("Password login") {
    json input = {{"type", "m.login.password"},
                  {"identifier", {{"type", "m.id.user"}, {"user", "alice"}}},
                  {"password", "secret"},
                  {"device_id", "DEV1"},
                  {"initial_device_display_name", "Phone"}};

    auto body = input.get<client_server_json::login_body>();
    REQUIRE(body.type == "m.login.password");
    REQUIRE(body.password.value() == "secret");
    REQUIRE(body.identifier->type == "m.id.user");
    REQUIRE(body.device_id.value() == "DEV1");

    json output = body;
    REQUIRE(output["type"] == "m.login.password");
    REQUIRE(output["password"] == "secret");
    REQUIRE(output["identifier"]["type"] == "m.id.user");
  }

  SECTION("Token login") {
    json input = {{"type", "m.login.token"}, {"token", "mytoken"}};
    auto body = input.get<client_server_json::login_body>();
    REQUIRE(body.type == "m.login.token");
    REQUIRE(body.token.value() == "mytoken");
  }
}

TEST_CASE("client_server_json::login_resp serialization",
          "[json_serialization]") {
  SECTION("Full response") {
    json input = {
        {"access_token", "syt_abc123"},    {"device_id", "DEVICEID"},
        {"user_id", "@alice:example.com"}, {"expires_in_ms", 3600000},
        {"home_server", "example.com"},    {"refresh_token", "ref_abc"}};

    auto resp = input.get<client_server_json::login_resp>();
    REQUIRE(resp.access_token == "syt_abc123");
    REQUIRE(resp.device_id == "DEVICEID");
    REQUIRE(resp.user_id == "@alice:example.com");
    REQUIRE(resp.expires_in_ms.value() == 3600000);
    REQUIRE(resp.home_server.value() == "example.com");
    REQUIRE(resp.refresh_token.value() == "ref_abc");

    json output = resp;
    REQUIRE(output["access_token"] == "syt_abc123");
    REQUIRE(output["device_id"] == "DEVICEID");
    REQUIRE(output["user_id"] == "@alice:example.com");
    REQUIRE(output["expires_in_ms"] == 3600000);
  }

  SECTION("Minimal response") {
    json input = {{"access_token", "tok"},
                  {"device_id", "DEV"},
                  {"user_id", "@bob:example.com"}};

    auto resp = input.get<client_server_json::login_resp>();
    REQUIRE(resp.access_token == "tok");
    REQUIRE_FALSE(resp.expires_in_ms.has_value());
    REQUIRE_FALSE(resp.home_server.has_value());
    REQUIRE_FALSE(resp.refresh_token.has_value());
    REQUIRE_FALSE(resp.well_known.has_value());
  }
}

TEST_CASE("client_server_json::registration_resp serialization",
          "[json_serialization]") {
  SECTION("Full response") {
    json input = {{"access_token", "syt_abc"},
                  {"device_id", "DEV"},
                  {"user_id", "@alice:example.com"},
                  {"expires_in_ms", 3600000},
                  {"refresh_token", "ref_abc"}};

    auto resp = input.get<client_server_json::registration_resp>();
    REQUIRE(resp.user_id == "@alice:example.com");
    REQUIRE(resp.access_token.value() == "syt_abc");
    REQUIRE(resp.device_id.value() == "DEV");
    REQUIRE(resp.expires_in_ms.value() == 3600000);

    json output = resp;
    REQUIRE(output["user_id"] == "@alice:example.com");
    REQUIRE(output["access_token"] == "syt_abc");
  }

  SECTION("Minimal response (inhibit_login)") {
    json input = {{"user_id", "@alice:example.com"}};
    auto resp = input.get<client_server_json::registration_resp>();
    REQUIRE(resp.user_id == "@alice:example.com");
    REQUIRE_FALSE(resp.access_token.has_value());
    REQUIRE_FALSE(resp.device_id.has_value());
  }
}

TEST_CASE("client_server_json::whoami_resp serialization",
          "[json_serialization]") {
  SECTION("With device_id") {
    json input = {{"user_id", "@alice:example.com"},
                  {"is_guest", false},
                  {"device_id", "MYDEVICE"}};

    auto resp = input.get<client_server_json::whoami_resp>();
    REQUIRE(resp.user_id == "@alice:example.com");
    REQUIRE(resp.is_guest == false);
    REQUIRE(resp.device_id.value() == "MYDEVICE");

    json output = resp;
    REQUIRE(output["user_id"] == "@alice:example.com");
    REQUIRE(output["is_guest"] == false);
    REQUIRE(output["device_id"] == "MYDEVICE");
  }

  SECTION("Guest without device_id") {
    json input = {{"user_id", "@guest:example.com"}, {"is_guest", true}};

    auto resp = input.get<client_server_json::whoami_resp>();
    REQUIRE(resp.is_guest == true);
    REQUIRE_FALSE(resp.device_id.has_value());

    json output = resp;
    REQUIRE_FALSE(output.contains("device_id"));
  }
}

TEST_CASE("client_server_json::JoinBody serialization",
          "[json_serialization]") {
  SECTION("With reason") {
    json input = {{"reason", "I want to join!"}};
    auto body = input.get<client_server_json::JoinBody>();
    REQUIRE(body.reason.value() == "I want to join!");

    json output = body;
    REQUIRE(output["reason"] == "I want to join!");
  }

  SECTION("Empty body") {
    json input = json::object();
    auto body = input.get<client_server_json::JoinBody>();
    REQUIRE_FALSE(body.reason.has_value());
    REQUIRE_FALSE(body.third_party_signed.has_value());
  }
}

TEST_CASE("client_server_json::well_known serialization",
          "[json_serialization]") {
  SECTION("Full well_known") {
    json input = {
        {"m.server", {{"base_url", "https://matrix.example.com"}}},
        {"m.identity_server", {{"base_url", "https://identity.example.com"}}}};

    auto wk = input.get<client_server_json::well_known>();
    REQUIRE(wk.m_server->base_url == "https://matrix.example.com");
    REQUIRE(wk.m_identity_server->base_url == "https://identity.example.com");

    json output = wk;
    REQUIRE(output["m.server"]["base_url"] == "https://matrix.example.com");
    REQUIRE(output["m.identity_server"]["base_url"] ==
            "https://identity.example.com");
  }
}

TEST_CASE("client_server_json::versions_obj serialization",
          "[json_serialization]") {
  SECTION("Round-trip") {
    json input = {{"versions", {"v1.10", "v1.11"}}};
    auto ver = input.get<client_server_json::versions_obj>();
    REQUIRE(ver.versions[0] == "v1.10");
    REQUIRE(ver.versions[1] == "v1.11");

    json output = ver;
    REQUIRE(output["versions"].size() == 2);
  }
}

TEST_CASE("client_server_json::LoginFlow serialization",
          "[json_serialization]") {
  SECTION("Round-trip") {
    json input = {{"type", "m.login.password"}, {"get_login_token", false}};
    auto flow = input.get<client_server_json::LoginFlow>();
    REQUIRE(flow.type == "m.login.password");
    REQUIRE(flow.get_login_token == false);

    json output = flow;
    REQUIRE(output["type"] == "m.login.password");
  }
}

TEST_CASE("client_server_json::GetLogin serialization",
          "[json_serialization]") {
  SECTION("Round-trip") {
    json input = {
        {"flows",
         {{{"type", "m.login.password"}, {"get_login_token", false}}}}};
    auto gl = input.get<client_server_json::GetLogin>();
    REQUIRE(gl.flows[0].type == "m.login.password");

    json output = gl;
    REQUIRE(output["flows"].size() == 1);
    REQUIRE(output["flows"][0]["type"] == "m.login.password");
  }
}

TEST_CASE("client_server_json::Invite3pid serialization",
          "[json_serialization]") {
  SECTION("Round-trip") {
    json input = {{"address", "alice@example.com"},
                  {"id_access_token", "tok123"},
                  {"id_server", "id.example.com"},
                  {"medium", "email"}};

    auto inv = input.get<client_server_json::Invite3pid>();
    REQUIRE(inv.address == "alice@example.com");
    REQUIRE(inv.id_access_token == "tok123");
    REQUIRE(inv.id_server == "id.example.com");
    REQUIRE(inv.medium == "email");

    json output = inv;
    REQUIRE(output["address"] == "alice@example.com");
    REQUIRE(output["medium"] == "email");
  }
}

TEST_CASE("client_server_json::incomplete_registration_resp serialization",
          "[json_serialization]") {
  SECTION("Round-trip") {
    json input = {{"session", "sess123"},
                  {"flows", {{{"stages", {"m.login.dummy"}}}}}};

    auto resp = input.get<client_server_json::incomplete_registration_resp>();
    REQUIRE(resp.session == "sess123");
    REQUIRE(resp.flows[0].stages[0] == "m.login.dummy");

    json output = resp;
    REQUIRE(output["session"] == "sess123");
    REQUIRE(output["flows"][0]["stages"][0] == "m.login.dummy");
  }
}

TEST_CASE("client_server_json::CreateRoomBody with power_level_override",
          "[json_serialization]") {
  SECTION("Power level override round-trip") {
    json input = {{"power_level_content_override",
                   {{"ban", 100},
                    {"events", {{"m.room.name", 100}}},
                    {"users", {{"@admin:example.com", 100}}}}}};

    auto body = input.get<client_server_json::CreateRoomBody>();
    REQUIRE(body.power_level_content_override.has_value());
    REQUIRE(body.power_level_content_override->ban.value() == 100);

    json output = body;
    REQUIRE(output["power_level_content_override"]["ban"] == 100);
  }
}

TEST_CASE("client_server_json::CreateRoomBody with invite_3pid",
          "[json_serialization]") {
  SECTION("3pid invite round-trip") {
    json input = {{"invite_3pid",
                   {{{"address", "a@b.c"},
                     {"id_access_token", "tok"},
                     {"id_server", "id.example.com"},
                     {"medium", "email"}}}}};

    auto body = input.get<client_server_json::CreateRoomBody>();
    REQUIRE(body.invite_3pid.has_value());
    REQUIRE(body.invite_3pid->size() == 1);
    REQUIRE(body.invite_3pid->at(0).address == "a@b.c");

    json output = body;
    REQUIRE(output["invite_3pid"][0]["address"] == "a@b.c");
  }
}

// ============================================================================
// Sync API types
// ============================================================================

TEST_CASE("client_server_json::SyncTimeline serialization",
          "[json_serialization]") {
  SECTION("Full timeline") {
    json input = {{"events", {{{"type", "m.room.message"}}}},
                  {"limited", true},
                  {"prev_batch", "s72594_4483_1934"}};

    auto tl = input.get<client_server_json::SyncTimeline>();
    REQUIRE(tl.events.size() == 1);
    REQUIRE(tl.limited == true);
    REQUIRE(tl.prev_batch.value() == "s72594_4483_1934");

    json output = tl;
    REQUIRE(output["events"].size() == 1);
    REQUIRE(output["limited"] == true);
    REQUIRE(output["prev_batch"] == "s72594_4483_1934");
  }

  SECTION("Defaults") {
    json input = {{"events", json::array()}};
    auto tl = input.get<client_server_json::SyncTimeline>();
    REQUIRE(tl.events.empty());
    REQUIRE(tl.limited == false);
    REQUIRE_FALSE(tl.prev_batch.has_value());
  }
}

TEST_CASE("client_server_json::SyncRoomState serialization",
          "[json_serialization]") {
  SECTION("Round-trip") {
    json input = {
        {"events", {{{"type", "m.room.create"}, {"state_key", ""}}}}};
    auto state = input.get<client_server_json::SyncRoomState>();
    REQUIRE(state.events.size() == 1);

    json output = state;
    REQUIRE(output["events"][0]["type"] == "m.room.create");
  }
}

TEST_CASE("client_server_json::SyncAccountData serialization",
          "[json_serialization]") {
  SECTION("Round-trip") {
    json input = {
        {"events",
         {{{"type", "m.push_rules"}, {"content", {{"global", json::object()}}}}}}};
    auto ad = input.get<client_server_json::SyncAccountData>();
    REQUIRE(ad.events.size() == 1);

    json output = ad;
    REQUIRE(output["events"][0]["type"] == "m.push_rules");
  }
}

TEST_CASE("client_server_json::UnreadNotificationCounts serialization",
          "[json_serialization]") {
  SECTION("Round-trip") {
    json input = {{"highlight_count", 3}, {"notification_count", 7}};
    auto unc = input.get<client_server_json::UnreadNotificationCounts>();
    REQUIRE(unc.highlight_count == 3);
    REQUIRE(unc.notification_count == 7);

    json output = unc;
    REQUIRE(output["highlight_count"] == 3);
    REQUIRE(output["notification_count"] == 7);
  }

  SECTION("Defaults to zero") {
    json input = json::object();
    auto unc = input.get<client_server_json::UnreadNotificationCounts>();
    REQUIRE(unc.highlight_count == 0);
    REQUIRE(unc.notification_count == 0);
  }
}

TEST_CASE("client_server_json::RoomSummary serialization",
          "[json_serialization]") {
  SECTION("Full summary") {
    json input = {{"m.heroes", {"@alice:example.com", "@bob:example.com"}},
                  {"m.joined_member_count", 5},
                  {"m.invited_member_count", 2}};
    auto rs = input.get<client_server_json::RoomSummary>();
    REQUIRE(rs.m_heroes->size() == 2);
    REQUIRE(rs.m_joined_member_count.value() == 5);
    REQUIRE(rs.m_invited_member_count.value() == 2);

    json output = rs;
    REQUIRE(output["m.heroes"].size() == 2);
    REQUIRE(output["m.joined_member_count"] == 5);
  }

  SECTION("Empty summary") {
    json input = json::object();
    auto rs = input.get<client_server_json::RoomSummary>();
    REQUIRE_FALSE(rs.m_heroes.has_value());
    REQUIRE_FALSE(rs.m_joined_member_count.has_value());
    REQUIRE_FALSE(rs.m_invited_member_count.has_value());

    json output = rs;
    REQUIRE_FALSE(output.contains("m.heroes"));
  }
}

TEST_CASE("client_server_json::DeviceLists serialization",
          "[json_serialization]") {
  SECTION("Full device lists") {
    json input = {{"changed", {"@alice:example.com", "@bob:example.com"}},
                  {"left", {"@charlie:example.com"}}};
    auto dl = input.get<client_server_json::DeviceLists>();
    REQUIRE(dl.changed.size() == 2);
    REQUIRE(dl.left.size() == 1);
    REQUIRE(dl.left[0] == "@charlie:example.com");

    json output = dl;
    REQUIRE(output["changed"].size() == 2);
    REQUIRE(output["left"].size() == 1);
  }

  SECTION("Empty device lists") {
    json input = json::object();
    auto dl = input.get<client_server_json::DeviceLists>();
    REQUIRE(dl.changed.empty());
    REQUIRE(dl.left.empty());
  }
}

TEST_CASE("client_server_json::SyncJoinedRoom serialization",
          "[json_serialization]") {
  SECTION("Minimal joined room") {
    json input = {
        {"timeline", {{"events", json::array()}}},
        {"state", {{"events", json::array()}}},
        {"account_data", {{"events", json::array()}}},
        {"ephemeral", {{"events", json::array()}}},
        {"unread_notifications",
         {{"highlight_count", 0}, {"notification_count", 0}}}};

    auto jr = input.get<client_server_json::SyncJoinedRoom>();
    REQUIRE(jr.timeline.events.empty());
    REQUIRE(jr.state.events.empty());
    REQUIRE_FALSE(jr.summary.has_value());

    json output = jr;
    REQUIRE(output["timeline"]["events"].empty());
  }
}

TEST_CASE("client_server_json::SyncInvitedRoom serialization",
          "[json_serialization]") {
  SECTION("With invite state") {
    json input = {
        {"invite_state",
         {{"events",
           {{{"type", "m.room.member"},
             {"content", {{"membership", "invite"}}}}}}}}};

    auto ir = input.get<client_server_json::SyncInvitedRoom>();
    REQUIRE(ir.invite_state.events.size() == 1);

    json output = ir;
    REQUIRE(output["invite_state"]["events"][0]["type"] == "m.room.member");
  }
}

TEST_CASE("client_server_json::SyncLeftRoom serialization",
          "[json_serialization]") {
  SECTION("Minimal left room") {
    json input = {{"timeline", {{"events", json::array()}}},
                  {"state", {{"events", json::array()}}},
                  {"account_data", {{"events", json::array()}}}};

    auto lr = input.get<client_server_json::SyncLeftRoom>();
    REQUIRE(lr.timeline.events.empty());
    REQUIRE(lr.state.events.empty());

    json output = lr;
    REQUIRE(output["timeline"]["events"].empty());
  }
}

TEST_CASE("client_server_json::SyncRooms serialization",
          "[json_serialization]") {
  SECTION("With joined, invited, and left rooms") {
    json input = {
        {"join",
         {{"!abc:example.com",
           {{"timeline", {{"events", json::array()}}},
            {"state", {{"events", json::array()}}},
            {"account_data", {{"events", json::array()}}},
            {"ephemeral", {{"events", json::array()}}},
            {"unread_notifications",
             {{"highlight_count", 0}, {"notification_count", 0}}}}}}},
        {"invite",
         {{"!def:example.com",
           {{"invite_state", {{"events", json::array()}}}}}}},
        {"leave",
         {{"!ghi:example.com",
           {{"timeline", {{"events", json::array()}}},
            {"state", {{"events", json::array()}}},
            {"account_data", {{"events", json::array()}}}}}}}};

    auto rooms = input.get<client_server_json::SyncRooms>();
    REQUIRE(rooms.join.size() == 1);
    REQUIRE(rooms.invite.size() == 1);
    REQUIRE(rooms.leave.size() == 1);
    REQUIRE(rooms.join.contains("!abc:example.com"));
    REQUIRE(rooms.invite.contains("!def:example.com"));
    REQUIRE(rooms.leave.contains("!ghi:example.com"));

    json output = rooms;
    REQUIRE(output["join"].size() == 1);
    REQUIRE(output["invite"].size() == 1);
    REQUIRE(output["leave"].size() == 1);
  }
}

TEST_CASE("client_server_json::SyncResponse serialization",
          "[json_serialization]") {
  SECTION("Minimal sync response") {
    json input = {
        {"next_batch", "s72594_4483_1934"},
        {"account_data", {{"events", json::array()}}},
        {"rooms",
         {{"join", json::object()},
          {"invite", json::object()},
          {"leave", json::object()}}},
        {"device_lists", {{"changed", json::array()}, {"left", json::array()}}},
        {"device_one_time_keys_count", {{"signed_curve25519", 50}}},
        {"device_unused_fallback_key_types", {"signed_curve25519"}}};

    auto resp = input.get<client_server_json::SyncResponse>();
    REQUIRE(resp.next_batch == "s72594_4483_1934");
    REQUIRE(resp.account_data.events.empty());
    REQUIRE(resp.rooms.join.empty());
    REQUIRE(resp.device_lists.changed.empty());
    REQUIRE(resp.device_one_time_keys_count.at("signed_curve25519") == 50);
    REQUIRE(resp.device_unused_fallback_key_types.size() == 1);

    json output = resp;
    REQUIRE(output["next_batch"] == "s72594_4483_1934");
    REQUIRE(output["device_one_time_keys_count"]["signed_curve25519"] == 50);
  }
}

// ============================================================================
// capabilities types
// ============================================================================

TEST_CASE("client_server_json::capabilities_obj serialization",
          "[json_serialization]") {
  SECTION("With room versions") {
    json input = {{"m.room_versions",
                   {{"default", "11"},
                    {"available", {{"1", "stable"}, {"11", "stable"}}}}}};

    auto caps = input.get<client_server_json::capabilities_obj>();
    REQUIRE(caps.room_versions.has_value());
    REQUIRE(caps.room_versions->default_ == "11");
    REQUIRE(caps.room_versions->available.at("1") == "stable");

    json output = caps;
    REQUIRE(output["m.room_versions"]["default"] == "11");
    REQUIRE(output["m.room_versions"]["available"]["11"] == "stable");
  }

  SECTION("With boolean capabilities") {
    json input = {{"m.change_password", {{"enabled", true}}},
                  {"m.set_displayname", {{"enabled", false}}}};

    auto caps = input.get<client_server_json::capabilities_obj>();
    REQUIRE(caps.change_password->enabled == true);
    REQUIRE(caps.set_displayname->enabled == false);

    json output = caps;
    REQUIRE(output["m.change_password"]["enabled"] == true);
    REQUIRE(output["m.set_displayname"]["enabled"] == false);
  }

  SECTION("Empty capabilities") {
    json input = json::object();
    auto caps = input.get<client_server_json::capabilities_obj>();
    REQUIRE_FALSE(caps.room_versions.has_value());
    REQUIRE_FALSE(caps.change_password.has_value());
  }
}

// ============================================================================
// server_server_json::DirectoryQueryResp
// ============================================================================

TEST_CASE("server_server_json::DirectoryQueryResp serialization",
          "[json_serialization]") {
  SECTION("Round-trip") {
    json input = {{"room_id", "!abc:example.com"},
                  {"servers", {"example.com", "other.com"}}};

    auto resp = input.get<server_server_json::DirectoryQueryResp>();
    REQUIRE(resp.room_id == "!abc:example.com");
    REQUIRE(resp.servers.size() == 2);

    json output = resp;
    REQUIRE(output["room_id"] == "!abc:example.com");
    REQUIRE(output["servers"].size() == 2);
  }

  SECTION("Empty servers") {
    json input = {{"room_id", "!xyz:example.com"}, {"servers", json::array()}};

    auto resp = input.get<server_server_json::DirectoryQueryResp>();
    REQUIRE(resp.room_id == "!xyz:example.com");
    REQUIRE(resp.servers.empty());
  }
}
