// Placeholder for now
#include "nlohmann/json.hpp"
#include "snitch/snitch_matcher.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"

#include <algorithm>
#include <drogon/HttpTypes.h>
#include <fstream>
#include <snitch/snitch.hpp>
#include <vector>

using json = nlohmann::json;

TEST_CASE("Json signatures are added", "[json_signing]") {
  // Ensure we have a key to sign with
  auto server_key = json_utils::generate_server_key();
  auto private_key = std::get<1>(server_key);
  std::vector<unsigned char> private_key_vec(private_key.begin(),
                                             private_key.end());

  SECTION("Doesn't sign null") {
    auto json_data = json{};
    REQUIRE_THROWS_MATCHES(
        json_utils::sign_json("test", "test", private_key_vec, json_data),
        std::runtime_error,
        snitch::matchers::with_what_contains{
            "Json data is null which is impossible for an event"});
  }

  SECTION("Simple signing") {
    auto json_data = json(json::value_t::object);
    auto signed_json =
        json_utils::sign_json("test", "test", private_key_vec, json_data);
    REQUIRE(signed_json.is_object());
    REQUIRE(signed_json.contains("signatures"));
    REQUIRE(signed_json["signatures"].is_object());
    REQUIRE(signed_json["signatures"].contains("test"));
    REQUIRE(signed_json["signatures"]["test"].is_object());
    REQUIRE(signed_json["signatures"]["test"].contains("ed25519:test"));
    REQUIRE(signed_json["signatures"]["test"]["ed25519:test"].is_string());
  }
}

TEST_CASE("Incorrect IDs are properly migrated", "[user_id_migration]") {
  SECTION("Uppercase") {
    auto user_id = "Test";
    auto expected = "test";

    auto real = migrate_localpart(user_id);

    REQUIRE(expected == real);
  }

  SECTION("Preserves special chars") {
    auto user_id = "Test[]_";
    auto expected = "test[]__";

    auto real = migrate_localpart(user_id);

    REQUIRE(expected == real);
  }

  SECTION("Preserves special chars and fails as invalid") {
    auto user_id = "Test!\":?\\@[]{|}£é\n'";
    auto expected = "test!\":?\\@[]{|}£é\n'";

    auto real = migrate_localpart(user_id);
    auto result = is_valid_localpart(real, "localhost");

    REQUIRE(expected == real);
    REQUIRE_FALSE(result);
  }

  SECTION("Works with valid usernames") {
    auto user_id = "test";
    auto expected = "test";

    auto real = migrate_localpart(user_id);
    auto result = is_valid_localpart(real, "localhost");

    REQUIRE(expected == real);
    REQUIRE(result);
  }
}

TEST_CASE("Parse Query Parameter String into Map", "[query_param_parsing]") {
  SECTION("Single key with multiple values") {
    std::string queryString = "key=1&key=2&key=3";
    auto paramMap = parseQueryParamString(queryString);

    REQUIRE(paramMap["key"].size() == static_cast<const unsigned long>(3));
    REQUIRE(paramMap["key"][0] == "1");
    REQUIRE(paramMap["key"][1] == "2");
    REQUIRE(paramMap["key"][2] == "3");
  }

  SECTION("Multiple keys with single value each") {
    std::string queryString = "id=123&name=John&age=30";
    auto paramMap = parseQueryParamString(queryString);

    REQUIRE(paramMap["id"].size() == static_cast<const unsigned long>(1));
    REQUIRE(paramMap["name"].size() == static_cast<const unsigned long>(1));
    REQUIRE(paramMap["age"].size() == static_cast<const unsigned long>(1));
    REQUIRE(paramMap["id"][0] == "123");
    REQUIRE(paramMap["name"][0] == "John");
    REQUIRE(paramMap["age"][0] == "30");
  }

  SECTION("Empty query string") {
    std::string queryString = "";
    auto paramMap = parseQueryParamString(queryString);

    REQUIRE(paramMap.empty());
  }

  SECTION("Query string with no values") {
    std::string queryString = "key1=&key2=";
    auto paramMap = parseQueryParamString(queryString);

    REQUIRE(paramMap["key1"].size() == static_cast<const unsigned long>(0));
    REQUIRE(paramMap["key2"].size() == static_cast<const unsigned long>(0));
  }

  SECTION("Single key-value pair") {
    std::string queryString = "key=value";
    auto paramMap = parseQueryParamString(queryString);

    REQUIRE(paramMap.size() == static_cast<const unsigned long>(1));
    REQUIRE(paramMap["key"].size() == static_cast<const unsigned long>(1));
    REQUIRE(paramMap["key"][0] == "value");
  }
}

TEST_CASE("Generate HTTP Query Parameter String", "[query_param_generation]") {
  SECTION("Empty values vector") {
    std::vector<std::string> values = {};
    std::string keyName = "test";
    std::string expected = "?test=";

    std::string result = generateQueryParamString(keyName, values);

    REQUIRE(result == expected);
  }

  SECTION("Single value") {
    std::vector<std::string> values = {"value1"};
    std::string keyName = "test";
    std::string expected = "?test=value1";

    std::string result = generateQueryParamString(keyName, values);

    REQUIRE(result == expected);
  }

  SECTION("Multiple values") {
    std::vector<std::string> values = {"value1", "value2", "value3"};
    std::string keyName = "test";
    std::string expected = "?test=value1&test=value2&test=value3";

    std::string result = generateQueryParamString(keyName, values);

    REQUIRE(result == expected);
  }

  SECTION("Key with special characters") {
    std::vector<std::string> values = {"val ue1", "val&ue2"};
    std::string keyName = "te!@st";
    std::string expected = "?te!@st=val+ue1&te!@st=val%26ue2";

    std::string result = generateQueryParamString(keyName, values);

    REQUIRE(result == expected);
  }
}

TEST_CASE("Signing Key", "[signing_keys]") {
  SECTION("Can ensure there is a signing key") {
    const auto *const config_file = R"(
---
database:
  host: localhost
  port: 5432
  database_name: postgres
  user: postgres
  password: mysecretpassword
matrix:
  server_name: localhost
  server_key_location: ./server_key.key
webserver:
  ssl: false
rabbitmq:
  host: localhost
  port: 5672
  )";

    // Write file to disk for testing
    std::ofstream file("config.yaml");
    file << config_file;
    file.close();

    // Test loading the config
    const Config config{};

    // Test ensuring the server key exists
    json_utils::ensure_server_keys(config);

    // Check if the file exists now
    std::ifstream keyfile(config.matrix_config.server_key_location);
    REQUIRE(keyfile.good());
    keyfile.close();
  }

  SECTION("Can load the server key") {
    const auto *const config_file = R"(
---
database:
  host: localhost
  port: 5432
  database_name: postgres
  user: postgres
  password: mysecretpassword
matrix:
  server_name: localhost
  server_key_location: ./server_key.key
webserver:
  ssl: false
rabbitmq:
  host: localhost
  port: 5672
  )";

    // Write file to disk for testing
    std::ofstream file("config.yaml");
    file << config_file;
    file.close();

    // Test loading the config
    const Config config{};

    json_utils::ensure_server_keys(config);

    // Test loading the keys
    const auto [private_key, public_key_base64, key_id, key_type] =
        get_verify_key_data(config);

    REQUIRE(!key_id.empty());
    REQUIRE(!key_type.empty());
    REQUIRE(!public_key_base64.empty());
    REQUIRE(!private_key.empty());
  }
}

TEST_CASE("Base64", "[base64]") {
  SECTION("Can encode and decode base64") {
    const auto data = std::vector<unsigned char>{'t', 'e', 's', 't'};
    const auto encoded = json_utils::base64_key(data);
    const auto decoded = json_utils::unbase64_key(encoded);

    REQUIRE(std::equal(data.begin(), data.end(), decoded.begin()));
  }
}

TEST_CASE("Matrix IDs", "[matrix_ids]") {
  SECTION("Can generate a valid looking room_id") {
    const auto room_id = generate_room_id("example.com");

    // Check if room_id contains the server name after the ':' character
    REQUIRE(room_id.find("example.com") != std::string::npos);

    // Check if the room_id starts with '!'
    REQUIRE(room_id[0] == '!');

    // Check if the string between '!' and ':' is not empty and contains only
    // alphanumeric characters
    REQUIRE(room_id.substr(1, room_id.find(':') - 1)
                .find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
                                   "RSTUVWXYZ0123456789") == std::string::npos);
  }

  SECTION("Ensures a room_id is never exceeding 255 bytes despite "
          "server_name") {
    const std::string server_name =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com";

    // Require that the server_name is less than 250 bytes
    REQUIRE(server_name.length() < 253);

    const auto room_id = generate_room_id(server_name);

    REQUIRE(room_id.length() <= 255);

    // Ensure its valid still

    // Check if room_id contains the server name after the ':' character
    REQUIRE(room_id.find(server_name) != std::string::npos);

    // Check if the room_id starts with '!'
    REQUIRE(room_id[0] == '!');

    // Check if the string between '!' and ':' is not empty and contains only
    // alphanumeric characters
    REQUIRE(room_id.substr(1, room_id.find(':') - 1)
                .find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
                                   "RSTUVWXYZ0123456789") == std::string::npos);
  }

  SECTION("Does warn about empty server_name") {
    REQUIRE_THROWS_MATCHES(
        generate_room_id(""), std::invalid_argument,
        snitch::matchers::with_what_contains{
            "Missing server_name when generating room_id. Please contact the "
            "developers if you see this message."});
  }

  SECTION("Can get server_name from various room_ids") {
    REQUIRE(get_serverpart("!test:example.com") == "example.com");
    REQUIRE(get_serverpart("!test:127.0.0.1") == "127.0.0.1");
    REQUIRE(get_serverpart("!test:[::1]") == "[::1]");
  }

  SECTION("Can remove brackets from IPV6 server_name") {
    REQUIRE(remove_brackets("[::1]") == "::1");
  }

  SECTION("Can get localpart of various user IDs") {
    REQUIRE(localpart("@test:example.com") == "test");
    REQUIRE(localpart("@test:127.0.0.1") == "test");
    REQUIRE(localpart("@test:[::1]") == "test");
  }
}

TEST_CASE("Passwords", "[passwords]") {
  SECTION("Can hash and verify password") {
    const auto original_password = "test";

    const auto password_hash = hash_password(original_password);

    REQUIRE(!password_hash.empty());

    REQUIRE(verify_hashed_password(password_hash, original_password));
  }
}

TEST_CASE("Misc Tests", "[misc]") {
  SECTION("Basic base62 encoding") {
    const auto *const expected = "3bj";
    constexpr unsigned long input = 12233;
    const auto result = base62_encode(input);

    REQUIRE(expected == result);
  }

  SECTION("Drogon method to string") {
    REQUIRE_THAT(drogon_to_string_method(drogon::HttpMethod::Get),
                 snitch::matchers::contains_substring("GET"));
    REQUIRE_THAT(drogon_to_string_method(drogon::HttpMethod::Post),
                 snitch::matchers::contains_substring("POST"));
    REQUIRE_THAT(drogon_to_string_method(drogon::HttpMethod::Head),
                 snitch::matchers::contains_substring("HEAD"));
    REQUIRE_THAT(drogon_to_string_method(drogon::HttpMethod::Put),
                 snitch::matchers::contains_substring("PUT"));
    REQUIRE_THAT(drogon_to_string_method(drogon::HttpMethod::Delete),
                 snitch::matchers::contains_substring("DELETE"));
    REQUIRE_THAT(drogon_to_string_method(drogon::HttpMethod::Options),
                 snitch::matchers::contains_substring("OPTIONS"));
    REQUIRE_THAT(drogon_to_string_method(drogon::HttpMethod::Patch),
                 snitch::matchers::contains_substring("PATCH"));
    REQUIRE_THAT(drogon_to_string_method(drogon::HttpMethod::Invalid),
                 snitch::matchers::contains_substring("INVALID"));
  }
}