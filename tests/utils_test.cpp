// Placeholder for now
#include "nlohmann/json.hpp"
#include "snitch/snitch_matcher.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"

#include <algorithm>
#include <drogon/HttpTypes.h>
#include <drogon/utils/coroutine.h>
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

  SECTION("Preserves unsigned when signing") {
    auto json_data = json(json::value_t::object);
    json_data["unsigned"] = {{"test", "test"}};
    auto signed_json =
        json_utils::sign_json("test", "test", private_key_vec, json_data);
    REQUIRE(signed_json.is_object());
    REQUIRE(signed_json.contains("signatures"));
    REQUIRE(signed_json["signatures"].is_object());
    REQUIRE(signed_json["signatures"].contains("test"));
    REQUIRE(signed_json["signatures"]["test"].is_object());
    REQUIRE(signed_json["signatures"]["test"].contains("ed25519:test"));
    REQUIRE(signed_json["signatures"]["test"]["ed25519:test"].is_string());
    REQUIRE(signed_json.contains("unsigned"));
    REQUIRE(signed_json["unsigned"].is_object());
    REQUIRE(signed_json["unsigned"].contains("test"));
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

    REQUIRE(paramMap["key"].size() == static_cast<unsigned long>(3));
    REQUIRE(paramMap["key"][0] == "1");
    REQUIRE(paramMap["key"][1] == "2");
    REQUIRE(paramMap["key"][2] == "3");
  }

  SECTION("Multiple keys with single value each") {
    std::string queryString = "id=123&name=John&age=30";
    auto paramMap = parseQueryParamString(queryString);

    REQUIRE(paramMap["id"].size() == static_cast<unsigned long>(1));
    REQUIRE(paramMap["name"].size() == static_cast<unsigned long>(1));
    REQUIRE(paramMap["age"].size() == static_cast<unsigned long>(1));
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

    REQUIRE(paramMap["key1"].size() == static_cast<unsigned long>(0));
    REQUIRE(paramMap["key2"].size() == static_cast<unsigned long>(0));
  }

  SECTION("Single key-value pair") {
    std::string queryString = "key=value";
    auto paramMap = parseQueryParamString(queryString);

    REQUIRE(paramMap.size() == static_cast<unsigned long>(1));
    REQUIRE(paramMap["key"].size() == static_cast<unsigned long>(1));
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
  )";

    // Delete key to ensure it doesn't exist yet
    std::filesystem::remove("./server_key.key");

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
    const auto encoded = json_utils::base64_urlencoded(data);
    const auto decoded = json_utils::unbase64_key(encoded);

    REQUIRE(std::equal(data.begin(), data.end(), decoded.begin()));
  }
}

TEST_CASE("Matrix IDs", "[matrix_ids]") {
  SECTION("Can generate a valid looking room_id") {
    const auto room_id = generate_room_id("example.com");

    // Check if room_id contains the server name after the ':' character
    REQUIRE(room_id.find("example.com") != std::string_view::npos);

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

  SECTION("CRC32") {
    const auto *const input = "Test";
    constexpr auto expected = 2018365746;
    const auto result = crc32_helper(input);

    REQUIRE_THAT(result, snitch::matchers::is_any_of<int, 1>(expected));
  }

  SECTION("server-server auth header") {
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
  )";

    // Delete key to ensure it doesn't exist yet
    std::filesystem::remove("./server_key.key");

    // Write file to disk for testing
    std::ofstream file("config.yaml");
    file << config_file;
    file.close();

    // Test loading the config
    const Config config{};

    // Test ensuring the server key exists
    json_utils::ensure_server_keys(config);

    const auto key_data = get_verify_key_data(config);

    const auto header =
        generate_ss_authheader({.server_name = config.matrix_config.server_name,
                                .key_id = key_data.key_id,
                                .secret_key = key_data.private_key,
                                .method = "GET",
                                .request_uri = "/_matrix/federation/v1/version",
                                .origin = "localhost",
                                .target = "example.com",
                                .content = json{{"test", "test"}}});

    LOG_DEBUG << "FED_HEADER: " << header;

    REQUIRE_THAT(header, snitch::matchers::contains_substring("X-Matrix"));
  }
}

// ============================================================================
// parse_xmatrix_header tests
// ============================================================================

TEST_CASE("parse_xmatrix_header", "[xmatrix_header]") {
  SECTION("Valid header") {
    auto result = parse_xmatrix_header(
        R"(X-Matrix origin="server.name",destination="our.server",key="ed25519:abc123",sig="base64sig")");
    REQUIRE(result.has_value());
    REQUIRE(result->origin == "server.name");
    REQUIRE(result->destination == "our.server");
    REQUIRE(result->key_id == "ed25519:abc123");
    REQUIRE(result->signature == "base64sig");
  }

  SECTION("Missing X-Matrix prefix") {
    auto result = parse_xmatrix_header(
        R"(Bearer origin="server.name",key="ed25519:abc",sig="sig")");
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("Empty string") {
    auto result = parse_xmatrix_header("");
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("Missing origin") {
    auto result = parse_xmatrix_header(
        R"(X-Matrix destination="our.server",key="ed25519:abc",sig="sig")");
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("Missing destination") {
    auto result = parse_xmatrix_header(
        R"(X-Matrix origin="server.name",key="ed25519:abc",sig="sig")");
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("Missing key") {
    auto result = parse_xmatrix_header(
        R"(X-Matrix origin="server.name",destination="our.server",sig="sig")");
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("Missing sig") {
    auto result = parse_xmatrix_header(
        R"(X-Matrix origin="server.name",destination="our.server",key="ed25519:abc")");
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("With leading/trailing whitespace") {
    auto result = parse_xmatrix_header(
        R"(  X-Matrix origin="a",destination="b",key="k",sig="s"  )");
    REQUIRE(result.has_value());
    REQUIRE(result->origin == "a");
    REQUIRE(result->destination == "b");
  }
}

// ============================================================================
// to_lower tests
// ============================================================================

TEST_CASE("to_lower", "[string_utils]") {
  SECTION("ASCII uppercase") {
    REQUIRE(to_lower("HELLO") == "hello");
  }

  SECTION("Already lowercase") {
    REQUIRE(to_lower("hello") == "hello");
  }

  SECTION("Mixed case") {
    REQUIRE(to_lower("HeLLo WoRLd") == "hello world");
  }

  SECTION("Empty string") {
    REQUIRE(to_lower("") == "");
  }

  SECTION("Numbers and special chars unchanged") {
    REQUIRE(to_lower("Test123!@#") == "test123!@#");
  }
}

// ============================================================================
// check_if_ip_address tests
// ============================================================================

TEST_CASE("check_if_ip_address", "[ip_detection]") {
  SECTION("IPv4 address") {
    REQUIRE(check_if_ip_address("127.0.0.1"));
    REQUIRE(check_if_ip_address("192.168.1.1"));
    REQUIRE(check_if_ip_address("0.0.0.0"));
  }

  SECTION("IPv6 address") {
    REQUIRE(check_if_ip_address("::1"));
    REQUIRE(check_if_ip_address("::"));
    REQUIRE(check_if_ip_address("fe80::1"));
    // Full 128-bit IPv6 addresses (regression: previously overflowed a
    // sockaddr_in.sin_addr buffer since inet_pton AF_INET6 writes 16 bytes)
    REQUIRE(check_if_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    REQUIRE(check_if_ip_address("fd00::1"));
  }

  SECTION("Not an IP address") {
    REQUIRE_FALSE(check_if_ip_address("example.com"));
    REQUIRE_FALSE(check_if_ip_address("localhost"));
    REQUIRE_FALSE(check_if_ip_address("not-an-ip"));
  }

  SECTION("Empty string") {
    REQUIRE_FALSE(check_if_ip_address(""));
  }
}

// ============================================================================
// is_valid_localpart tests
// ============================================================================

TEST_CASE("is_valid_localpart", "[localpart_validation]") {
  SECTION("Valid localparts") {
    REQUIRE(is_valid_localpart("alice", "example.com"));
    REQUIRE(is_valid_localpart("alice.bob", "example.com"));
    REQUIRE(is_valid_localpart("alice-bob", "example.com"));
    REQUIRE(is_valid_localpart("alice_bob", "example.com"));
    REQUIRE(is_valid_localpart("alice/bob", "example.com"));
    REQUIRE(is_valid_localpart("alice+bob", "example.com"));
    REQUIRE(is_valid_localpart("alice=bob", "example.com"));
    REQUIRE(is_valid_localpart("1234567890", "example.com"));
  }

  SECTION("Invalid localparts") {
    REQUIRE_FALSE(is_valid_localpart("Alice", "example.com")); // uppercase
    REQUIRE_FALSE(is_valid_localpart("alice bob", "example.com")); // space
    REQUIRE_FALSE(is_valid_localpart("alice@bob", "example.com")); // @
    REQUIRE_FALSE(is_valid_localpart("alice:bob", "example.com")); // colon
  }

  SECTION("Length limit (255 bytes for full user_id)") {
    // @localpart:server_name must be <= 255
    // With server_name "example.com" (11 chars), localpart can be at most
    // 255 - 1(@) - 1(:) - 11 = 242 chars
    std::string long_localpart(242, 'a');
    REQUIRE(is_valid_localpart(long_localpart, "example.com"));

    std::string too_long_localpart(243, 'a');
    REQUIRE_FALSE(is_valid_localpart(too_long_localpart, "example.com"));
  }
}

// ============================================================================
// random_string tests
// ============================================================================

TEST_CASE("random_string", "[random]") {
  SECTION("Correct length") {
    auto str = random_string(16);
    REQUIRE(str.length() == 16);
  }

  SECTION("Only alphanumeric characters") {
    auto str = random_string(100);
    for (auto c : str) {
      REQUIRE(std::isalnum(static_cast<unsigned char>(c)));
    }
  }

  SECTION("Zero length") {
    auto str = random_string(0);
    REQUIRE(str.empty());
  }

  SECTION("Two random strings are different") {
    auto a = random_string(32);
    auto b = random_string(32);
    // Extremely unlikely to be equal
    REQUIRE(a != b);
  }
}

// ============================================================================
// get_serverpart error case
// ============================================================================

TEST_CASE("get_serverpart error", "[matrix_ids]") {
  SECTION("No colon throws") {
    REQUIRE_THROWS_MATCHES(get_serverpart("nocolon"), std::runtime_error,
                           snitch::matchers::with_what_contains{
                               "Invalid Input"});
  }
}

// ============================================================================
// get_default_pushrules tests
// ============================================================================

TEST_CASE("get_default_pushrules", "[pushrules]") {
  SECTION("Has correct structure") {
    auto rules = get_default_pushrules("@alice:example.com");
    REQUIRE(rules.contains("global"));
    REQUIRE(rules["global"].contains("content"));
    REQUIRE(rules["global"].contains("override"));
    REQUIRE(rules["global"].contains("room"));
    REQUIRE(rules["global"].contains("sender"));
    REQUIRE(rules["global"].contains("underride"));
  }

  SECTION("Content rule contains user localpart") {
    auto rules = get_default_pushrules("@alice:example.com");
    auto content = rules["global"]["content"];
    REQUIRE(content.size() == 1);
    REQUIRE(content[0]["pattern"] == "alice");
    REQUIRE(content[0]["rule_id"] == ".m.rule.contains_user_name");
  }

  SECTION("Override rules") {
    auto rules = get_default_pushrules("@alice:example.com");
    auto override_rules = rules["global"]["override"];
    REQUIRE(override_rules.size() == 2);
    REQUIRE(override_rules[0]["rule_id"] == ".m.rule.master");
    REQUIRE(override_rules[1]["rule_id"] == ".m.rule.suppress_notices");
  }

  SECTION("Underride rules") {
    auto rules = get_default_pushrules("@alice:example.com");
    auto underride = rules["global"]["underride"];
    REQUIRE(underride.size() == 6);
    REQUIRE(underride[0]["rule_id"] == ".m.rule.call");
    REQUIRE(underride[3]["rule_id"] == ".m.rule.invite_for_me");
    // invite_for_me should reference the user_id
    bool found_user_pattern = false;
    for (const auto &cond : underride[3]["conditions"]) {
      if (cond.contains("pattern") && cond["pattern"] == "@alice:example.com") {
        found_user_pattern = true;
      }
    }
    REQUIRE(found_user_pattern);
  }
}

// ============================================================================
// Additional base64 and signature tests (json_utils)
// ============================================================================

TEST_CASE("base64_std_unpadded", "[base64]") {
  SECTION("Encode and decode round-trip") {
    const auto data =
        std::vector<unsigned char>{'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o',
                                   'r', 'l', 'd'};
    const auto encoded = json_utils::base64_std_unpadded(data);
    // Standard base64 unpadded of "hello world" = "aGVsbG8gd29ybGQ"
    REQUIRE(encoded == "aGVsbG8gd29ybGQ");
  }
}

TEST_CASE("decode_base64", "[base64]") {
  SECTION("Empty input") {
    auto result = json_utils::decode_base64("");
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("URL-safe base64") {
    // Encode some data with url-safe variant, then decode
    const auto data = std::vector<unsigned char>{0xFF, 0xFE, 0xFD};
    const auto encoded = json_utils::base64_urlencoded(data);
    auto decoded = json_utils::decode_base64(encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->size() == 3);
    REQUIRE((*decoded)[0] == 0xFF);
    REQUIRE((*decoded)[1] == 0xFE);
    REQUIRE((*decoded)[2] == 0xFD);
  }

  SECTION("Standard base64") {
    // Encode with standard variant, then decode
    const auto data = std::vector<unsigned char>{'t', 'e', 's', 't'};
    const auto encoded = json_utils::base64_std_unpadded(data);
    auto decoded = json_utils::decode_base64(encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->size() == 4);
    REQUIRE(std::equal(data.begin(), data.end(), decoded->begin()));
  }

  SECTION("Invalid base64") {
    auto result = json_utils::decode_base64("!!!invalid!!!");
    REQUIRE_FALSE(result.has_value());
  }
}

TEST_CASE("verify_signature", "[crypto]") {
  SECTION("Sign and verify round-trip") {
    // Generate a key pair
    auto [public_key, secret_key] = json_utils::generate_server_key();

    // Create a message and sign it
    std::vector<unsigned char> sk_vec(secret_key.begin(), secret_key.end());
    auto json_data = json{{"test", "data"}};
    auto signed_json =
        json_utils::sign_json("server", "keyid", sk_vec, json_data);

    // Extract the signature
    auto sig_b64 = signed_json["signatures"]["server"]["ed25519:keyid"]
                       .get<std::string>();

    // Get the public key as base64
    std::vector<unsigned char> pk_vec(public_key.begin(), public_key.end());
    auto pk_b64 = json_utils::base64_std_unpadded(pk_vec);

    // Get the canonical JSON (without signatures and unsigned)
    auto to_verify = signed_json;
    to_verify.erase("signatures");
    to_verify.erase("unsigned");
    auto canonical = to_verify.dump();

    REQUIRE(json_utils::verify_signature(pk_b64, sig_b64, canonical));
  }

  SECTION("Invalid signature fails") {
    auto [public_key, secret_key] = json_utils::generate_server_key();
    std::vector<unsigned char> pk_vec(public_key.begin(), public_key.end());
    auto pk_b64 = json_utils::base64_std_unpadded(pk_vec);

    REQUIRE_FALSE(
        json_utils::verify_signature(pk_b64, "invalidsignature", "message"));
  }

  SECTION("Wrong key fails") {
    // Generate two key pairs
    auto [pk1, sk1] = json_utils::generate_server_key();
    auto [pk2, sk2] = json_utils::generate_server_key();

    // Sign with key 1
    std::vector<unsigned char> sk1_vec(sk1.begin(), sk1.end());
    auto json_data = json{{"data", "test"}};
    auto signed_json =
        json_utils::sign_json("server", "key", sk1_vec, json_data);
    auto sig = signed_json["signatures"]["server"]["ed25519:key"]
                   .get<std::string>();

    // Verify with key 2 (should fail)
    std::vector<unsigned char> pk2_vec(pk2.begin(), pk2.end());
    auto pk2_b64 = json_utils::base64_std_unpadded(pk2_vec);

    auto to_verify = signed_json;
    to_verify.erase("signatures");
    to_verify.erase("unsigned");

    REQUIRE_FALSE(
        json_utils::verify_signature(pk2_b64, sig, to_verify.dump()));
  }

  SECTION("Wrong message fails") {
    auto [public_key, secret_key] = json_utils::generate_server_key();
    std::vector<unsigned char> sk_vec(secret_key.begin(), secret_key.end());
    auto json_data = json{{"data", "original"}};
    auto signed_json =
        json_utils::sign_json("server", "key", sk_vec, json_data);
    auto sig = signed_json["signatures"]["server"]["ed25519:key"]
                   .get<std::string>();

    std::vector<unsigned char> pk_vec(public_key.begin(), public_key.end());
    auto pk_b64 = json_utils::base64_std_unpadded(pk_vec);

    // Verify against different message
    REQUIRE_FALSE(json_utils::verify_signature(
        pk_b64, sig, R"({"data":"tampered"})"));
  }
}

TEST_CASE("sign_json error cases", "[json_signing]") {
  SECTION("Empty secret key") {
    std::vector<unsigned char> empty_key;
    auto json_data = json{{"test", "data"}};
    REQUIRE_THROWS_MATCHES(
        json_utils::sign_json("server", "key", empty_key, json_data),
        std::runtime_error,
        snitch::matchers::with_what_contains{"Secret key is empty"});
  }
}
