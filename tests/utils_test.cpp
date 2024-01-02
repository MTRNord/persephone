// Placeholder for now
#include "nlohmann/json.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include <snitch/snitch.hpp>
#include <vector>

using json = nlohmann::json;

TEST_CASE("Json signatures are added", "[json_signing]") {
  // Ensure we have a key to sign with
  auto server_key = json_utils::generate_server_key();
  auto private_key = std::get<1>(server_key);
  std::vector<unsigned char> private_key_vec(private_key.begin(),
                                             private_key.end());

  std::cout << "test" << '\n';

  SECTION("Doesn't sign null") {
    auto json_data = json{};
    REQUIRE_THROWS_AS(
        json_utils::sign_json("test", "test", private_key_vec, json_data),
        json::type_error);
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
    auto user_id = "Test[]";
    auto expected = "test[]";

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

    REQUIRE(paramMap["key"].size() == 3);
    REQUIRE(paramMap["key"][0] == "1");
    REQUIRE(paramMap["key"][1] == "2");
    REQUIRE(paramMap["key"][2] == "3");
  }

  SECTION("Multiple keys with single value each") {
    std::string queryString = "id=123&name=John&age=30";
    auto paramMap = parseQueryParamString(queryString);

    REQUIRE(paramMap["id"].size() == 1);
    REQUIRE(paramMap["name"].size() == 1);
    REQUIRE(paramMap["age"].size() == 1);
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

    REQUIRE(paramMap["key1"].size() == 0);
    REQUIRE(paramMap["key2"].size() == 0);
  }

  SECTION("Single key-value pair") {
    std::string queryString = "key=value";
    auto paramMap = parseQueryParamString(queryString);

    REQUIRE(paramMap.size() == 1);
    REQUIRE(paramMap["key"].size() == 1);
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
