// Placeholder for now
#include "nlohmann/json.hpp"
#include "utils/json_utils.hpp"
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