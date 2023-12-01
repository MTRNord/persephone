#include "utils.hpp"
#include "sodium.h"
#include "webserver/json.hpp"
#include <format>
#include <map>
#include <nlohmann/json.hpp>
#include <random>
#include <utility>
#include <zlib.h>

void return_error(std::function<void(const HttpResponsePtr &)> const &callback,
                  std::string errorcode, std::string error, int status_code) {
  generic_json::generic_json_error json_error{std::move(errorcode),
                                              std::move(error)};
  json j = json_error;
  auto resp = HttpResponse::newHttpResponse();
  resp->setBody(j.dump());
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  resp->setCustomStatusCode(status_code);
  callback(resp);
}

std::string random_string(const std::size_t len) {
  // We dont seed as this is NOT used for crypto but rather just naming things
  // randomly!
  std::minstd_rand simple_rand; // NOLINT(cert-msc32-c, cert-msc51-cpp)

  std::string alphanum =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  std::string tmp_s;
  tmp_s.reserve(len);

  auto size = alphanum.length();

  for (std::size_t i = 0; i < len; ++i) {
    tmp_s += alphanum.at(simple_rand() % (size - 1));
  }

  return tmp_s;
}

std::string hash_password(std::string const &password) {
  std::array<char, crypto_pwhash_STRBYTES> hashed_password_array;
  if (crypto_pwhash_str(hashed_password_array.data(), password.c_str(),
                        password.length(), crypto_pwhash_OPSLIMIT_SENSITIVE,
                        crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
    throw std::runtime_error("Failed to hash password");
  }
  std::string hashed_password(hashed_password_array.data());

  return hashed_password;
}

std::string localpart(std::string const &matrix_id) {
  return matrix_id.substr(1, matrix_id.find(':') - 1);
}

// Helper to generate a crc32 checksum.
unsigned long crc32_helper(std::string const &input) {
  unsigned long crc = crc32(0L, Z_NULL, 0);

  crc = crc32(crc, reinterpret_cast<const Bytef *>(input.data()),
              static_cast<unsigned int>(input.size()));
  return crc;
}

// Helper to base62 encode the crc32 checksum.
std::string base62_encode(unsigned long input) {
  std::string alphabet =
      "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  std::string output;

  while (input > 0) {
    output.push_back(alphabet[input % 62]);
    input /= 62;
  }

  return output;
}