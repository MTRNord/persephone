#include "utils.hpp"
#include "sodium.h"
#include "webserver/json.hpp"
#include <format>
#include <map>
#include <nlohmann/json.hpp>
#include <random>
#include <utility>
#include <zlib.h>

void return_error(const std::function<void(const HttpResponsePtr &)> &callback,
                  const std::string &errorcode, const std::string &error,
                  const int status_code) {
  generic_json::generic_json_error json_error{errorcode, error};
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

std::string hash_password(const std::string &password) {
  std::array<char, crypto_pwhash_STRBYTES> hashed_password_array;
  if (crypto_pwhash_str(hashed_password_array.data(), password.c_str(),
                        password.length(), crypto_pwhash_OPSLIMIT_SENSITIVE,
                        crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
    throw std::runtime_error("Failed to hash password");
  }
  std::string hashed_password(hashed_password_array.data());

  return hashed_password;
}

std::string localpart(const std::string &matrix_id) {
  return matrix_id.substr(1, matrix_id.find(':') - 1);
}

// Helper to generate a crc32 checksum.
unsigned long crc32_helper(const std::string &input) {
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

/**
 * Migrates the historic localpart format to the new one.
 *
 * 1. Encode character strings as UTF-8.
 * 2. Convert the bytes `A-Z` to lower-case.
 *     2a. In the case where a bridge must be able to distinguish two different
 *        users with ids which differ only by case, escape upper-case characters
 *        by prefixing with `_` before downcasing. For example, `A` becomes
 * `_a`. Escape a real `_` with a second `_`.
 * 3. Encode any remaining bytes outside the allowed character set, as well as
 *    `=`, as their hexadecimal value, prefixed with
 *    `=`. For example, `#` becomes `=23`; `á` becomes `=c3=a1`.
 *
 * For migration the chars must be in this grammar:
 *
 * ```
 * extended_user_id_char = %x21-39 / %x3B-7E  ; all ASCII printing chars except
 *                                            ; `:`
 * ```
 *
 * otherwise we do not change the chars as they then will be invalidated in the
 * next stage.
 *
 * Allowed in the localpart itself is:
 *
 * ```
 * user_id_localpart = 1*user_id_char
 * user_id_char = DIGIT
 *             / %x61-7A                   ; a-z
 *             / "-" / "." / "=" / "_" / "/" / "+"
 * ```
 */
std::string migrate_localpart(const std::string &original_mxid) {
  std::string migrated_mxid;
  migrated_mxid.reserve(original_mxid.size());

  for (auto const &c : original_mxid) {
    if (c >= 'A' && c <= 'Z') {
      migrated_mxid.push_back(static_cast<char>(c + 32));
    } else if (c == '_') {
      migrated_mxid.push_back('_');
      migrated_mxid.push_back('_');
    } else if (c == '.' || c == '-' || c == '=' || c == '/' || c == '+' ||
               (c >= 'a' && c <= 'z') ||
               /*Check if outside of range of historic ids*/
               (c >= 0x21 && c <= 0x39) || (c >= 0x3B && c <= 0x7E)) {
      migrated_mxid.push_back(c);
    } else {
      migrated_mxid += std::format("={:02x}", static_cast<unsigned char>(c));
    }
  }

  return migrated_mxid;
}