#pragma once

#include "drogon/drogon.h"
#include "drogon/utils/coroutine.h"
#include "utils/config.hpp"
#include <nlohmann/json.hpp>
#include <source_location>
#include <string>
#include <format>
#include <string_view>

using json = nlohmann::json;
using namespace drogon;

constexpr auto UserAgent = "persephone/0.1.0";

struct SRVRecord {
  std::string host;
  unsigned int port;
  unsigned short int priority;
  unsigned short int weight;
};

struct ResolvedServer {
  std::string address;
  // Unsigned long since conversion from string is a little easier here
  unsigned long port;
  std::string server_name;
};

struct HTTPRequest {
  drogon::HttpClientPtr client;
  drogon::HttpMethod method;
  std::string path;
  std::string key_id;
  std::vector<unsigned char> secret_key;
  std::string origin;
  std::string target;
  std::optional<json> content;
  int timeout;
};

struct VerifyKeyData {
  std::vector<unsigned char> private_key;
  std::string public_key_base64;
  std::string key_id;
  std::string key_type;
};

void return_error(const std::function<void(const HttpResponsePtr &)> &callback,
                  const std::string &errorcode, const std::string &error,
                  const int status_code);

[[nodiscard]] std::string random_string(const std::size_t len);

[[nodiscard]] std::string hash_password(const std::string &password);

// Get the localpart of a user's matrix id.
[[nodiscard]] constexpr std::string localpart(const std::string &matrix_id) {
  return matrix_id.substr(1, matrix_id.find(':') - 1);
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
 * Allowed in the localpart itself is:
 *
 * ```
 * user_id_localpart = 1*user_id_char
 * user_id_char = DIGIT
 *             / %x61-7A                   ; a-z
 *             / "-" / "." / "=" / "_" / "/" / "+"
 * ```
 */
[[nodiscard]] constexpr std::string
migrate_localpart(const std::string &localpart) {
  std::string migrated_localpart;
  migrated_localpart.reserve(localpart.size());

  for (auto const &c : localpart) {
    if (c >= 'A' && c <= 'Z') {
      migrated_localpart.push_back(static_cast<char>(c + 32));
    } else if (c == '_') {
      migrated_localpart.push_back('_');
      migrated_localpart.push_back('_');
    } else {
      migrated_localpart.push_back(c);
    }
  }

  return migrated_localpart;
}

// Helper to generate a crc32 checksum.
[[nodiscard]] unsigned long crc32_helper(const std::string &input);

// Helper to base62 encode the crc32 checksum.
[[nodiscard]] std::string base62_encode(unsigned long input);

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
[[nodiscard]] constexpr bool
is_valid_localpart(const std::string &localpart,
                   const std::string &server_name) {
  for (auto const &c : localpart) {
    if (std::isdigit(c) || (c >= 'a' && c <= 'z') ||
        (c == '-' || c == '.' || c == '=' || c == '_' || c == '/' ||
         c == '+')) {
      continue;
    } else {
      return false;
    }
  }

  // Check if the localpart is too long
  return !(std::format("@{}:{}", localpart, server_name).length() > 255);
}

[[nodiscard]] constexpr std::string get_serverpart(const std::string &input) {
  size_t pos = input.find(':');
  if (pos != std::string::npos) {
    // Case: Colon found in input string
    return input.substr(pos + 1);
  }
  throw std::runtime_error("Invalid Input");
}

[[nodiscard]] Task<std::vector<SRVRecord>>
get_srv_record(const std::string &address);

[[nodiscard]] Task<ResolvedServer>
discover_server(const std::string &server_name);

[[nodiscard]] std::string generate_ss_authheader(
    const std::string &server_name, const std::string &key_id,
    const std::vector<unsigned char> &secret_key, const std::string &method,
    const std::string &request_uri, std::string origin, std::string target,
    std::optional<json> content);

[[nodiscard]] std::string
generateQueryParamString(const std::string &keyName,
                         const std::vector<std::string> &values);

/**
 * This is supposed to fix the missing array availability for drogon
 *
 * @example
 *
 * ```cpp
 * auto query = req->getQuery();
 * auto query_map = parseQueryParamString(query);
 * ```
 */
[[nodiscard]] std::unordered_map<std::string, std::vector<std::string>>
parseQueryParamString(const std::string &queryString);

[[nodiscard]] Task<drogon::HttpResponsePtr>
federation_request(const HTTPRequest &request);

[[nodiscard]] VerifyKeyData get_verify_key_data(const Config &config);

template <typename... Args>
struct debug
{
    debug(std::string_view format_string, Args&&... args, const std::source_location& loc = std::source_location::current())
    {
        auto str = std::format("{}({}): {}\n", loc.file_name(), loc.line(), std::vformat(format_string, std::make_format_args(args...)));
        std::cout << str;
    }
};

template <typename... Args>
debug(Args&&...) -> debug<Args...>;
