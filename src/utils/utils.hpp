#pragma once

#include "drogon/utils/coroutine.h"
#include "utils/config.hpp"
#include <cstddef>
#include <drogon/HttpClient.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <drogon/utils/Utilities.h>
#include <format>
#include <functional>
#include <nlohmann/json.hpp>
#include <optional>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

using json = nlohmann::json;
using namespace drogon;

static constexpr auto UserAgent = "persephone/0.1.0";
static constexpr auto DEFAULT_FEDERATION_TIMEOUT = 30;

static constexpr int MATRIX_SSL_PORT = 8448;
static constexpr int MATRIX_HTTP_PORT = 8008;

static constexpr auto id_max_length = 255;

struct [[nodiscard]] SRVRecord {
  std::string host;
  unsigned int port;
  unsigned short int priority;
  unsigned short int weight;
};

struct [[nodiscard]] ResolvedServer {
  std::string address;
  // Unsigned long since conversion from string is a little easier here
  unsigned long port;
  std::string server_name;
};

struct [[nodiscard]] HTTPRequest {
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

struct [[nodiscard]] VerifyKeyData {
  std::vector<unsigned char> private_key;
  std::string public_key_base64;
  std::string key_id;
  std::string key_type;
};

void return_error(const std::function<void(const HttpResponsePtr &)> &callback,
                  const std::string &errorcode, const std::string &error,
                  const HttpStatusCode status_code);

[[nodiscard]] std::string random_string(const std::size_t len);

[[nodiscard]] std::string hash_password(const std::string &password);

[[nodiscard]] bool verify_hashed_password(const std::string &hash,
                                          const std::string &password);

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

  for (auto const &character : localpart) {
    if (character >= 'A' && character <= 'Z') {
      migrated_localpart.push_back(static_cast<char>(character + 32));
    } else if (character == '_') {
      migrated_localpart.push_back('_');
      migrated_localpart.push_back('_');
    } else {
      migrated_localpart.push_back(character);
    }
  }

  return migrated_localpart;
}

[[nodiscard]] unsigned long crc32_helper(const std::string &input);

/**
 * @brief Encodes an unsigned long integer into a base62 string.
 *
 * This function takes an unsigned long integer as input and encodes it into a
 * base62 string. The base62 string is composed of the characters 0-9, a-z, and
 * A-Z. The function iteratively takes the modulus of the input by 62 and uses
 * the result as an index into the base62 alphabet to select a character. The
 * selected character is added to the output string. The input is then divided
 * by 62 and the process repeats until the input becomes 0. The function returns
 * the base62-encoded string.
 *
 * @param input The unsigned long integer to be encoded.
 * @return The base62-encoded string.
 */
[[nodiscard]] constexpr std::string base62_encode(unsigned long input) {
  const std::string alphabet =
      "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  std::string output;

  while (input > 0) {
    output.push_back(alphabet[input % 62]);
    input /= 62;
  }

  return output;
}

/**
 * @brief Removes brackets from a server name.
 *
 * This function takes a server name as input and removes any brackets ('[' or
 * ']') from it. It iterates over each character in the server name and removes
 * it if it is a bracket. The function returns the server name with the brackets
 * removed.
 *
 * @param server_name The server name from which to remove brackets.
 * @return The server name with the brackets removed.
 */
[[nodiscard]] constexpr std::string remove_brackets(std::string server_name) {
  std::erase_if(server_name, [](const char character) {
    switch (character) {
    case '[':
    case ']':
      return true;
    default:
      return false;
    }
  });
  return server_name;
}

/**
 * Check if a localpart is valid according to
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
 * @param server_name The server name to check against
 * @return true if the localpart is valid, false otherwise
 */
[[nodiscard]] constexpr bool
is_valid_localpart(const std::string &localpart,
                   const std::string &server_name) {
  for (auto const &character : localpart) {
    if (std::isdigit(character) || (character >= 'a' && character <= 'z') ||
        (character == '-' || character == '.' || character == '=' ||
         character == '_' || character == '/' || character == '+')) {
      continue;
    }
    return false;
  }

  // Check if the localpart is too long
  return std::format("@{}:{}", localpart, server_name).length() <=
         id_max_length;
}

/**
 * @brief Extracts the server part from a given input string.
 *
 * This function takes a string as input and finds the position of the first
 * colon (':'). If a colon is found, it returns the substring from the position
 * after the colon to the end of the input string. If no colon is found, it
 * throws a runtime error with the message "Invalid Input".
 *
 * @param input The string from which to extract the server part.
 * @return The server part of the input string.
 * @throws std::runtime_error If no colon is found in the input string.
 */
[[nodiscard]] constexpr std::string get_serverpart(const std::string &input) {
  if (const size_t pos = input.find(':'); pos != std::string::npos) {
    // Case: Colon found in input string
    return input.substr(pos + 1);
  }
  throw std::runtime_error("Invalid Input");
}

[[nodiscard]] static Task<std::vector<SRVRecord>>
get_srv_record(std::string address);

[[nodiscard]] Task<ResolvedServer> discover_server(std::string server_name);

[[nodiscard]] std::string generate_ss_authheader(
    const std::string &server_name, const std::string &key_id,
    const std::vector<unsigned char> &secret_key, const std::string &method,
    const std::string &request_uri, const std::string &origin,
    const std::string &target, const std::optional<json> &content);

/**
 * @brief Generates a query parameter string from a key and a list of values.
 *
 * This function takes a key and a list of values as input and generates a query
 * parameter string. The query parameter string starts with a '?' followed by
 * the key and '='. If the list of values is not empty, it URL encodes the first
 * value and appends it to the string. For each remaining value in the list, it
 * appends
 * '&' followed by the key, '=', and the URL encoded value to the string. The
 * function returns the generated query parameter string.
 *
 * @param keyName The key to be included in the query parameter string.
 * @param values The list of values to be included in the query parameter
 * string.
 * @return The generated query parameter string.
 */
[[nodiscard]] constexpr std::string
generateQueryParamString(const std::string &keyName,
                         const std::vector<std::string> &values) {
  std::string query_param_string{};
  query_param_string += '?' + keyName + '=';

  if (!values.empty()) {
    query_param_string += drogon::utils::urlEncodeComponent(values[0]);

    for (size_t i = 1; i < values.size(); ++i) {
      query_param_string +=
          '&' + keyName + '=' + drogon::utils::urlEncodeComponent(values[i]);
    }
  }

  return query_param_string;
}

[[nodiscard]] std::unordered_map<std::string, std::vector<std::string>>
parseQueryParamString(const std::string &queryString);

[[nodiscard]] Task<drogon::HttpResponsePtr>
federation_request(HTTPRequest request);

[[nodiscard]] VerifyKeyData get_verify_key_data(const Config &config);

/**
 * @brief A template struct for debugging.
 *
 * This struct is used for debugging purposes. It takes a format string and a
 * variable number of arguments, formats them into a string, and prints the
 * string to the console. It also includes the file name and line number where
 * the debug struct is instantiated.
 *
 * @tparam Args The types of the arguments to be formatted into the string.
 */
template <typename... Args> struct debug {
  /**
   * @brief Constructs a new debug object and prints the formatted string.
   *
   * This constructor takes a format string and a variable number of arguments,
   * formats them into a string, and prints the string to the console. It also
   * includes the file name and line number where the debug struct is
   * instantiated.
   *
   * @param format_string The format string.
   * @param args The arguments to be formatted into the string.
   * @param loc The source location where the debug struct is instantiated.
   * Defaults to the current location.
   */
  explicit debug(
      const std::string_view format_string, Args &&...args,
      const std::source_location &loc = std::source_location::current()) {
    auto str = std::format(
        "{}({}): {}\n", loc.file_name(), loc.line(),
        std::vformat(format_string, std::make_format_args(args...)));
    LOG_DEBUG << str;
  }
};

/**
 * @brief A deduction guide for the debug struct.
 *
 * This deduction guide allows the compiler to deduce the template arguments for
 * the debug struct from the arguments to the constructor.
 *
 * @tparam Args The types of the arguments to the debug constructor.
 */
template <typename... Args> debug(Args &&...) -> debug<Args...>;

/**
 * @brief Converts a drogon::HttpMethod to its string representation.
 *
 * This function takes a drogon::HttpMethod as input and returns its string
 * representation. The switch statement is used to map each drogon::HttpMethod
 * to its corresponding string. If the method is invalid, it returns "INVALID".
 *
 * @param method The drogon::HttpMethod to be converted.
 * @return The string representation of the drogon::HttpMethod.
 */
[[nodiscard]] constexpr std::string
drogon_to_string_method(const drogon::HttpMethod &method) {
  switch (method) {
  case drogon::HttpMethod::Get:
    return "GET";
  case drogon::HttpMethod::Post:
    return "POST";
  case drogon::HttpMethod::Head:
    return "HEAD";
  case drogon::HttpMethod::Put:
    return "PUT";
  case drogon::HttpMethod::Delete:
    return "DELETE";
  case drogon::HttpMethod::Options:
    return "OPTIONS";
  case drogon::HttpMethod::Patch:
    return "PATCH";
  case drogon::HttpMethod::Invalid:
    return "INVALID";
  }
  return "INVALID";
}

[[nodiscard]] constexpr std::string
generate_room_id(const std::string &server_name) {
  // Generate a room id which including the server name and the `!` prefix does
  // not exceed 255 bytes in length. The opaque_id between the `!` and the `:`
  // must be random, and should only contain ASCII characters. It is
  // case-sensitive.

  // Generate a random opaque_id
  constexpr auto opaque_id_start_length = 16;
  auto opaque_id = random_string(opaque_id_start_length);

  // Check if the combined length of the server name, `!`, opaque_id, and `:`
  // exceeds 255 bytes and if it does truncate the opaque_id until it fits
  while (std::format("!{}:{}", opaque_id, server_name).length() >
         id_max_length) {
    opaque_id.pop_back();
  }

  return std::format("!{}:{}", opaque_id, server_name);
}
