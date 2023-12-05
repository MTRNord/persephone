#pragma once
#include "drogon/drogon.h"
#include <string>

using namespace drogon;

void return_error(const std::function<void(const HttpResponsePtr &)> &callback,
                  const std::string &errorcode, const std::string &error,
                  const int status_code);

[[nodiscard]] std::string random_string(const std::size_t len);

[[nodiscard]] std::string hash_password(const std::string &password);

// Get the localpart of a user's matrix id.
[[nodiscard]] std::string localpart(const std::string &matrix_id);

[[nodiscard]] std::string migrate_localpart(const std::string &localpart);

// Helper to generate a crc32 checksum.
[[nodiscard]] unsigned long crc32_helper(const std::string &input);

// Helper to base62 encode the crc32 checksum.
[[nodiscard]] std::string base62_encode(unsigned long input);

[[nodiscard]] bool is_valid_localpart(const std::string &localpart,
                                      const std::string &server_name);