#pragma once
#include "drogon/drogon.h"
#include <string>

using namespace drogon;

void return_error(std::function<void(const HttpResponsePtr &)> const &callback,
                  std::string errorcode, std::string error, int status_code);

[[nodiscard]] std::string random_string(const unsigned long len);

[[nodiscard]] std::string hash_password(std::string const &password);

// Get the localpart of a user's matrix id.
[[nodiscard]] std::string localpart(std::string const &matrix_id);

// Helper to generate a crc32 checksum.
[[nodiscard]] unsigned long crc32_helper(std::string const &input);

// Helper to base62 encode the crc32 checksum.
[[nodiscard]] std::string base62_encode(unsigned long input);