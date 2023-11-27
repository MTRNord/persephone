#pragma once
#include "httplib.h"
#include <string>

using namespace httplib;

std::string dump_headers(const Headers &headers);
std::string log(const Request &req, const Response &res);

void return_error(Response &res, std::string errorcode, std::string error,
                  int status_code);

[[nodiscard]] std::string random_string(const unsigned long len);

[[nodiscard]] std::string hash_password(std::string const &password);

// Get the localpart of a user's matrix id.
[[nodiscard]] std::string localpart(std::string const &matrix_id);

// Helper to generate a crc32 checksum.
[[nodiscard]] unsigned long crc32_helper(std::string const &input);

// Helper to base62 encode the crc32 checksum.
[[nodiscard]] std::string base62_encode(unsigned long input);