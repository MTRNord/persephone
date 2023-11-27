#include "utils.hpp"
#include "sodium.h"
#include "webserver/json.hpp"
#include <cstdlib>
#include <format>
#include <map>
#include <nlohmann/json.hpp>
#include <utility>

std::string dump_headers(const Headers &headers) {
  std::string s;

  for (const auto &x : headers) {
    s += std::format("{}: {}\n", x.first, x.second);
  }

  return s;
}

std::string log(const Request &req, const Response &res) {
  std::string s;

  s += "================================\n";
  s += std::format("{} {} {}\n", req.method, req.version, req.path);

  std::string query;
  for (auto it = req.params.begin(); it != req.params.end(); ++it) {
    const auto &x = *it;
    query += std::format("{}{}={}\n", (it == req.params.begin()) ? '?' : '&',
                         x.first, x.second);
  }

  s += std::format("{}\n", query);
  s += dump_headers(req.headers);

  s += "--------------------------------\n";
  s += std::format("{} {}\n", res.status, res.version);

  s += dump_headers(res.headers);
  s += "\n";

  if (!res.body.empty()) {
    s += res.body;
  }

  s += "\n";
  return s;
}

void return_error(Response &res, std::string errorcode, std::string error,
                  int status_code) {
  generic_json::generic_json_error json_error{std::move(errorcode),
                                              std::move(error)};
  json j = json_error;
  res.set_content(j.dump(), "application/json");
  res.status = status_code;
}

std::string random_string(const unsigned long len) {
  static const char alphanum[] = "0123456789"
                                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "abcdefghijklmnopqrstuvwxyz";
  std::string tmp_s;
  tmp_s.reserve(len);

  for (unsigned long i = 0; i < len; ++i) {
    tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
  }

  return tmp_s;
}

std::string hash_password(std::string const &password) {
  std::string hashed_password;

  if (crypto_pwhash_str(hashed_password.data(), password.c_str(),
                        password.size(), crypto_pwhash_OPSLIMIT_SENSITIVE,
                        crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
    throw std::runtime_error("Failed to hash password");
  }

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