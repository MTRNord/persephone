#include "utils.hpp"
#include "webserver/json.hpp"
#include <format>

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

void return_error(Response &res, std::string errorcode, std::string error) {
  generic_json::generic_json_error json_error{std::move(errorcode),
                                              std::move(error)};
  json j = json_error;
  res.set_content(j.dump(), "application/json");
  res.status = 500;
}