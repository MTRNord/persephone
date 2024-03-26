#include "utils.hpp"
#include "sodium.h"
#include "utils/json_utils.hpp"
#include "webserver/json.hpp"
#include <algorithm>
#include <ares.h>
#include <arpa/nameser.h>
#include <coroutine>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
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

[[nodiscard]] std::string random_string(const std::size_t len) {
  std::mt19937 mt_gen(std::random_device{}());

  std::string alphanum =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  std::string tmp_s;
  tmp_s.reserve(len);

  auto size = alphanum.length();

  for (std::size_t i = 0; i < len; ++i) {
    tmp_s += alphanum.at(mt_gen() % size);
  }

  return tmp_s;
}

[[nodiscard]] std::string hash_password(const std::string &password) {
  std::array<char, crypto_pwhash_STRBYTES> hashed_password_array;
  if (crypto_pwhash_str(hashed_password_array.data(), password.c_str(),
                        password.length(), crypto_pwhash_OPSLIMIT_SENSITIVE,
                        crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
    throw std::runtime_error("Failed to hash password");
  }
  std::string hashed_password(hashed_password_array.data());

  return hashed_password;
}

// Helper to generate a crc32 checksum.
[[nodiscard]] unsigned long crc32_helper(const std::string &input) {
  unsigned long crc = crc32(0L, Z_NULL, 0);

  crc = crc32(crc, reinterpret_cast<const Bytef *>(input.data()),
              static_cast<unsigned int>(input.size()));
  return crc;
}

[[nodiscard]] Task<std::vector<SRVRecord>>
get_srv_record(const std::string &address) {
  std::vector<SRVRecord> records;
  struct awaiter : public std::suspend_always {
    std::string address;
    std::vector<SRVRecord> &records;
    std::coroutine_handle<> handle;
    ares_channel channel;

    awaiter(std::string address, std::vector<SRVRecord> &records)
        : address(std::move(address)), records(records) {
      auto status = ares_init(&channel);
      if (status != ARES_SUCCESS) {
        throw std::runtime_error(std::format("Failed to init ares channel: {}",
                                             ares_strerror(status)));
      }
    }

    void await_suspend(std::coroutine_handle<> handle_) {
      this->handle = handle_;

      ares_query(
          channel, address.c_str(), ns_c_in, ns_t_srv,
          [](void *arg_, int status, int, unsigned char *abuf, int alen) {
            auto arg = static_cast<awaiter *>(arg_);
            struct ares_srv_reply *reply;

            auto parse_status = ares_parse_srv_reply(abuf, alen, &reply);
            if (parse_status != ARES_SUCCESS) {
              throw std::runtime_error(std::format(
                  "Failed to parse response: {}", ares_strerror(status)));
            }

            struct ares_srv_reply *next = reply;
            while (next != nullptr) {
              SRVRecord record;
              record.host = next->host;
              record.port = next->port;
              record.priority = next->priority;
              record.weight = next->weight;
              arg->records.push_back(record);
              next = next->next;
            }

            ares_destroy(arg->channel);
            arg->handle();
          },
          this);
    }
  };

  //  FIXME: We might need to rethrow here
  co_await awaiter(std::format("_matrix-fed._tcp.{}", address), records);
  co_return records;
}

[[nodiscard]] bool check_if_ip_address(const std::string &address) {
  struct sockaddr_in sa;
  auto is_ipv4 = false;
  auto result = inet_pton(AF_INET, address.c_str(), &(sa.sin_addr));
  is_ipv4 = result == 1;

  auto result_v6 = inet_pton(AF_INET6, address.c_str(), &(sa.sin_addr));
  return is_ipv4 || result_v6 == 1;
}

[[nodiscard]] Task<bool> isServerReachable(const SRVRecord &server) {
  auto client = HttpClient::newHttpClient(
      std::format("https://{}:{}", server.host, server.port));
  client->setUserAgent(UserAgent);

  auto req = HttpRequest::newHttpRequest();
  req->setMethod(drogon::Get);
  req->setPath("/_matrix/federation/v1/version");

  HttpResponsePtr resp;
  auto failure = false;
  try {
    resp = co_await client->sendRequestCoro(req, 10);
    if (resp->statusCode() != 200) {
      failure = true;
    }
  } catch (const std::exception &err) {
    failure = true;
  }
  co_return !failure;
}

[[nodiscard]] Task<SRVRecord> pick_srv_server(std::vector<SRVRecord> servers) {
  std::random_device rd;
  std::mt19937 gen(rd());

  while (!servers.empty()) {
    // Finding the minimum priority using std::min_element and lambda
    const auto minPriority =
        std::min_element(servers.begin(), servers.end(),
                         [](const SRVRecord &a, const SRVRecord &b) {
                           return a.priority < b.priority;
                         });

    const auto minPriorityVal = minPriority->priority;

    // Filtering servers with the minimum priority using std::copy_if and lambda
    std::vector<SRVRecord> minPriorityServers;
    std::copy_if(servers.begin(), servers.end(),
                 std::back_inserter(minPriorityServers),
                 [minPriorityVal](const SRVRecord &srv) {
                   return srv.priority == minPriorityVal;
                 });

    // Sorting the servers based on weight using std::sort and lambda
    std::sort(minPriorityServers.begin(), minPriorityServers.end(),
              [](const SRVRecord &a, const SRVRecord &b) {
                return a.weight > b.weight;
              });

    unsigned int totalWeight =
        std::accumulate(minPriorityServers.begin(), minPriorityServers.end(),
                        0u, [](unsigned int sum, const SRVRecord &srv) {
                          return sum + srv.weight;
                        });

    // Selecting a server based on weighted random distribution
    std::uniform_int_distribution<unsigned int> dist(1, totalWeight);
    unsigned int selectedWeight = dist(gen);
    for (const auto &server : minPriorityServers) {
      selectedWeight -= server.weight;
      if (selectedWeight <= 0) {
        if (co_await isServerReachable(server)) {
          co_return server;
        }
        // If server is unreachable, continue to the next server
      }
    }
  }

  throw std::runtime_error("Error selecting server");
}

[[nodiscard]] Task<ResolvedServer>
discover_server(const std::string &server_name) {
  /*
   * If the hostname is an IP literal, then that IP address should be used,
   * together with the given port number, or 8448 if no port is given. The
   * target server must present a valid certificate for the IP address. The Host
   * header in the request should be set to the server name, including the port
   * if the server name included one.
   */
  auto port = server_name.substr(server_name.find_last_of(':') + 1,
                                 server_name.length() -
                                     (server_name.find_last_of(':') + 1));
  auto address = server_name.substr(0, server_name.find_last_of(':') + 1);
  auto clean_address = remove_brackets(address);
  if (check_if_ip_address(clean_address)) {
    unsigned long integer_port = 8448;
    if (!port.empty()) {
      integer_port = std::stoul(port);
    }
    co_return ResolvedServer{
        .address = address,
        .port = integer_port,
        .server_name = server_name,
    };
  }

  /*
   * If the hostname is not an IP literal, and the server name includes an
   * explicit port, resolve the hostname to an IP address using CNAME, AAAA or A
   * records. Requests are made to the resolved IP address and given port with a
   * Host header of the original server name (with port). The target server must
   * present a valid certificate for the hostname.
   */
  if (!port.empty()) {
    co_return ResolvedServer{
        .address = address,
        .port = std::stoul(port),
        .server_name = server_name,
    };
  }

  auto client =
      HttpClient::newHttpClient(std::format("https://{}", server_name));
  client->setUserAgent(UserAgent);

  auto req = HttpRequest::newHttpRequest();
  req->setMethod(drogon::Get);
  req->setPath("/.well-known/matrix/server");

  HttpResponsePtr resp;
  auto failure = false;
  try {
    resp = co_await client->sendRequestCoro(req, 10);
    if (resp->statusCode() != 200) {
      failure = true;
    }
  } catch (const std::exception &err) {
    failure = true;
  }

  if (!failure) {
    // Get the response body as json
    json body = json::parse(resp->body());
    server_server_json::well_known well_known =
        body.get<server_server_json::well_known>();

    if (well_known.m_server) {
      auto delegated_server_name = well_known.m_server.value();
      auto delegated_port = delegated_server_name.substr(
          delegated_server_name.find_last_of(':') + 1,
          delegated_server_name.length() -
              (delegated_server_name.find_last_of(':') + 1));
      auto delegated_address = delegated_server_name.substr(
          0, delegated_server_name.find_last_of(':') + 1);
      auto delegated_clean_address = remove_brackets(delegated_address);

      if (check_if_ip_address(delegated_clean_address)) {
        unsigned long integer_port = 8448;
        if (!port.empty()) {
          integer_port = std::stoul(delegated_port);
        }
        co_return ResolvedServer{
            .address = delegated_address,
            .port = integer_port,
            .server_name = delegated_server_name,
        };
      }

      if (!delegated_port.empty()) {
        co_return ResolvedServer{
            .address = delegated_address,
            .port = std::stoul(delegated_port),
            .server_name = delegated_server_name,
        };
      }

      auto srv_resp = co_await get_srv_record(server_name);
      if (!srv_resp.empty()) {
        auto server = co_await pick_srv_server(srv_resp);
        co_return ResolvedServer{
            .address = server.host,
            .port = server.port,
            .server_name = delegated_server_name,
        };
      }

      co_return ResolvedServer{
          .address = delegated_address,
          .port = 8448,
          .server_name = delegated_server_name,
      };
    }
  }

  /*
   *  If the /.well-known request resulted in an error response, a server is
   * found by resolving an SRV record for _matrix-fed._tcp.<hostname>. This may
   * result in a hostname (to be resolved using AAAA or A records) and port.
   * Requests are made to the resolved IP address and port, with a Host header
   * of <hostname>. The target server must present a valid certificate for
   * <hostname>.
   */
  auto srv_resp = co_await get_srv_record(server_name);
  if (!srv_resp.empty()) {
    auto server = co_await pick_srv_server(srv_resp);
    co_return ResolvedServer{
        .address = server.host,
        .port = server.port,
        .server_name = server_name,
    };
  }

  co_return ResolvedServer{
      .address = address,
      .port = 8448,
      .server_name = server_name,
  };
}

[[nodiscard]] std::string generate_ss_authheader(
    const std::string &server_name, const std::string &key_id,
    const std::vector<unsigned char> &secret_key, const std::string &method,
    const std::string &request_uri, const std::string &origin,
    const std::string &target, std::optional<json> content) {

  auto request_json = json::object();
  request_json["method"] = method;
  request_json["uri"] = request_uri;
  request_json["origin"] = origin;
  request_json["destination"] = target;

  if (content) {
    request_json["content"] = content.value();
  }

  auto signed_json =
      json_utils::sign_json(server_name, key_id, secret_key, request_json);

  std::vector<std::string> authorization_headers;
  for (auto &[key, val] : signed_json.items()) {
    authorization_headers.push_back(std::format(
        R"(X-Matrix origin="{}",destination="{}",key="{}",sig="{}")", origin,
        target, key, val.get<std::string>()));
  }

  return authorization_headers[0];
}

// Function to parse query parameter string into a map
[[nodiscard]] std::unordered_map<std::string, std::vector<std::string>>
parseQueryParamString(const std::string &queryString) {
  std::unordered_map<std::string, std::vector<std::string>> paramMap;

  std::istringstream iss(queryString);
  std::string pair;

  while (std::getline(iss, pair, '&')) {
    std::istringstream pairStream(pair);
    std::string key;
    std::string value;

    if (std::getline(pairStream, key, '=') && std::getline(pairStream, value)) {
      paramMap[key].push_back(value);
    }
  }

  return paramMap;
}

[[nodiscard]] Task<drogon::HttpResponsePtr>
federation_request(const HTTPRequest &request) {
  auto auth_header = generate_ss_authheader(
      request.origin, request.key_id, request.secret_key,
      drogon_to_string_method(request.method), request.path, request.origin,
      request.target, request.content);
  auto req = HttpRequest::newHttpRequest();
  req->setMethod(request.method);
  req->setPath(request.path);
  req->addHeader("Authorization", auth_header);
  req->removeHeader("Host");
  req->addHeader("Host", request.target);

  co_return co_await request.client->sendRequestCoro(req, request.timeout);
}

[[nodiscard]] VerifyKeyData get_verify_key_data(const Config &config) {
  std::ifstream t(config.matrix_config.server_key_location);
  std::string server_key((std::istreambuf_iterator<char>(t)),
                         std::istreambuf_iterator<char>());
  std::istringstream buffer(server_key);
  std::vector<std::string> splitted_data{
      std::istream_iterator<std::string>(buffer),
      std::istream_iterator<std::string>()};

  auto private_key = json_utils::unbase64_key(splitted_data[2]);
  std::vector<unsigned char> public_key(crypto_sign_PUBLICKEYBYTES);
  crypto_sign_ed25519_sk_to_pk(public_key.data(), private_key.data());
  auto public_key_base64 = json_utils::base64_key(public_key);

  return {.private_key = private_key,
          .public_key_base64 = public_key_base64,
          .key_id = splitted_data[1],
          .key_type = splitted_data[0]};
}
