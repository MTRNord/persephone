#include "utils.hpp"
#include "utils/json_utils.hpp"
#include "webserver/json.hpp"
#include <algorithm>
#include <coroutine>
#include <cstddef>
#include <cstdlib>
#include <drogon/HttpClient.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <drogon/utils/coroutine.h>
#include <error.h>
#include <exception>
#include <format>
#include <fstream>
#include <functional>
#include <iterator>
#include <ldns/ldns.h>
#include <netinet/in.h>
#include <optional>
#include <random>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <zconf.h>
#include <zlib.h>

/**
 * @brief Returns an error response with a given error code, error message, and
 * status code.
 *
 * This function creates a new HTTP response, sets its body to a JSON object
 * containing the error code and error message, sets the content type to
 * application/json, and sets the status code to the given status code. It then
 * calls the provided callback function with the response.
 *
 * @param callback The callback function to be called with the error response.
 * @param errorcode The error code to be included in the response.
 * @param error The error message to be included in the response.
 * @param status_code The status code to be set for the response.
 */
void return_error(const std::function<void(const HttpResponsePtr &)> &callback,
                  const std::string &errorcode, const std::string &error,
                  const HttpStatusCode status_code) {
  generic_json::generic_json_error const json_error{.errcode = errorcode,
                                                    .error = error};
  json const json_data = json_error;
  const auto resp = HttpResponse::newHttpResponse();
  resp->setBody(json_data.dump());
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  resp->setStatusCode(status_code);
  callback(resp);
}

/**
 * @brief Generates a random alphanumeric string of a given length.
 *
 * This function generates a random string of a specified length. The string
 * consists of alphanumeric characters (both uppercase and lowercase letters,
 * and digits). The function uses the Mersenne Twister algorithm (std::mt19937)
 * for generating random numbers, which are then used to select characters from
 * the alphanumeric set.
 *
 * @param len The length of the random string to be generated.
 * @return A random alphanumeric string of length 'len'.
 */
[[nodiscard]] std::string random_string(const std::size_t len) {
  std::mt19937 mt_gen(std::random_device{}());

  const std::string alphanum =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  std::string tmp_s;
  tmp_s.reserve(len);

  const auto size = alphanum.length();

  for (std::size_t i = 0; i < len; ++i) {
    tmp_s += alphanum.at(mt_gen() % size);
  }

  return tmp_s;
}

/**
 * @brief Hashes a password using the Sodium library.
 *
 * This function hashes a given password using the Sodium library's password
 * hashing function. The function uses the sensitive limits for operations and
 * memory usage. If the hashing fails, it throws a runtime error.
 *
 * @param password The password to be hashed.
 * @return A hashed version of the input password.
 * @throws std::runtime_error if the password hashing fails.
 */
[[nodiscard]] std::string hash_password(const std::string &password) {
  std::string hashed_password_array(crypto_pwhash_STRBYTES, '\0');
  if (crypto_pwhash_str(hashed_password_array.data(), password.c_str(),
                        password.length(), crypto_pwhash_OPSLIMIT_SENSITIVE,
                        crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
    throw std::runtime_error("Failed to hash password");
  }
  std::string hashed_password(hashed_password_array);

  return hashed_password;
}

/**
 * @brief Verifies a hashed password using the Sodium library.
 *
 * This function verifies a given password against a hashed password using the
 * Sodium library's password hashing verification function. It compares the
 * provided password with the hashed password and returns true if they match,
 * false otherwise.
 *
 * @param hash The hashed password to verify against.
 * @param password The password to be verified.
 * @return true if the password matches the hashed password, false otherwise.
 */
[[nodiscard]] bool verify_hashed_password(const std::string &hash,
                                          const std::string &password) {
  // Convert the hash to an array
  return crypto_pwhash_str_verify(hash.c_str(), password.c_str(),
                                  password.length()) == 0;
}

/**
 * @brief Computes the CRC32 checksum of the input string.
 *
 * This function computes the CRC32 checksum of a given input string. The CRC32
 * checksum is a type of hash function that produces a checksum (a small-sized
 * datum) from a block of data for the purpose of detecting errors during its
 * transmission or storage. The function uses the zlib's crc32 function to
 * compute the checksum.
 *
 * @param input The string for which the CRC32 checksum is to be computed.
 * @return The CRC32 checksum of the input string.
 */
[[nodiscard]] unsigned long crc32_helper(const std::string &input) {
  unsigned long crc = crc32(0L, nullptr, 0);

  crc = crc32(crc, reinterpret_cast<const Bytef *>(input.data()),
              static_cast<unsigned int>(input.size()));
  return crc;
}

/**
 * @brief Asynchronously fetches SRV records for a given address.
 *
 * This function uses the ldns library to asynchronously query the DNS SRV
 * records for a given address. The function is implemented as a C++ coroutine
 * and returns a Task that will eventually contain the SRV records.
 *
 * @param address The address to query the SRV records for.
 * @return A Task that will eventually contain a vector of SRV records.
 */
[[nodiscard]] std::vector<SRVRecord>
get_srv_record(const std::string &address) {
  LOG_DEBUG << "Awaiting SRV record for address: " << address;

  ldns_resolver *res = nullptr;
  ldns_rdf *domain = ldns_dname_new_frm_str(address.c_str());
  if (!domain) {
    throw std::runtime_error("Failed to parse domain");
  }
  if (!ldns_dname_str_absolute(address.c_str()) &&
      ldns_dname_absolute(domain)) {
    ldns_rdf_set_size(domain, ldns_rdf_size(domain) - 1);
  }

  if (ldns_status const status = ldns_resolver_new_frm_file(&res, nullptr);
      status != LDNS_STATUS_OK) {
    throw std::runtime_error(std::format("Failed to create resolver: {}",
                                         ldns_get_errorstr_by_id(status)));
  }

  ldns_pkt *record_packet = ldns_resolver_search(res, domain, LDNS_RR_TYPE_SRV,
                                                 LDNS_RR_CLASS_IN, LDNS_RD);
  ldns_rdf_deep_free(domain);

  if (!record_packet) {
    throw std::runtime_error("Failed to resolve SRV record");
  }

  LOG_DEBUG << "SRV record resolved for address: " << address
            << " and starting to parse it";
  ldns_rr_list *srv_record = ldns_pkt_rr_list_by_type(
      record_packet, LDNS_RR_TYPE_SRV, LDNS_SECTION_ANSWER);

  if (!srv_record) {
    ldns_pkt_free(record_packet);
    ldns_resolver_deep_free(res);
    throw std::runtime_error("Failed to parse SRV record");
  }

  ldns_rr_list_sort(srv_record);

  LOG_DEBUG << "SRV record parsed successfully for address: " << address;
  LOG_DEBUG << "Creating SRVRecord objects";

  std::vector<SRVRecord> records;

  // Create the SRVRecord objects
  for (size_t i = 0; i < ldns_rr_list_rr_count(srv_record); i++) {
    const ldns_rr *record_rr = ldns_rr_list_rr(srv_record, i);

    // get record type
    const auto type = ldns_rr_get_type(record_rr);

    char *raw_host = ldns_rdf2str(ldns_rr_rdf(record_rr, 3));
    LOG_DEBUG << "SRV record host: " << raw_host;
    const std::string host = raw_host;
    // Necessary manual free due to how ldns does memory management. We cant
    // use delete here.
    free(raw_host);

    SRVRecord srv;
    // Remove the trailing dot from the host
    if (host.back() == '.') {
      srv.host = host.substr(0, host.size() - 1);
    } else {
      srv.host = host;
    }
    srv.port = ldns_rdf2native_int16(ldns_rr_rdf(record_rr, 2));
    srv.priority = ldns_rdf2native_int16(ldns_rr_rdf(record_rr, 0));
    srv.weight = ldns_rdf2native_int16(ldns_rr_rdf(record_rr, 1));
    records.push_back(srv);
  }
  ldns_rr_list_deep_free(srv_record);

  ldns_pkt_free(record_packet);
  ldns_resolver_deep_free(res);

  LOG_DEBUG << "SRVRecord objects created successfully";

  return records;
}

/**
 * @brief Checks if a server is reachable by sending a GET request to its
 * "/_matrix/federation/v1/version" endpoint.
 *
 * This function creates a new HTTP client and sends a GET request to the
 * "/_matrix/federation/v1/version" endpoint of the server. The server is
 * considered reachable if the status code of the response is 200. If an
 * exception occurs during the request or the status code is not 200, the server
 * is considered unreachable.
 *
 * @param server The server to check. The server is represented by an SRVRecord
 * object, which contains the host and port of the server.
 * @return A Task that will eventually contain a boolean value indicating
 * whether the server is reachable or not.
 */
[[nodiscard]] Task<bool> isServerReachable(const SRVRecord server) {
  LOG_DEBUG << "Checking if server is reachable: https://" << server.host << ":"
            << server.port;
  const auto client = HttpClient::newHttpClient(
      std::format("https://{}:{}", server.host, server.port));
  client->setUserAgent(UserAgent);

  const auto req = HttpRequest::newHttpRequest();
  req->setMethod(drogon::Get);
  req->setPath("/_matrix/federation/v1/version");

  LOG_DEBUG << "Sending request to server: [" << req->methodString()
            << "] https://" << client->host() << req->path();

  try {
    if (const HttpResponsePtr resp = co_await client->sendRequestCoro(req, 10);
        resp->statusCode() == k200OK) {
      co_return true;
    } else {
      LOG_WARN << "Server is unreachable. Status code: " << resp->statusCode()
               << " body: " << resp->body();
    }
  } catch (const drogon::HttpException &err) {
    LOG_WARN << "Error while checking server reachability: " << err.what();
  } catch (const std::exception &err) {
    LOG_WARN << "Error while checking server reachability: " << err.what();
  } catch (...) {
    LOG_WARN << "Unknown error while checking server reachability";
  }
  co_return false;
}

/**
 * @brief Selects a server from a list of SRV records based on priority and
 * weight.
 *
 * This function selects a server from a list of SRV records. The selection is
 * based on the priority and weight of the servers. The function first finds the
 * servers with the minimum priority. If there are multiple servers with the
 * same minimum priority, it selects a server based on a weighted random
 * distribution. The weight of a server influences the probability of it being
 * selected. The function uses the C++ Standard Library's random number
 * generation facilities to generate the weighted random distribution. If the
 * selected server is reachable, it is returned. If not, the function continues
 * with the next server. If no server can be selected, the function throws a
 * runtime error.
 *
 * @param servers A vector of SRVRecord objects representing the servers to
 * select from.
 * @return A Task that will eventually contain the selected SRVRecord object.
 * @throws std::runtime_error if no server can be selected.
 */
[[nodiscard]] Task<SRVRecord> pick_srv_server(std::vector<SRVRecord> servers) {
  std::random_device random_device;
  std::mt19937 gen(random_device());

  LOG_DEBUG << "Selecting server from SRV records";

  while (!servers.empty()) {
    // Finding the minimum priority using std::min_element and lambda
    const auto minPriority = std::ranges::min_element(
        servers, [](const SRVRecord &first, const SRVRecord &second) {
          return first.priority < second.priority;
        });

    const auto minPriorityVal = minPriority->priority;

    // Filtering servers with the minimum priority using std::copy_if and lambda
    std::vector<SRVRecord> minPriorityServers;
    std::ranges::copy_if(servers, std::back_inserter(minPriorityServers),
                         [minPriorityVal](const SRVRecord &srv) {
                           return srv.priority == minPriorityVal;
                         });

    // Sorting the servers based on weight using std::sort and lambda
    std::ranges::sort(minPriorityServers,
                      [](const SRVRecord &first, const SRVRecord &second) {
                        return first.weight > second.weight;
                      });

    const unsigned int totalWeight =
        std::accumulate(minPriorityServers.begin(), minPriorityServers.end(),
                        0U, [](unsigned int sum, const SRVRecord &srv) {
                          return sum + srv.weight;
                        });

    LOG_DEBUG << "Total weight: " << totalWeight;
    // Selecting a server based on weighted random distribution
    std::uniform_int_distribution<> dist(1, static_cast<int>(totalWeight));
    auto selectedWeight = dist(gen);
    LOG_DEBUG << "Selected weight: " << selectedWeight;
    for (const auto &server : minPriorityServers) {
      LOG_DEBUG << "Trying server: " << server.host << ":" << server.port;
      selectedWeight -= server.weight;
      LOG_DEBUG << "Selected weight: " << selectedWeight;
      if (selectedWeight <= 0) {
        if (co_await isServerReachable(server)) {
          co_return server;
        }
        LOG_DEBUG << "Server is unreachable";
        // If server is unreachable, continue to the next server
      }
    }

    // Remove the servers with the minimum priority from the list
    std::erase_if(servers, [minPriorityVal](const SRVRecord &srv) {
      return srv.priority == minPriorityVal;
    });
  }

  throw std::runtime_error("Error selecting server");
}

/**
 * @brief Discovers a server based on the given server name.
 *
 * This function discovers a server based on the given server name. It follows
 * several steps:
 * 1. If the server name is an IP literal, it uses that IP address along with
 * the given port number, or 8448 if no port is given.
 * 2. If the server name is not an IP literal and includes an explicit port, it
 * resolves the hostname to an IP address using CNAME, AAAA or A records.
 * 3. If the /.well-known request resulted in an error response, it finds a
 * server by resolving an SRV record for _matrix-fed._tcp.<hostname>.
 *
 * The function returns a ResolvedServer object that contains the address, port,
 * and server name of the discovered server.
 *
 * @param server_name The server name to discover.
 * @return A Task that will eventually contain a ResolvedServer object
 * representing the discovered server.
 */
[[nodiscard]] Task<ResolvedServer> discover_server(std::string server_name) {
  /*
   * If the hostname is an IP literal, then that IP address should be used,
   * together with the given port number, or 8448 if no port is given. The
   * target server must present a valid certificate for the IP address. The Host
   * header in the request should be set to the server name, including the port
   * if the server name included one.
   */
  LOG_DEBUG << "Discovering server: " << server_name;
  // If there is a colon then use the thing after the last colon as the port
  // otherwise make it an empty optional
  const std::optional<std::string> port =
      [&server_name]() -> std::optional<std::string> {
    if (const auto pos = server_name.find_last_of(':');
        pos != std::string::npos) {
      return server_name.substr(pos + 1);
    }
    return std::nullopt;
  }();
  LOG_DEBUG << "Port: " << port.value_or("None");
  LOG_DEBUG << "Server name: " << server_name;

  // Server name with the port removed. If no port is given, this is the same as
  // the server name. Use the port optional to determine if the port should be
  // removed.
  auto address = [&server_name, &port]() -> std::string {
    if (port.has_value()) {
      return server_name.substr(0, server_name.find_last_of(':'));
    }
    return server_name;
  }();
  if (auto clean_address = remove_brackets(address);
      check_if_ip_address(clean_address)) {
    unsigned long integer_port = MATRIX_SSL_PORT;
    if (port.has_value()) {
      integer_port = std::stoul(port.value());
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
  if (port.has_value()) {
    co_return ResolvedServer{
        .address = address,
        .port = std::stoul(port.value()),
        .server_name = server_name,
    };
  }

  LOG_DEBUG << "Discovering server's well-known endpoint";
  auto client =
      HttpClient::newHttpClient(std::format("https://{}", server_name));
  client->setUserAgent(UserAgent);

  auto req = HttpRequest::newHttpRequest();
  req->setMethod(drogon::Get);
  req->setPath("/.well-known/matrix/server");

  LOG_DEBUG << "Initialized well-known request. [" << req->methodString()
            << "] " << req->path();

  try {
    LOG_DEBUG << "Sending well-known request";
    const auto http_response =
        co_await client->sendRequestCoro(req, DEFAULT_FEDERATION_TIMEOUT);
    LOG_DEBUG << "Well-known response status: " << http_response->statusCode();
    if (http_response->statusCode() == k200OK) {
      LOG_DEBUG << "Got well-known response";

      LOG_DEBUG << "Well-known response status code: "
                << http_response->statusCode();
      // Get the response body as json
      json const body = json::parse(http_response->body());

      if (auto [m_server] = body.get<server_server_json::well_known>();
          m_server) {
        auto delegated_server_name = m_server.value();
        // If there is a colon then use the thing after the last colon as the
        // port otherwise make it an empty optional
        const std::optional<std::string> delegated_port =
            [&delegated_server_name]() -> std::optional<std::string> {
          if (const auto pos = delegated_server_name.find_last_of(':');
              pos != std::string::npos) {
            return delegated_server_name.substr(pos + 1);
          }
          return std::nullopt;
        }();

        // Server name with the port removed. If no port is given, this is the
        // same as the server name. Use the port optional to determine if the
        // port should be removed.
        auto delegated_address = [&delegated_server_name,
                                  &delegated_port]() -> std::string {
          if (delegated_port.has_value()) {
            return delegated_server_name.substr(
                0, delegated_server_name.find_last_of(':'));
          }
          return delegated_server_name;
        }();
        if (auto delegated_clean_address = remove_brackets(delegated_address);
            check_if_ip_address(delegated_clean_address)) {
          unsigned long integer_port = MATRIX_SSL_PORT;
          if (delegated_port.has_value()) {
            integer_port = std::stoul(delegated_port.value());
          }
          co_return ResolvedServer{
              .address = delegated_address,
              .port = integer_port,
              // TODO: Verify this is correct
              .server_name = server_name,
          };
        }

        if (delegated_port.has_value()) {
          co_return ResolvedServer{
              .address = delegated_address,
              .port = std::stoul(delegated_port.value()),
              // TODO: Verify this is correct
              .server_name = server_name,
          };
        }

        try {
          if (auto srv_resp = get_srv_record(
                  std::format("_matrix-fed._tcp.{}", server_name));
              !srv_resp.empty()) {
            auto server = co_await pick_srv_server(srv_resp);
            co_return ResolvedServer{
                .address = server.host,
                .port = server.port,
                // TODO: Verify this is correct
                .server_name = server_name,
            };
          }
        } catch (const std::exception &err) {
          LOG_WARN << "Failed to fetch srv record: " << err.what();
        } catch (...) {
          LOG_WARN << "Failed to fetch srv record";
        }

        try {
          if (auto srv_resp =
                  get_srv_record(std::format("_matrix._tcp.{}", server_name));
              !srv_resp.empty()) {
            auto server = co_await pick_srv_server(srv_resp);
            co_return ResolvedServer{
                .address = server.host,
                .port = server.port,
                // TODO: Verify this is correct
                .server_name = server_name,
            };
          }
        } catch (const std::exception &err) {
          LOG_WARN << "Failed to fetch srv record: " << err.what();
        } catch (...) {
          LOG_WARN << "Failed to fetch srv record";
        }

        co_return ResolvedServer{
            .address = delegated_address,
            .port = MATRIX_SSL_PORT,
            // TODO: Verify this is correct
            .server_name = server_name,
        };
      }
    }
  } catch (const drogon::HttpException &err) {
    LOG_WARN << "Failed to send well-known request: " << err.what();
  } catch (const std::exception &err) {
    LOG_WARN << "Failed to send well-known request: " << err.what();
  } catch (...) {
    LOG_WARN << "Failed to send well-known request";
  }

  LOG_DEBUG << "Discovering server's SRV record";

  /*
   *  If the /.well-known request resulted in an error response, a server is
   * found by resolving an SRV record for _matrix-fed._tcp.<hostname>. This may
   * result in a hostname (to be resolved using AAAA or A records) and port.
   * Requests are made to the resolved IP address and port, with a Host header
   * of <hostname>. The target server must present a valid certificate for
   * <hostname>.
   */
  try {
    if (auto srv_resp =
            get_srv_record(std::format("_matrix-fed._tcp.{}", server_name));
        !srv_resp.empty()) {
      auto server = co_await pick_srv_server(srv_resp);
      co_return ResolvedServer{
          .address = server.host,
          .port = server.port,
          .server_name = server_name,
      };
    }
  } catch (const std::exception &err) {
    LOG_WARN << "Failed to fetch srv record: " << err.what();
  } catch (...) {
    LOG_WARN << "Failed to fetch srv record";
  }

  try {
    if (auto srv_resp =
            get_srv_record(std::format("_matrix._tcp.{}", server_name));
        !srv_resp.empty()) {
      auto server = co_await pick_srv_server(srv_resp);
      co_return ResolvedServer{
          .address = server.host,
          .port = server.port,
          .server_name = server_name,
      };
    }
  } catch (const std::exception &err) {
    LOG_WARN << "Failed to fetch srv record: " << err.what();
  } catch (...) {
    LOG_WARN << "Failed to fetch srv record";
  }

  co_return ResolvedServer{
      .address = address,
      .port = MATRIX_SSL_PORT,
      .server_name = server_name,
  };
}

/**
 * @brief Generates the Server-Server Authorization header for Matrix Federation
 * requests.
 *
 * This function generates the Server-Server Authorization header required for
 * Matrix Federation requests. It first creates a JSON object with the request
 * method, URI, origin, and destination. If the content is provided, it is also
 * added to the JSON object. The JSON object is then signed using the server's
 * name, key ID, and secret key. The signed JSON is used to create the
 * Authorization header, which is formatted as "X-Matrix
 * origin=<origin>,destination=<destination>,key=<key_id>,sig=<signature>". The
 * function returns the first Authorization header in the list of headers.
 *
 * @param data The AuthheaderData object containing the details required to
 * generate the header.
 * @return The Server-Server Authorization header.
 */
[[nodiscard]] std::string generate_ss_authheader(const AuthheaderData &data) {
  if (data.secret_key.empty()) {
    throw std::runtime_error("Secret key is empty");
  }
  if (!data.content.has_value()) {
    throw std::runtime_error("Invalid content");
  }

  auto request_json = json::object();
  request_json["method"] = data.method;
  request_json["uri"] = data.request_uri;
  request_json["origin"] = data.origin;
  request_json["destination"] = data.target;

  if (data.content) {
    request_json["content"] = data.content.value();
  }

  auto signed_json = json_utils::sign_json(data.server_name, data.key_id,
                                           data.secret_key, request_json);

  std::vector<std::string> authorization_headers;
  for (const auto &[key, val] :
       signed_json["signatures"][data.origin].items()) {
    authorization_headers.push_back(std::format(
        R"(X-Matrix origin="{}",destination="{}",key="{}",sig="{}")",
        data.origin, data.target, key, val.get<std::string>()));
  }

  return authorization_headers[0];
}

/**
 * @brief Parses a query parameter string into a map.
 *
 * This function takes a query string as input and parses it into a map where
 * the key is the parameter name and the value is a vector of values for that
 * parameter. The function uses the '&' character to split the query string into
 * pairs of parameter name and value. Then, it uses the '=' character to split
 * each pair into the parameter name and value. If a parameter has multiple
 * values, they are all added to the vector of values for that parameter in the
 * map.
 *
 * @param queryString The query string to parse.
 * @return An unordered map where the key is the parameter name and the value is
 * a vector of values for that parameter.
 *
 * @example
 *
 * ```cpp
 * auto query = req->getQuery();
 * auto query_map = parseQueryParamString(query);
 * ```
 */
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

/**
 * @brief Sends a federation request to a Matrix server.
 *
 * This function sends a federation request to a Matrix server. It first
 * generates the Server-Server Authorization header using the request's origin,
 * key ID, secret key, method, path, target, and content. It then creates a new
 * HTTP request, sets the method and path, and adds the Authorization header. It
 * also sets the Host header to the target server. The function sends the
 * request using the request's client and timeout. It returns a Task that will
 * eventually contain the HTTP response from the server.
 *
 * @param request The HTTPRequest object containing the details of the
 * federation request.
 * @return A Task that will eventually contain the HTTP response from the
 * server.
 */
[[nodiscard]] Task<drogon::HttpResponsePtr>
federation_request(const HTTPRequest request) {
  const AuthheaderData authheader_data{
      .server_name = request.origin,
      .key_id = request.key_id,
      .secret_key = request.secret_key,
      .method = drogon_to_string_method(request.method),
      .request_uri = request.path,
      .origin = request.origin,
      .target = request.target,
      .content = request.content};
  const auto auth_header = generate_ss_authheader(authheader_data);
  const auto req = HttpRequest::newHttpRequest();
  req->setMethod(request.method);
  req->setPath(request.path);
  req->addHeader("Authorization", auth_header);
  req->removeHeader("Host");
  req->addHeader("Host", request.target);

  co_return co_await request.client->sendRequestCoro(req, request.timeout);
}

/**
 * @brief Retrieves the server's key data from the configuration.
 *
 * This function retrieves the server's key data from the configuration. It
 * first reads the server key from the location specified in the configuration.
 * The server key is then split into its components (key type, key ID, and
 * private key in base64 format). The private key is decoded from base64 format.
 * The function then generates the public key from the private key using the
 * Sodium library's crypto_sign_ed25519_sk_to_pk function. The public key is
 * encoded in base64 format. The function returns a VerifyKeyData object that
 * contains the private key, the base64-encoded public key, the key ID, and the
 * key type.
 *
 * @param config The configuration from which to retrieve the server's key data.
 * @return A VerifyKeyData object that contains the server's key data.
 */
[[nodiscard]] VerifyKeyData get_verify_key_data(const Config &config) {
  std::ifstream t(config.matrix_config.server_key_location);
  std::string const server_key((std::istreambuf_iterator<char>(t)),
                               std::istreambuf_iterator<char>());
  std::istringstream buffer(server_key);
  std::vector<std::string> split_data{
      std::istream_iterator<std::string>(buffer),
      std::istream_iterator<std::string>()};

  auto private_key = json_utils::unbase64_key(split_data[2]);
  std::vector<unsigned char> public_key(crypto_sign_PUBLICKEYBYTES);
  crypto_sign_ed25519_sk_to_pk(public_key.data(), private_key.data());
  auto public_key_base64 = json_utils::base64_key(public_key);

  return {.private_key = private_key,
          .public_key_base64 = public_key_base64,
          .key_id = split_data[1],
          .key_type = split_data[0]};
}