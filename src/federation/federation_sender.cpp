#include "federation_sender.hpp"
#include "database/database.hpp"
#include "utils/room_version.hpp"
#include "utils/utils.hpp"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpClient.h>
#include <drogon/orm/Exception.h>
#include <format>
#include <random>
#include <string>
#include <string_view>
#include <trantor/net/EventLoop.h>
#include <trantor/utils/Logger.h>
#include <vector>

// Static member definitions
std::string FederationSender::_server_name;
std::string FederationSender::_key_id;
std::vector<unsigned char> FederationSender::_secret_key;
std::mutex FederationSender::active_deliveries_mutex_;
std::unordered_set<std::string> FederationSender::active_deliveries_;

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

static std::string random_suffix() {
  static constexpr std::string_view chars =
      "0123456789abcdefghijklmnopqrstuvwxyz";
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<size_t> dist(0, chars.size() - 1);
  std::string result;
  result.reserve(8);
  for (int i = 0; i < 8; ++i) {
    result += chars[dist(gen)];
  }
  return result;
}

void FederationSender::start(std::string server_name, std::string key_id,
                             std::vector<unsigned char> secret_key) {
  _server_name = std::move(server_name);
  _key_id = std::move(key_id);
  _secret_key = std::move(secret_key);

  LOG_INFO << "FederationSender started for " << _server_name;
  drogon::async_run([]() -> drogon::Task<> {
    try {
      co_await process_queue_loop();
    } catch (const std::exception &e) {
      LOG_ERROR << "FederationSender: Queue loop crashed: " << e.what();
    } catch (...) {
      LOG_ERROR
          << "FederationSender: Queue loop crashed with unknown exception";
    }
  });
}

bool FederationSender::try_lock_delivery(const std::string &destination) {
  std::lock_guard lock(active_deliveries_mutex_);
  return active_deliveries_.insert(destination).second;
}

void FederationSender::unlock_delivery(const std::string &destination) {
  std::lock_guard lock(active_deliveries_mutex_);
  active_deliveries_.erase(destination);
}

void FederationSender::broadcast_pdu(const json &event,
                                     const std::string &room_id,
                                     const std::string &exclude_server,
                                     std::string_view room_version) {
  // Strip event_id for room v3+ (PDUs sent over federation must not include it)
  auto pdu = event;
  if (room_version::uses_reference_hash(std::string(room_version))) {
    pdu.erase("event_id");
  }

  const auto &room_id_copy = room_id;
  const auto &exclude_copy = exclude_server;
  const auto &server_name = _server_name;

  drogon::async_run([pdu, room_id_copy, exclude_copy,
                     server_name]() -> drogon::Task<> {
    try {
      const auto servers = co_await Database::get_servers_in_room(room_id_copy);

      const auto sql = drogon::app().getDbClient();
      if (sql == nullptr) {
        LOG_ERROR << "FederationSender: No database connection";
        co_return;
      }

      // Filter out the sending server and ourselves
      std::vector<std::string> destinations;
      for (const auto &server : servers) {
        if (server != exclude_copy && server != server_name) {
          destinations.push_back(server);
        }
      }

      if (destinations.empty()) {
        co_return;
      }

      const auto event_id = pdu.value("event_id", "");
      const auto event_json_str = pdu.dump();
      const auto created_at = now_ms();

      try {
        // Batch INSERT destinations (single query with multiple VALUES)
        std::string dest_values;
        for (size_t i = 0; i < destinations.size(); ++i) {
          if (i > 0) {
            dest_values += ", ";
          }
          dest_values += std::format("(${})", i + 1);
        }
        std::string dest_query = std::format(
            "INSERT INTO federation_destinations (server_name) VALUES {} "
            "ON CONFLICT DO NOTHING",
            dest_values);

        // Build parameter pack for destinations insert
        // Drogon's execSqlCoro needs individual params, so we use a raw SQL
        // approach with string params
        for (const auto &dest : destinations) {
          co_await sql->execSqlCoro(
              "INSERT INTO federation_destinations (server_name) "
              "VALUES ($1) ON CONFLICT DO NOTHING",
              dest);
        }

        // Batch INSERT queue entries
        for (const auto &dest : destinations) {
          co_await sql->execSqlCoro(
              "INSERT INTO federation_event_queue "
              "(destination, event_id, event_json, created_at) "
              "VALUES ($1, $2, $3::jsonb, $4) ON CONFLICT DO NOTHING",
              dest, event_id, event_json_str, created_at);
        }

        // Batch check backoff status for all destinations at once
        const auto backoff_result = co_await sql->execSqlCoro(
            "SELECT server_name FROM federation_destinations "
            "WHERE retry_after_ts > $1",
            now_ms());

        std::unordered_set<std::string> backed_off_servers;
        for (const auto &row : backoff_result) {
          backed_off_servers.insert(row["server_name"].as<std::string>());
        }

        // Fire delivery attempts for non-backed-off destinations
        for (const auto &dest : destinations) {
          if (backed_off_servers.contains(dest)) {
            continue;
          }

          if (!try_lock_delivery(dest)) {
            continue; // Already being delivered to
          }

          drogon::async_run([dest]() -> drogon::Task<> {
            try {
              co_await deliver_to_server(dest);
            } catch (const std::exception &e) {
              LOG_ERROR << "FederationSender: Delivery to " << dest
                        << " failed: " << e.what();
            } catch (...) {
              LOG_ERROR << "FederationSender: Delivery to " << dest
                        << " failed with unknown exception";
            }
            unlock_delivery(dest);
          });
        }
      } catch (const drogon::orm::DrogonDbException &e) {
        LOG_ERROR << "FederationSender: Failed to queue events: "
                  << e.base().what();
      }
    } catch (const std::exception &e) {
      LOG_ERROR << "FederationSender: broadcast_pdu failed: " << e.what();
    } catch (...) {
      LOG_ERROR << "FederationSender: broadcast_pdu failed with unknown "
                   "exception";
    }
  });
}

drogon::Task<> FederationSender::process_queue_loop() {
  LOG_INFO << "FederationSender: Queue processor started";

  int iterations_since_probe = 0;

  while (true) {
    co_await drogon::sleepCoro(
        trantor::EventLoop::getEventLoopOfCurrentThread(),
        std::chrono::milliseconds(
            static_cast<int>(QUEUE_POLL_INTERVAL_S * 1000)));

    ++iterations_since_probe;

    try {
      const auto sql = drogon::app().getDbClient();
      if (sql == nullptr) {
        continue;
      }

      // Get distinct destinations with pending events
      const auto destinations = co_await sql->execSqlCoro(
          "SELECT DISTINCT destination FROM federation_event_queue");

      for (const auto &row : destinations) {
        const auto destination = row["destination"].as<std::string>();

        // Skip if server is in backoff
        if (co_await is_server_in_backoff(destination)) {
          continue;
        }

        if (!try_lock_delivery(destination)) {
          continue; // Already being delivered to
        }

        // Launch independent delivery coroutine
        const auto dest = destination;
        drogon::async_run([dest]() -> drogon::Task<> {
          try {
            co_await deliver_to_server(dest);
          } catch (const std::exception &e) {
            LOG_ERROR << "FederationSender: Delivery to " << dest
                      << " failed: " << e.what();
          } catch (...) {
            LOG_ERROR << "FederationSender: Delivery to " << dest
                      << " failed with unknown exception";
          }
          unlock_delivery(dest);
        });
      }

      // Periodic probe: try one backed-off server that has queued events
      if (iterations_since_probe >= PROBE_INTERVAL_ITERATIONS) {
        iterations_since_probe = 0;

        const auto probe_result = co_await sql->execSqlCoro(
            "SELECT DISTINCT q.destination FROM federation_event_queue q "
            "JOIN federation_destinations d ON d.server_name = q.destination "
            "WHERE d.retry_after_ts > $1 "
            "ORDER BY q.destination LIMIT 1",
            now_ms());

        if (!probe_result.empty()) {
          const auto probe_dest =
              probe_result.at(0)["destination"].as<std::string>();

          if (try_lock_delivery(probe_dest)) {
            LOG_INFO << "FederationSender: Probing backed-off server "
                     << probe_dest;
            drogon::async_run([probe_dest]() -> drogon::Task<> {
              try {
                co_await deliver_to_server(probe_dest);
              } catch (const std::exception &e) {
                LOG_WARN << "FederationSender: Probe to " << probe_dest
                         << " failed: " << e.what();
              } catch (...) {
                LOG_WARN << "FederationSender: Probe to " << probe_dest
                         << " failed with unknown exception";
              }
              unlock_delivery(probe_dest);
            });
          }
        }
      }
    } catch (const std::exception &e) {
      LOG_ERROR << "FederationSender: Queue processor error: " << e.what();
    }
  }
}

drogon::Task<bool>
FederationSender::deliver_to_server(const std::string &destination) {
  try {
    const auto sql = drogon::app().getDbClient();
    if (sql == nullptr) {
      co_return false;
    }

    // Fetch all queued events for this destination
    const auto queue_entries = co_await sql->execSqlCoro(
        "SELECT queue_id, event_json FROM federation_event_queue "
        "WHERE destination = $1 ORDER BY queue_id",
        destination);

    if (queue_entries.empty()) {
      co_return true;
    }

    // Collect PDUs
    std::vector<json> pdus;
    std::vector<int> queue_ids;
    pdus.reserve(queue_entries.size());
    queue_ids.reserve(queue_entries.size());

    for (const auto &row : queue_entries) {
      pdus.push_back(json::parse(row["event_json"].as<std::string>()));
      queue_ids.push_back(row["queue_id"].as<int>());
    }

    // Resolve destination server
    ResolvedServer resolved;
    bool resolve_failed = false;
    try {
      resolved = co_await discover_server(destination);
    } catch (const std::exception &e) {
      LOG_WARN << "FederationSender: Failed to resolve " << destination << ": "
               << e.what();
      resolve_failed = true;
    }
    if (resolve_failed) {
      co_await mark_server_failure(destination);
      co_return false;
    }

    // Build transaction body
    const auto ts = now_ms();
    const auto txn_id = std::format("{}_{}", ts, random_suffix());

    json transaction_body;
    transaction_body["origin"] = _server_name;
    transaction_body["origin_server_ts"] = ts;
    transaction_body["pdus"] = pdus;

    // Debug: log what we're sending
    for (const auto &p : pdus) {
      LOG_DEBUG << "FederationSender: Sending PDU to " << destination
                << " type=" << p.value("type", "?")
                << " sender=" << p.value("sender", "?")
                << " room_id=" << p.value("room_id", "?")
                << " depth=" << p.value("depth", 0)
                << " auth_events=" << p.value("auth_events", json::array()).size()
                << " prev_events=" << p.value("prev_events", json::array()).size()
                << " has_signatures=" << p.contains("signatures")
                << " has_hashes=" << p.contains("hashes")
                << " has_event_id=" << p.contains("event_id");
    }

    // Retry loop with exponential backoff
    const auto path = std::format("/_matrix/federation/v1/send/{}", txn_id);
    int backoff_ms = INITIAL_BACKOFF_MS;

    for (int attempt = 0; attempt <= MAX_RETRIES_PER_ATTEMPT; ++attempt) {
      if (attempt > 0) {
        co_await drogon::sleepCoro(
            trantor::EventLoop::getEventLoopOfCurrentThread(),
            std::chrono::milliseconds(backoff_ms));
        backoff_ms = std::min(backoff_ms * 2, MAX_RETRY_BACKOFF_MS);
      }

      try {
        const auto client = create_http_client_for_resolved(resolved);

        const auto response = co_await federation_request(
            HTTPRequest{.client = client,
                        .method = drogon::Put,
                        .path = path,
                        .key_id = _key_id,
                        .secret_key = _secret_key,
                        .origin = _server_name,
                        .target = destination,
                        .host_header = build_host_header(resolved),
                        .content = transaction_body,
                        .timeout = 30});

        if (response && response->getStatusCode() == drogon::k200OK) {
          // Success - delete queue entries and mark server as healthy
          for (const auto &qid : queue_ids) {
            co_await sql->execSqlCoro(
                "DELETE FROM federation_event_queue WHERE queue_id = $1", qid);
          }
          co_await mark_server_success(destination);
          LOG_INFO << "FederationSender: Delivered " << pdus.size()
                   << " PDU(s) to " << destination;
          co_return true;
        }

        if (response) {
          LOG_WARN << "FederationSender: " << destination << " returned status "
                   << response->getStatusCode() << " (attempt " << attempt + 1
                   << "/" << MAX_RETRIES_PER_ATTEMPT + 1
                   << ") body: " << response->body();
        }
      } catch (const std::exception &e) {
        LOG_WARN << "FederationSender: Error sending to " << destination
                 << " (attempt " << attempt + 1 << "/"
                 << MAX_RETRIES_PER_ATTEMPT + 1 << "): " << e.what();
      }
    }

    // All retries exhausted
    co_await mark_server_failure(destination);
    LOG_ERROR << "FederationSender: Failed to deliver to " << destination
              << " after " << MAX_RETRIES_PER_ATTEMPT + 1 << " attempts";
    co_return false;
  } catch (const std::exception &e) {
    LOG_ERROR << "FederationSender: deliver_to_server(" << destination
              << ") failed: " << e.what();
    co_return false;
  }
}

drogon::Task<>
FederationSender::mark_server_success(const std::string &server) {
  try {
    const auto sql = drogon::app().getDbClient();
    if (sql == nullptr) {
      co_return;
    }
    co_await sql->execSqlCoro(
        "UPDATE federation_destinations "
        "SET last_successful_ts = $2, failure_count = 0, retry_after_ts = 0 "
        "WHERE server_name = $1",
        server, now_ms());
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "FederationSender: mark_server_success failed: "
              << e.base().what();
  }
}

drogon::Task<>
FederationSender::mark_server_failure(const std::string &server) {
  try {
    const auto sql = drogon::app().getDbClient();
    if (sql == nullptr) {
      co_return;
    }

    // Read current failure count
    const auto result = co_await sql->execSqlCoro(
        "SELECT failure_count FROM federation_destinations "
        "WHERE server_name = $1",
        server);

    int failure_count = 1;
    if (!result.empty()) {
      failure_count = result.at(0)["failure_count"].as<int>() + 1;
    }

    // Gentle early backoff: 5s, 10s, 20s, 40s for first 4 failures
    // Then exponential growth: 5s * 2^(n-1) from failure 5+, capped at 24h
    const auto exponent = std::min(failure_count - 1, 20);
    int64_t backoff_ms =
        BASE_SERVER_BACKOFF_MS * (static_cast<int64_t>(1) << exponent);
    backoff_ms = std::min(backoff_ms, MAX_SERVER_BACKOFF_MS);

    const auto current_time = now_ms();
    const auto retry_after = current_time + backoff_ms;

    co_await sql->execSqlCoro(
        "UPDATE federation_destinations "
        "SET last_failure_ts = $2, failure_count = $3, retry_after_ts = $4 "
        "WHERE server_name = $1",
        server, current_time, failure_count, retry_after);

    LOG_WARN << "FederationSender: " << server << " marked as failing "
             << "(count=" << failure_count << ", backoff=" << backoff_ms / 1000
             << "s)";
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "FederationSender: mark_server_failure failed: "
              << e.base().what();
  }
}

drogon::Task<bool>
FederationSender::is_server_in_backoff(const std::string &server) {
  try {
    const auto sql = drogon::app().getDbClient();
    if (sql == nullptr) {
      co_return false;
    }

    const auto result = co_await sql->execSqlCoro(
        "SELECT retry_after_ts FROM federation_destinations "
        "WHERE server_name = $1",
        server);

    if (result.empty()) {
      co_return false;
    }

    const auto retry_after = result.at(0)["retry_after_ts"].as<int64_t>();
    co_return now_ms() < retry_after;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "FederationSender: is_server_in_backoff failed: "
              << e.base().what();
    co_return false;
  }
}
