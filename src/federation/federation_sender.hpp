#pragma once

#include "utils/config.hpp"
#include "utils/utils.hpp"
#include <cstdint>
#include <drogon/drogon.h>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include "nlohmann/json.hpp"
#pragma GCC diagnostic pop
#else
#include <nlohmann/json.hpp>
#endif
#include <string>
#include <vector>

using json = nlohmann::json;

/// Persistent, restart-safe federation event sender.
///
/// Events are first written to `federation_event_queue` in the DB, then
/// delivered asynchronously. On startup, pending entries are recovered
/// and retried. Per-server health is tracked in `federation_destinations`
/// to avoid hammering unreachable servers.
class FederationSender {
public:
  /// Initialize with server config. Call once at startup after migrations.
  /// Starts the background queue processor.
  static void start(std::string server_name, std::string key_id,
                    std::vector<unsigned char> secret_key);

  /// Enqueue a PDU for delivery to all servers in a room.
  /// Writes to DB, then kicks off async delivery. Returns immediately.
  /// For room v3+, event_id is stripped from the PDU before sending.
  static void broadcast_pdu(const json &event, const std::string &room_id,
                            const std::string &exclude_server,
                            std::string_view room_version);

private:
  /// Background loop: periodically scans queue for deliverable entries.
  static drogon::Task<> process_queue_loop();

  /// Attempt delivery of all queued events for one destination.
  static drogon::Task<bool> deliver_to_server(const std::string &destination);

  /// Update federation_destinations on success/failure.
  static drogon::Task<> mark_server_success(const std::string &server);
  static drogon::Task<> mark_server_failure(const std::string &server);

  /// Check if a server is currently in backoff.
  static drogon::Task<bool> is_server_in_backoff(const std::string &server);

  // Server identity (set once at startup)
  static std::string _server_name;
  static std::string _key_id;
  static std::vector<unsigned char> _secret_key;

  // Per-delivery-attempt backoff
  static constexpr int MAX_RETRIES_PER_ATTEMPT = 3;
  static constexpr int INITIAL_BACKOFF_MS = 1000;
  static constexpr int MAX_RETRY_BACKOFF_MS = 10000;

  // Per-server backoff (based on consecutive failures)
  // Schedule: 30s, 1m, 2m, 4m, ... capped at 24h
  static constexpr int64_t MAX_SERVER_BACKOFF_MS = 86400000; // 24 hours

  // Queue processor polling interval
  static constexpr double QUEUE_POLL_INTERVAL_S = 5.0;
};
