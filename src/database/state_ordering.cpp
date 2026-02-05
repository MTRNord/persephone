#include "state_ordering.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <drogon/HttpAppFramework.h>
#include <drogon/orm/Exception.h>
#include <exception>
#include <functional>
#include <limits>
#include <queue>
#include <trantor/utils/Logger.h>
#include <utility>
#include <vector>

namespace {
// Simple constexpr LCG for generating hash coefficients at compile time
// Using constants from Numerical Recipes (Knuth MMIX LCG)
// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers)
constexpr uint64_t LCG_MULTIPLIER = 6364136223846793005ULL;
constexpr uint64_t LCG_INCREMENT = 1442695040888963407ULL;
constexpr uint64_t MINHASH_SEED = 0x517cc1b727220a95ULL;
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers)

constexpr uint64_t lcg_next(uint64_t state) {
  return (state * LCG_MULTIPLIER) + LCG_INCREMENT;
}

// Generate hash coefficients at compile time using consteval
consteval std::array<std::pair<uint64_t, uint64_t>, StateOrdering::MINHASH_SIZE>
generate_hash_coefficients() {
  std::array<std::pair<uint64_t, uint64_t>, StateOrdering::MINHASH_SIZE>
      coeffs{};
  uint64_t state = MINHASH_SEED;
  for (size_t idx = 0; idx < StateOrdering::MINHASH_SIZE; ++idx) {
    state = lcg_next(state);
    const uint64_t coeff_a = state;
    state = lcg_next(state);
    const uint64_t coeff_b = state;
    coeffs.at(idx) = {coeff_a, coeff_b};
  }
  return coeffs;
}

constexpr auto HASH_COEFFICIENTS = generate_hash_coefficients();
} // namespace

// FNV-1a hash constants
// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers)
constexpr uint64_t FNV_OFFSET_BASIS = 0xcbf29ce484222325ULL;
constexpr uint64_t FNV_PRIME = 0x100000001b3ULL;
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers)

uint64_t StateOrdering::hash_state_tuple(const int event_type_nid,
                                         const int state_key_nid,
                                         const int event_nid) {
  // Combine the three NIDs into a single hash using FNV-1a
  uint64_t hash = FNV_OFFSET_BASIS;

  auto mix = [&](uint64_t val) {
    hash ^= val;
    hash *= FNV_PRIME;
  };

  mix(static_cast<uint64_t>(event_type_nid));
  mix(static_cast<uint64_t>(state_key_nid));
  mix(static_cast<uint64_t>(event_nid));

  return hash;
}

StateOrdering::MinHashSignature
StateOrdering::compute_minhash(const StateSnapshot &snapshot) {
  MinHashSignature sig{};
  sig.start_index = snapshot.start_index;

  // Initialize with max values
  sig.signature.fill(std::numeric_limits<uint64_t>::max());

  // For each element in the set, compute hash with each hash function
  for (const uint64_t element_hash : snapshot.state_tuple_hashes) {
    for (size_t i = 0; i < MINHASH_SIZE; ++i) {
      // h_i(x) = (a_i * x + b_i) mod p (we use 64-bit arithmetic)
      const auto &[coeff_a, coeff_b] = HASH_COEFFICIENTS.at(i);
      const uint64_t h = (coeff_a * element_hash) + coeff_b;
      sig.signature.at(i) = std::min(sig.signature.at(i), h);
    }
  }

  return sig;
}

float StateOrdering::estimate_jaccard(const MinHashSignature &sig_a,
                                      const MinHashSignature &sig_b) {
  size_t matches = 0;
  for (size_t i = 0; i < MINHASH_SIZE; ++i) {
    if (sig_a.signature.at(i) == sig_b.signature.at(i)) {
      ++matches;
    }
  }
  return static_cast<float>(matches) / static_cast<float>(MINHASH_SIZE);
}

std::vector<std::vector<size_t>>
StateOrdering::build_mst(const std::vector<MinHashSignature> &signatures) {
  const size_t n = signatures.size();
  if (n == 0) {
    return {};
  }

  // Adjacency list for MST
  std::vector<std::vector<size_t>> mst(n);

  if (n == 1) {
    return mst;
  }

  // Prim's algorithm with lazy edge addition
  // Use distance as (1 - jaccard_similarity) so lower is better
  std::vector<bool> in_mst(n, false);
  std::vector<float> min_dist(n, std::numeric_limits<float>::max());
  std::vector<size_t> parent(n, SIZE_MAX);

  // Priority queue: (distance, node)
  using PQEntry = std::pair<float, size_t>;
  std::priority_queue<PQEntry, std::vector<PQEntry>, std::greater<>> pq;

  // Start from node 0
  min_dist[0] = 0.0F;
  pq.emplace(0.0F, 0);

  while (!pq.empty()) {
    auto [dist, u] = pq.top();
    pq.pop();

    if (in_mst[u]) {
      continue;
    }
    in_mst[u] = true;

    // Add edge to MST (except for root)
    if (parent[u] != SIZE_MAX) {
      mst[parent[u]].push_back(u);
      mst[u].push_back(parent[u]);
    }

    // Update distances to neighbors
    for (size_t v = 0; v < n; ++v) {
      if (in_mst[v]) {
        continue;
      }

      // Compute similarity on demand (lazy evaluation)
      const float similarity = estimate_jaccard(signatures[u], signatures[v]);

      if (const float edge_dist = 1.0F - similarity; edge_dist < min_dist[v]) {
        min_dist[v] = edge_dist;
        parent[v] = u;
        pq.emplace(edge_dist, v);
      }
    }
  }

  return mst;
}

std::vector<std::pair<int64_t, int>>
StateOrdering::bfs_ordering(const std::vector<std::vector<size_t>> &mst,
                            const std::vector<MinHashSignature> &signatures) {
  const size_t n = mst.size();
  if (n == 0) {
    return {};
  }

  std::vector<std::pair<int64_t, int>> ordering;
  ordering.reserve(n);

  std::vector<bool> visited(n, false);
  std::queue<size_t> queue;

  // BFS from node 0
  queue.push(0);
  visited[0] = true;
  int order = 0;

  while (!queue.empty()) {
    const size_t u = queue.front();
    queue.pop();

    ordering.emplace_back(signatures[u].start_index, order++);

    for (const size_t v : mst[u]) {
      if (!visited[v]) {
        visited[v] = true;
        queue.push(v);
      }
    }
  }

  return ordering;
}

drogon::Task<bool> StateOrdering::needs_reordering(int room_nid) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    const auto query = co_await sql->execSqlCoro(
        "SELECT EXISTS(SELECT 1 FROM temporal_state "
        "WHERE room_nid = $1 AND ordering IS NULL) as needs_reorder",
        room_nid);

    co_return query.at(0)["needs_reorder"].as<bool>();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Failed to check reordering need: " << e.base().what();
    co_return false;
  }
}

drogon::Task<void> StateOrdering::reorder_room(int room_nid) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    // Get all unique start_index values (state snapshots) for this room
    const auto snapshots_query = co_await sql->execSqlCoro(
        "SELECT DISTINCT start_index FROM temporal_state "
        "WHERE room_nid = $1 ORDER BY start_index",
        room_nid);

    if (snapshots_query.empty()) {
      co_return;
    }

    std::vector<StateSnapshot> snapshots;
    snapshots.reserve(snapshots_query.size());

    // For each snapshot, get the state tuples
    for (const auto &row : snapshots_query) {
      const int64_t start_idx = row["start_index"].as<int64_t>();

      // Get all state tuples active at this start_index
      const auto tuples_query = co_await sql->execSqlCoro(
          "SELECT event_type_nid, state_key_nid, event_nid "
          "FROM temporal_state "
          "WHERE room_nid = $1 AND start_index <= $2 "
          "AND (end_index > $2 OR end_index IS NULL)",
          room_nid, start_idx);

      StateSnapshot snapshot;
      snapshot.start_index = start_idx;
      snapshot.state_tuple_hashes.reserve(tuples_query.size());

      for (const auto &tuple_row : tuples_query) {
        const uint64_t h =
            hash_state_tuple(tuple_row["event_type_nid"].as<int>(),
                             tuple_row["state_key_nid"].as<int>(),
                             tuple_row["event_nid"].as<int>());
        snapshot.state_tuple_hashes.push_back(h);
      }

      snapshots.push_back(std::move(snapshot));
    }

    if (snapshots.empty()) {
      co_return;
    }

    // Compute MinHash signatures
    std::vector<MinHashSignature> signatures;
    signatures.reserve(snapshots.size());
    for (const auto &snapshot : snapshots) {
      signatures.push_back(compute_minhash(snapshot));
    }

    // Build MST and compute BFS ordering
    const auto mst = build_mst(signatures);
    auto ordering = bfs_ordering(mst, signatures);

    // Update the database with new ordering values
    const auto transaction = co_await sql->newTransactionCoro();
    if (transaction == nullptr) {
      LOG_ERROR << "Failed to create transaction for reordering room "
                << room_nid;
      co_return;
    }

    for (const auto &[start_index, order] : ordering) {
      co_await transaction->execSqlCoro(
          "UPDATE temporal_state SET ordering = $1 "
          "WHERE room_nid = $2 AND start_index = $3",
          order, room_nid, start_index);
    }

    LOG_INFO << "Reordered " << ordering.size() << " state snapshots for room "
             << room_nid;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Failed to reorder room " << room_nid << ": "
              << e.base().what();
  }
}

drogon::Task<void> StateOrdering::reorder_all_rooms() {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    // Get all rooms that have temporal state
    const auto rooms_query = co_await sql->execSqlCoro(
        "SELECT DISTINCT room_nid FROM temporal_state");

    for (const auto &row : rooms_query) {
      if (const int room_nid = row["room_nid"].as<int>();
          co_await needs_reordering(room_nid)) {
        co_await reorder_room(room_nid);
      }
    }

    LOG_INFO << "Completed reordering for all rooms";
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Failed to reorder all rooms: " << e.base().what();
  }
}
