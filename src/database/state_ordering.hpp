#pragma once

#include <array>
#include <cstdint>
#include <drogon/drogon.h>
#include <utility>
#include <vector>

/**
 * @brief State ordering for temporal state compression.
 *
 * Implements BFS ordering of state rows based on Matthew Hodgson's
 * state-experiments research. By ordering similar states together,
 * database compression achieves up to 66x better ratios.
 *
 * Algorithm:
 * 1. Compute MinHash signatures for each state snapshot
 * 2. Build minimum spanning tree using Jaccard similarity as edge weight
 * 3. BFS traverse MST to assign ordering numbers
 * 4. Update temporal_state.ordering column
 */
class StateOrdering {
public:
  /// Number of hash functions for MinHash (higher = more accurate, slower)
  static constexpr size_t MINHASH_SIZE = 128;

  /// Reorder all state for a specific room (e.g., after federation join)
  [[nodiscard]] static drogon::Task<void> reorder_room(int room_nid);

  /// Reorder state for all rooms (e.g., nightly maintenance)
  [[nodiscard]] static drogon::Task<void> reorder_all_rooms();

  /// Check if a room needs reordering (has NULL ordering values)
  [[nodiscard]] static drogon::Task<bool> needs_reordering(int room_nid);

private:
  /// Represents a state snapshot for similarity computation
  struct StateSnapshot {
    int64_t start_index;
    std::vector<uint64_t> state_tuple_hashes; // (type_nid, key_nid, event_nid)
  };

  /// MinHash signature for a state snapshot
  struct MinHashSignature {
    int64_t start_index;
    std::array<uint64_t, MINHASH_SIZE> signature;
  };

  /// Edge in the similarity graph
  struct Edge {
    size_t from;
    size_t to;
    float similarity; // Jaccard similarity (0-1)
  };

  /// Compute hash for a state tuple
  static uint64_t hash_state_tuple(const int event_type_nid,
                                   const int state_key_nid,
                                   const int event_nid);

  /// Compute MinHash signature for a state snapshot
  static MinHashSignature compute_minhash(const StateSnapshot &snapshot);

  /// Estimate Jaccard similarity from MinHash signatures
  static float estimate_jaccard(const MinHashSignature &sig_a,
                                const MinHashSignature &sig_b);

  /// Build minimum spanning tree using Prim's algorithm
  static std::vector<std::vector<size_t>>
  build_mst(const std::vector<MinHashSignature> &signatures);

  /// BFS traverse MST to compute ordering
  static std::vector<std::pair<int64_t, int>>
  bfs_ordering(const std::vector<std::vector<size_t>> &mst,
               const std::vector<MinHashSignature> &signatures);
};
