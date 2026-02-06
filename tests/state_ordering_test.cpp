#include "database/state_ordering.hpp"
#include <cstdint>
#include <limits>
#include <snitch/snitch.hpp>
#include <vector>

// Test access helper - friends with StateOrdering
class StateOrderingTestAccess {
public:
  using StateSnapshot = StateOrdering::StateSnapshot;
  using MinHashSignature = StateOrdering::MinHashSignature;

  static uint64_t hash_state_tuple(int event_type_nid, int state_key_nid,
                                   int event_nid) {
    return StateOrdering::hash_state_tuple(event_type_nid, state_key_nid,
                                           event_nid);
  }

  static MinHashSignature compute_minhash(const StateSnapshot &snapshot) {
    return StateOrdering::compute_minhash(snapshot);
  }

  static float estimate_jaccard(const MinHashSignature &a,
                                const MinHashSignature &b) {
    return StateOrdering::estimate_jaccard(a, b);
  }

  static std::vector<std::vector<size_t>>
  build_mst(const std::vector<MinHashSignature> &sigs) {
    return StateOrdering::build_mst(sigs);
  }

  static std::vector<std::pair<int64_t, int>>
  bfs_ordering(const std::vector<std::vector<size_t>> &mst,
               const std::vector<MinHashSignature> &sigs) {
    return StateOrdering::bfs_ordering(mst, sigs);
  }
};

using SA = StateOrderingTestAccess;

// ============================================================================
// hash_state_tuple tests
// ============================================================================

TEST_CASE("hash_state_tuple", "[state_ordering]") {
  SECTION("Same inputs produce same hash") {
    auto h1 = SA::hash_state_tuple(1, 2, 3);
    auto h2 = SA::hash_state_tuple(1, 2, 3);
    REQUIRE(h1 == h2);
  }

  SECTION("Different inputs produce different hashes") {
    auto h1 = SA::hash_state_tuple(1, 2, 3);
    auto h2 = SA::hash_state_tuple(1, 2, 4);
    auto h3 = SA::hash_state_tuple(1, 3, 3);
    auto h4 = SA::hash_state_tuple(2, 2, 3);
    REQUIRE(h1 != h2);
    REQUIRE(h1 != h3);
    REQUIRE(h1 != h4);
  }

  SECTION("Order of NIDs matters") {
    auto h1 = SA::hash_state_tuple(1, 2, 3);
    auto h2 = SA::hash_state_tuple(3, 2, 1);
    REQUIRE(h1 != h2);
  }
}

// ============================================================================
// compute_minhash tests
// ============================================================================

TEST_CASE("compute_minhash", "[state_ordering]") {
  SECTION("Empty snapshot") {
    SA::StateSnapshot snap{.start_index = 0, .state_tuple_hashes = {}};
    auto sig = SA::compute_minhash(snap);

    REQUIRE(sig.start_index == 0);
    // All signature values should be max (no elements to minimize)
    for (size_t i = 0; i < StateOrdering::MINHASH_SIZE; ++i) {
      REQUIRE(sig.signature[i] == std::numeric_limits<uint64_t>::max());
    }
  }

  SECTION("Single element snapshot") {
    auto hash = SA::hash_state_tuple(1, 1, 1);
    SA::StateSnapshot snap{.start_index = 42, .state_tuple_hashes = {hash}};
    auto sig = SA::compute_minhash(snap);

    REQUIRE(sig.start_index == 42);
    // With one element, signature values should not all be max
    bool has_non_max = false;
    for (size_t i = 0; i < StateOrdering::MINHASH_SIZE; ++i) {
      if (sig.signature[i] != std::numeric_limits<uint64_t>::max()) {
        has_non_max = true;
        break;
      }
    }
    REQUIRE(has_non_max);
  }

  SECTION("Same snapshot produces same signature") {
    auto h1 = SA::hash_state_tuple(1, 2, 3);
    auto h2 = SA::hash_state_tuple(4, 5, 6);
    SA::StateSnapshot snap{.start_index = 1, .state_tuple_hashes = {h1, h2}};

    auto sig1 = SA::compute_minhash(snap);
    auto sig2 = SA::compute_minhash(snap);

    REQUIRE(sig1.signature == sig2.signature);
  }
}

// ============================================================================
// estimate_jaccard tests
// ============================================================================

TEST_CASE("estimate_jaccard", "[state_ordering]") {
  SECTION("Identical signatures yield similarity of 1.0") {
    auto h1 = SA::hash_state_tuple(1, 2, 3);
    auto h2 = SA::hash_state_tuple(4, 5, 6);
    SA::StateSnapshot snap{.start_index = 1, .state_tuple_hashes = {h1, h2}};
    auto sig = SA::compute_minhash(snap);

    float similarity = SA::estimate_jaccard(sig, sig);
    REQUIRE(similarity == 1.0F);
  }

  SECTION("Completely different snapshots yield low similarity") {
    // Two snapshots with no overlapping elements
    SA::StateSnapshot snap_a{
        .start_index = 1,
        .state_tuple_hashes = {SA::hash_state_tuple(1, 1, 1),
                               SA::hash_state_tuple(2, 2, 2),
                               SA::hash_state_tuple(3, 3, 3)}};
    SA::StateSnapshot snap_b{
        .start_index = 2,
        .state_tuple_hashes = {SA::hash_state_tuple(100, 100, 100),
                               SA::hash_state_tuple(200, 200, 200),
                               SA::hash_state_tuple(300, 300, 300)}};

    auto sig_a = SA::compute_minhash(snap_a);
    auto sig_b = SA::compute_minhash(snap_b);

    float similarity = SA::estimate_jaccard(sig_a, sig_b);
    // Should be low (close to 0), but MinHash is probabilistic
    REQUIRE(similarity < 0.5F);
  }

  SECTION("Overlapping snapshots yield moderate similarity") {
    auto shared_hash = SA::hash_state_tuple(1, 1, 1);
    SA::StateSnapshot snap_a{
        .start_index = 1,
        .state_tuple_hashes = {shared_hash, SA::hash_state_tuple(2, 2, 2)}};
    SA::StateSnapshot snap_b{
        .start_index = 2,
        .state_tuple_hashes = {shared_hash,
                               SA::hash_state_tuple(100, 100, 100)}};

    auto sig_a = SA::compute_minhash(snap_a);
    auto sig_b = SA::compute_minhash(snap_b);

    float similarity = SA::estimate_jaccard(sig_a, sig_b);
    // With 1/3 overlap (Jaccard = 1/3 ≈ 0.33), similarity should be > 0
    REQUIRE(similarity > 0.0F);
    REQUIRE(similarity < 1.0F);
  }
}

// ============================================================================
// build_mst tests
// ============================================================================

TEST_CASE("build_mst", "[state_ordering]") {
  SECTION("Empty input") {
    std::vector<SA::MinHashSignature> sigs;
    auto mst = SA::build_mst(sigs);
    REQUIRE(mst.empty());
  }

  SECTION("Single node") {
    SA::StateSnapshot snap{.start_index = 1,
                           .state_tuple_hashes = {SA::hash_state_tuple(1, 1, 1)}};
    auto sig = SA::compute_minhash(snap);
    std::vector<SA::MinHashSignature> sigs = {sig};

    auto mst = SA::build_mst(sigs);
    REQUIRE(mst.size() == 1);
    REQUIRE(mst[0].empty()); // No edges for single node
  }

  SECTION("Two nodes") {
    SA::StateSnapshot snap_a{
        .start_index = 1,
        .state_tuple_hashes = {SA::hash_state_tuple(1, 1, 1)}};
    SA::StateSnapshot snap_b{
        .start_index = 2,
        .state_tuple_hashes = {SA::hash_state_tuple(2, 2, 2)}};

    auto sig_a = SA::compute_minhash(snap_a);
    auto sig_b = SA::compute_minhash(snap_b);
    std::vector<SA::MinHashSignature> sigs = {sig_a, sig_b};

    auto mst = SA::build_mst(sigs);
    REQUIRE(mst.size() == 2);
    // Node 0 should connect to node 1 and vice versa
    REQUIRE(mst[0].size() == 1);
    REQUIRE(mst[1].size() == 1);
    REQUIRE(mst[0][0] == 1);
    REQUIRE(mst[1][0] == 0);
  }

  SECTION("Three nodes form a tree") {
    SA::StateSnapshot snap_a{
        .start_index = 1,
        .state_tuple_hashes = {SA::hash_state_tuple(1, 1, 1)}};
    SA::StateSnapshot snap_b{
        .start_index = 2,
        .state_tuple_hashes = {SA::hash_state_tuple(2, 2, 2)}};
    SA::StateSnapshot snap_c{
        .start_index = 3,
        .state_tuple_hashes = {SA::hash_state_tuple(3, 3, 3)}};

    auto sig_a = SA::compute_minhash(snap_a);
    auto sig_b = SA::compute_minhash(snap_b);
    auto sig_c = SA::compute_minhash(snap_c);

    std::vector<SA::MinHashSignature> sigs = {sig_a, sig_b, sig_c};
    auto mst = SA::build_mst(sigs);

    REQUIRE(mst.size() == 3);
    // MST with 3 nodes has exactly 2 edges (4 entries in adjacency lists)
    size_t total_edges = 0;
    for (const auto &adj : mst) {
      total_edges += adj.size();
    }
    REQUIRE(total_edges == 4); // 2 edges × 2 (bidirectional)
  }
}

// ============================================================================
// bfs_ordering tests
// ============================================================================

TEST_CASE("bfs_ordering", "[state_ordering]") {
  SECTION("Empty input") {
    std::vector<std::vector<size_t>> mst;
    std::vector<SA::MinHashSignature> sigs;
    auto ordering = SA::bfs_ordering(mst, sigs);
    REQUIRE(ordering.empty());
  }

  SECTION("Single node") {
    SA::StateSnapshot snap{.start_index = 42,
                           .state_tuple_hashes = {SA::hash_state_tuple(1, 1, 1)}};
    auto sig = SA::compute_minhash(snap);

    std::vector<std::vector<size_t>> mst = {{}};
    std::vector<SA::MinHashSignature> sigs = {sig};

    auto ordering = SA::bfs_ordering(mst, sigs);
    REQUIRE(ordering.size() == 1);
    REQUIRE(ordering[0].first == 42);  // start_index
    REQUIRE(ordering[0].second == 0);  // order
  }

  SECTION("Linear chain 0-1-2") {
    SA::StateSnapshot snap_a{.start_index = 10,
                             .state_tuple_hashes = {SA::hash_state_tuple(1, 1, 1)}};
    SA::StateSnapshot snap_b{.start_index = 20,
                             .state_tuple_hashes = {SA::hash_state_tuple(2, 2, 2)}};
    SA::StateSnapshot snap_c{.start_index = 30,
                             .state_tuple_hashes = {SA::hash_state_tuple(3, 3, 3)}};

    auto sig_a = SA::compute_minhash(snap_a);
    auto sig_b = SA::compute_minhash(snap_b);
    auto sig_c = SA::compute_minhash(snap_c);

    // Linear: 0-1-2
    std::vector<std::vector<size_t>> mst = {{1}, {0, 2}, {1}};
    std::vector<SA::MinHashSignature> sigs = {sig_a, sig_b, sig_c};

    auto ordering = SA::bfs_ordering(mst, sigs);
    REQUIRE(ordering.size() == 3);

    // BFS from 0: order should be 0, 1, 2
    REQUIRE(ordering[0].first == 10);
    REQUIRE(ordering[0].second == 0);
    REQUIRE(ordering[1].first == 20);
    REQUIRE(ordering[1].second == 1);
    REQUIRE(ordering[2].first == 30);
    REQUIRE(ordering[2].second == 2);
  }

  SECTION("Round-trip: hash through BFS produces valid ordering") {
    // Create several snapshots with varying similarity
    std::vector<SA::StateSnapshot> snapshots;
    for (int i = 0; i < 5; ++i) {
      SA::StateSnapshot snap;
      snap.start_index = i * 10;
      for (int j = 0; j < 3; ++j) {
        snap.state_tuple_hashes.push_back(
            SA::hash_state_tuple(i, j, i + j));
      }
      snapshots.push_back(snap);
    }

    // Compute signatures
    std::vector<SA::MinHashSignature> sigs;
    for (const auto &snap : snapshots) {
      sigs.push_back(SA::compute_minhash(snap));
    }

    // Build MST
    auto mst = SA::build_mst(sigs);
    REQUIRE(mst.size() == 5);

    // BFS ordering
    auto ordering = SA::bfs_ordering(mst, sigs);
    REQUIRE(ordering.size() == 5);

    // Each start_index should appear exactly once
    std::set<int64_t> seen_indices;
    std::set<int> seen_orders;
    for (const auto &[idx, order] : ordering) {
      REQUIRE(seen_indices.insert(idx).second);
      REQUIRE(seen_orders.insert(order).second);
    }

    // Orders should be 0..4
    REQUIRE(*seen_orders.begin() == 0);
    REQUIRE(*seen_orders.rbegin() == 4);
  }
}
