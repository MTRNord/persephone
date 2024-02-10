#include "utils/json_utils.hpp"

//  This file is essentially C

/* this lets the source compile without afl-clang-fast/lto */
#ifndef __AFL_FUZZ_TESTCASE_LEN

ssize_t fuzz_len;                // skipcq:  CXX-W2009
unsigned char fuzz_buf[1024000]; // skipcq: CXX-W2066, CXX-W2009
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#define __AFL_FUZZ_TESTCASE_LEN fuzz_len
#define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
#define __AFL_FUZZ_INIT() void sync(void);
#define __AFL_LOOP(x)                                                          \
  ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
#define __AFL_INIT() sync()
// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#endif

__AFL_FUZZ_INIT();

/* To ensure checks are not optimized out it is recommended to disable
   code optimization for the fuzzer harness main() */
#pragma clang optimize off
#pragma GCC optimize("O0") // NOLINT(clang-diagnostic-unknown-pragmas)

int main() {

  ssize_t len;        /* how much input did we read? */
  unsigned char *buf; /* test case buffer pointer    */
  __AFL_INIT();
  // skipcq: CXX-C1000
  buf = __AFL_FUZZ_TESTCASE_BUF; // this must be assigned before __AFL_LOOP!

  while (__AFL_LOOP(UINT_MAX)) {
    // TODO: Json signing
    len = __AFL_FUZZ_TESTCASE_LEN; // do not use the macro directly in a call!
  }

  return 0;
}
