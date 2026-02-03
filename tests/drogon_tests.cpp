#include <future>
#define DROGON_TEST_MAIN
#include <drogon/HttpAppFramework.h>
#include <drogon/drogon_test.h>
#include <drogon/utils/coroutine.h>
#include <string_view>
#include <utils/utils.hpp>
using namespace std::string_view_literals;

DROGON_TEST(DiscoveryTest) {
  /*auto discovery_test = [TEST_CTX]() -> drogon::Task<> {
    const auto *const server_name = "matrix.org";

    const auto result = co_await discover_server(server_name);
    CO_REQUIRE(result.address == "matrix-federation.matrix.org"sv);
    CO_REQUIRE(result.port == 443);
    CO_REQUIRE(result.server_name == server_name);

    const auto *const server_name_port = "matrix.org:443";

    const auto result_port = co_await discover_server(server_name_port);
    CO_REQUIRE(result_port.address == "matrix.org");
    CO_REQUIRE(result_port.port == 443);
    CO_REQUIRE(result_port.server_name == "matrix.org:443");
    ;

    const auto *const srv_test_server_name =
        "drogon-test-hs.midnightthoughts.space";

    const auto srv_result = co_await discover_server(srv_test_server_name);
    // This is a little hacky on the dns side due to cloudflare but this is
    // correct and expected.
    CO_REQUIRE(srv_result.address == "matrix.mtrnord.blog");
    CO_REQUIRE(srv_result.port == 443);
    CO_REQUIRE(srv_result.server_name == srv_test_server_name);

    co_return;
  };*/

  // sync_wait(discovery_test());
}

int main(int argc, char **argv) {
  std::promise<void> p1;
  std::future<void> f1 = p1.get_future();

  // Start the main loop on another thread
  std::thread thr([&]() {
    // Queues the promise to be fulfilled after starting the loop
    app().getLoop()->queueInLoop([&p1]() { p1.set_value(); });
    app().run();
  });

  // The future is only satisfied after the event loop started
  f1.get();
  int status = test::run(argc, argv);

  // Ask the event loop to shutdown and wait
  app().getLoop()->queueInLoop([]() { app().quit(); });
  thr.join();
  return status;
}