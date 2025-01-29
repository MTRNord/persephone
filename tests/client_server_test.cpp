#define DROGON_TEST_MAIN
#include <drogon/drogon.h>
#include <drogon/drogon_test.h>

using namespace drogon;

DROGON_TEST(ClientServerCtrlTest) {
  // TODO: This requires persephone to be running. This means changing the ci to
  // also run a postgres
  const auto client = HttpClient::newHttpClient("http://127.0.0.1:8008");

  // Test versions endpoint
  {
    const auto req = HttpRequest::newHttpRequest();
    req->setPath("/_matrix/client/versions");
    client->sendRequest(
        req, [TEST_CTX](const ReqResult result, const HttpResponsePtr &resp) {
          REQUIRE(result == ReqResult::Ok);
          REQUIRE(resp->getStatusCode() == k200OK);
          const auto json = resp->getJsonObject();
          REQUIRE(json != nullptr);
          REQUIRE(json->isMember("versions"));
        });
  }

  // Test whoami endpoint
  {
    const auto req = HttpRequest::newHttpRequest();
    req->setPath("/_matrix/client/v3/account/whoami");
    req->addHeader("Authorization", "Bearer valid_token");
    client->sendRequest(
        req, [TEST_CTX](const ReqResult result, const HttpResponsePtr &resp) {
          REQUIRE(result == ReqResult::Ok);
          // TODO: We get 401 instead of 200. TLDR: we need to first generate a
          // valid token
          REQUIRE(resp->getStatusCode() == k200OK);
          const auto json = resp->getJsonObject();
          REQUIRE(json != nullptr);
          REQUIRE(json->isMember("user_id"));
        });
  }

  // Test user_available endpoint
  {
    const auto req = HttpRequest::newHttpRequest();
    req->setPath("/_matrix/client/v3/register/available?username=testuser");
    client->sendRequest(
        req, [TEST_CTX](const ReqResult result, const HttpResponsePtr &resp) {
          REQUIRE(result == ReqResult::Ok);
          REQUIRE(resp->getStatusCode() == k200OK);
          const auto json = resp->getJsonObject();
          REQUIRE(json != nullptr);
          REQUIRE(json->isMember("available"));
        });
  }

  // Test login endpoint
  {
    const auto req = HttpRequest::newHttpRequest();
    req->setPath("/_matrix/client/v3/login");
    req->setMethod(Post);
    Json::Value body;
    body["type"] = "m.login.password";
    body["identifier"]["type"] = "m.id.user";
    body["identifier"]["user"] = "testuser";
    body["password"] = "password";
    req->setBody(body.toStyledString());
    client->sendRequest(
        req, [TEST_CTX](const ReqResult result, const HttpResponsePtr &resp) {
          // TODO: We get 403 instead of 200. TLDR: we need to first register
          // the user
          REQUIRE(result == ReqResult::Ok);
          REQUIRE(resp->getStatusCode() == k200OK);
          const auto json = resp->getJsonObject();
          REQUIRE(json != nullptr);
          REQUIRE(json->isMember("access_token"));
        });
  }

  // Test register_user endpoint
  {
    const auto req = HttpRequest::newHttpRequest();
    req->setPath("/_matrix/client/v3/register");
    req->setMethod(Post);
    Json::Value body;
    body["username"] = "newuser";
    body["password"] = "password";
    req->setBody(body.toStyledString());
    client->sendRequest(
        req, [TEST_CTX](const ReqResult result, const HttpResponsePtr &resp) {
          // TODO: We get 401 instead of 200. TLDR: we need to first generate a
          // valid session (iirc?)
          REQUIRE(result == ReqResult::Ok);
          REQUIRE(resp->getStatusCode() == k200OK);
          const auto json = resp->getJsonObject();
          REQUIRE(json != nullptr);
          REQUIRE(json->isMember("user_id"));
        });
  }

  // Test joinRoomIdOrAlias endpoint
  {
    const auto req = HttpRequest::newHttpRequest();
    req->setPath("/_matrix/client/v3/join/!roomid:server");
    req->setMethod(Post);
    req->addHeader("Authorization", "Bearer valid_token");
    client->sendRequest(
        req, [TEST_CTX](const ReqResult result, const HttpResponsePtr &resp) {
          REQUIRE(result == ReqResult::Ok);
          // TODO: We get 401 instead of 200. TLDR: we need to first generate a
          // valid token
          REQUIRE(resp->getStatusCode() == k200OK);
        });
  }

  // Test createRoom endpoint
  {
    const auto req = HttpRequest::newHttpRequest();
    req->setPath("/_matrix/client/v3/createRoom");
    req->setMethod(Post);
    req->addHeader("Authorization", "Bearer valid_token");
    Json::Value body;
    body["name"] = "Test Room";
    req->setBody(body.toStyledString());
    client->sendRequest(
        req, [TEST_CTX](const ReqResult result, const HttpResponsePtr &resp) {
          REQUIRE(result == ReqResult::Ok);
          // TODO: We get 401 instead of 200. TLDR: we need to first generate a
          // valid token
          REQUIRE(resp->getStatusCode() == k200OK);
          const auto json = resp->getJsonObject();
          REQUIRE(json != nullptr);
          REQUIRE(json->isMember("room_id"));
        });
  }

  // Test state endpoint
  {
    const auto req = HttpRequest::newHttpRequest();
    req->setPath("/_matrix/client/v3/rooms/!roomid:server/state/m.room.name");
    req->addHeader("Authorization", "Bearer valid_token");
    client->sendRequest(
        req, [TEST_CTX](const ReqResult result, const HttpResponsePtr &resp) {
          REQUIRE(result == ReqResult::Ok);
          // TODO: We get 401 instead of 200. TLDR: we need to first generate a
          // valid token and then create a room to test with
          REQUIRE(resp->getStatusCode() == k200OK);
          const auto json = resp->getJsonObject();
          REQUIRE(json != nullptr);
        });
  }
}

int main(int argc, char **argv) {
  using namespace drogon;

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
