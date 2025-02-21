#pragma once
#include "ReconnectingLibEventHandler.hpp"

#include <amqpcpp.h>
#include <amqpcpp/libevent.h>
#include <amqpcpp/linux_tcp.h>
#include <string>
#ifdef __GNUC__
// Ignore false positives (see https://github.com/nlohmann/json/issues/3808)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include "nlohmann/json.hpp"
#pragma GCC diagnostic pop
#else
#include <nlohmann/json.hpp>
#endif

class Producer {
public:
  explicit Producer(const std::string &address, struct event_base *evbase);
  void enqueue_federation_request(const nlohmann::json &request,
                                  const std::string &reply_to);

private:
  ReconnectingLibEventHandler handler;
  AMQP::TcpConnection connection;
  AMQP::TcpChannel channel;
};