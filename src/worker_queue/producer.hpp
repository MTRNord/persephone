#pragma once
#include "ReconnectingLibEventHandler.hpp"

#include <amqpcpp.h>
#include <amqpcpp/libevent.h>
#include <amqpcpp/linux_tcp.h>
#include <nlohmann/json.hpp>
#include <string>

class Producer {
public:
  explicit Producer(const std::string &address, struct event_base *evbase);
  void enqueue_federation_request(const nlohmann::json &request,
                                  const std::string &reply_to);

private:
  struct event_base *evbase;
  ReconnectingLibEventHandler handler;
  AMQP::TcpConnection connection;
  AMQP::TcpChannel channel;
};