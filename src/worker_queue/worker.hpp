#pragma once

#include "ReconnectingLibEventHandler.hpp"

#include <amqpcpp.h>
#include <amqpcpp/libevent.h>
#include <amqpcpp/linux_tcp.h>
#include <event2/event.h>
#include <nlohmann/json.hpp>
#include <string>

class Worker {
public:
  Worker(const std::string &address, struct event_base *evbase);
  void start();

private:
  struct event_base *evbase;
  ReconnectingLibEventHandler handler;
  AMQP::TcpConnection connection;
  AMQP::TcpChannel channel;
  void process_request(const nlohmann::json &, const std::string &);
};