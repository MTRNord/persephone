#pragma once
#include <amqpcpp.h>
#include <amqpcpp/libevent.h>
#include <amqpcpp/linux_tcp.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/util.h>
#include <memory>
#include <string>

class ReconnectingLibEventHandler final : public AMQP::LibEventHandler {
public:
  ReconnectingLibEventHandler(struct event_base *evbase,
                              const std::string &address);
  void onError(AMQP::TcpConnection *connection, const char *message) override;
  void onClosed(AMQP::TcpConnection *connection) override;

private:
  struct event_base *evbase;
  std::string address;
  std::unique_ptr<struct event, void (*)(struct event *)> reconnect_event;

  void reconnect();
  void scheduleReconnect();
  static void onReconnect(evutil_socket_t fd, short what, void *arg);
};