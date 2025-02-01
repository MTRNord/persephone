#include "ReconnectingLibEventHandler.hpp"

#include <amqpcpp/address.h>
#include <trantor/utils/Logger.h>

ReconnectingLibEventHandler::ReconnectingLibEventHandler(
    struct event_base *evbase, const std::string &address)
    : AMQP::LibEventHandler(evbase), evbase(evbase), address(address),
      reconnect_event(nullptr, event_free) {}

void ReconnectingLibEventHandler::onError(AMQP::TcpConnection *connection,
                                          const char *message) {
  LOG_ERROR << "Connection error: " << message;
  scheduleReconnect();
}

void ReconnectingLibEventHandler::onClosed(
    AMQP::TcpConnection * /*connection*/) {
  LOG_INFO << "Connection closed.";
  scheduleReconnect();
}

void ReconnectingLibEventHandler::reconnect() {
  LOG_INFO << "Attempting to reconnect to RabbitMQ server...";
  new AMQP::TcpConnection(this, AMQP::Address(address));
  LOG_INFO << "Reconnected to RabbitMQ server.";
}

void ReconnectingLibEventHandler::scheduleReconnect() {
  LOG_INFO << "Scheduling reconnect...";
  constexpr timeval timeout = {.tv_sec = 5, .tv_usec = 0}; // 5 seconds
  reconnect_event.reset(event_new(evbase, -1, 0, onReconnect, this));
  event_add(reconnect_event.get(), &timeout);
}

void ReconnectingLibEventHandler::onReconnect(evutil_socket_t fd, short what,
                                              void *arg) {
  auto *self = static_cast<ReconnectingLibEventHandler *>(arg);
  self->reconnect();
}