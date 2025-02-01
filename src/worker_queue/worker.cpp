#include "worker.hpp"

#include <trantor/utils/Logger.h>

Worker::Worker(const std::string &address, struct event_base *evbase_passed)
    : evbase(evbase_passed), handler(evbase, AMQP::Address(address)),
      connection(&handler, AMQP::Address(address)), channel(&connection) {
  channel.declareQueue("federation_requests");
}

[[noreturn]] void Worker::start() {
  LOG_INFO << "Starting worker queue";
  channel.consume("federation_requests")
      .onReceived([this](const AMQP::Message &message,
                         const uint64_t deliveryTag, bool redelivered) {
        const nlohmann::json request = nlohmann::json::parse(message.body());
        const std::string &reply_to = message.replyTo();
        process_request(request, reply_to);
        channel.ack(deliveryTag);
      });
  LOG_INFO << "Worker queue started";
  while (true) {
    event_base_dispatch(evbase);
    LOG_ERROR << "Worker queue exited, restarting event loop";
  }
  LOG_ERROR << "Worker queue exited";
}

void Worker::process_request(const nlohmann::json &request,
                             const std::string &reply_to) {
  LOG_INFO << "Processing request: " << request.dump();

  // TODO: Implement processing of federation requests
  // For now, just log the request and acknowledge it
  channel.startTransaction();
  channel.publish("", reply_to, request.dump());
  channel.commitTransaction();
}