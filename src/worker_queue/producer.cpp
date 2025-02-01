#include "producer.hpp"

Producer::Producer(const std::string &address, struct event_base *evbase)
    : handler(evbase, AMQP::Address(address)),
      connection(&handler, AMQP::Address(address)), channel(&connection) {
  channel.declareQueue("federation_requests");
}

void Producer::enqueue_federation_request(const nlohmann::json &request,
                                          const std::string &reply_to) {
  // Ensure the queue exists
  channel.declareQueue("federation_requests");

  AMQP::Envelope envelope(request.dump());
  envelope.setReplyTo(reply_to);
  channel.publish("", "federation_requests", envelope);
}