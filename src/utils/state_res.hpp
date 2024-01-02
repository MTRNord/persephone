#pragma once
#include <nlohmann/json.hpp>

using json = nlohmann::json;

[[nodiscard]] json redact(const json &event, std::string room_version);

[[nodiscard]] std::string reference_hash(const json &event,
                                         std::string room_version);

[[nodiscard]] std::string event_id(const json &event, std::string room_version);
