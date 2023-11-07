#pragma once
#include "httplib.h"

using namespace httplib;

std::string dump_headers(const Headers &headers);
std::string log(const Request &req, const Response &res);