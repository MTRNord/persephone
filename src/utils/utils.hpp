#pragma once
#include "httplib.h"
#include <string>

using namespace httplib;

std::string dump_headers(const Headers &headers);
std::string log(const Request &req, const Response &res);

void return_error(Response &res, std::string errorcode, std::string error);

std::string random_string(const unsigned long len);
