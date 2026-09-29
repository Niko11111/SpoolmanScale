#pragma once

#include <WebServer.h>

// GET /api/net/probe?url=<address>: how long a request to any address takes
// from the device, plain or over TLS, and what it costs in memory. A
// maintenance tool with no page of its own - for measuring an https backend
// or a cloud service before building for it. Registered by the logs page.
void netProbeRoutes(WebServer& srv);

// The worker side, see web_jobs.cpp: fills body with the JSON answer.
void netProbeRun(const char* url, String& body);
