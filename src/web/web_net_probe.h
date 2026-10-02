#pragma once

#include <WebServer.h>

// GET /api/net/probe: how long a request to the backend that is set up takes
// from the device, plain or over TLS, and what it costs in memory. A
// maintenance tool with no page of its own - for measuring an https backend.
// It opens connections of its own and never touches the kept one. Registered
// by the logs page.
void netProbeRoutes(WebServer& srv);

// The worker side, see web_jobs.cpp: fills body with the JSON answer.
void netProbeRun(const char* url, String& body);
