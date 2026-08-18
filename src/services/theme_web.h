#pragma once

#include <WebServer.h>

// Theme editor routes, registered onto the existing web server rather than
// standing up a second one. Registered unconditionally; each handler checks
// webThemeEnabled() at request time, because WebServer::stop() does not free
// handlers so route sets cannot be swapped by re-registering.
void registerThemeRoutes(WebServer &srv);
