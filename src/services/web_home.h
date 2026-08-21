#pragma once

#include <WebServer.h>

// Landing page at "/" plus the JSON it polls.
//
// The firmware upload page used to live at "/", which meant browsing the
// device address dropped you straight into a file picker with no way to reach
// anything else. That page is now at "/ota" and the root is a hub: what the
// device currently thinks its state is, and links to everything it serves.
void registerHomeRoutes(WebServer &srv);
