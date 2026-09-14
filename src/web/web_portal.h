#pragma once

#include <WebServer.h>

// The WiFi setup portal's pages: the form, what it posts to, and a redirect
// for everything else, which is what makes a phone open the form by itself.
//
// Outside the gate system on purpose. This server only listens while the
// portal screen is open on the device (see webServerSyncState()), on an access
// point whose password only that screen shows, and it can do nothing but
// hand over a WiFi network to try. Plain HTML without JavaScript, so a phone's
// captive portal sheet shows it the same as a browser does.
//
// Registered once, on the server object web_server.cpp keeps for it.
void registerPortalRoutes(WebServer &srv);
