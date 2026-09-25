#pragma once

#include <stdbool.h>

// The mDNS responder. Makes the scale answer to "<label>.local" and
// advertises its web interface as an _http._tcp service, so it also turns up
// in Home Assistant, Bonjour browsers and Safari rather than only at an
// address the user has to read off the device and retype.
//
// The name itself lives in services/device_name.h - this file only answers to
// it. That module also owns the switch that turns the responder off, for a
// network that does not want .local traffic on it.
//
// ESPmDNS ships with the Arduino core, so nothing is added to lib_deps.

// True while the responder is up. The address lines fall back to the bare IP
// when it is not.
bool mdnsRunning();

// Idempotent, called once a second from appLoop() next to
// webServerSyncState(). Derives the responder and the advertised service from
// WiFi, the stored name, the mDNS switch and whether the web server is
// listening, so nothing has to be remembered at the point where any of those
// change - a rename takes effect on the next pass, without a reboot.
void mdnsSyncState();

// Takes the responder down now, while the network interface still exists.
// Called before anything that switches WiFi off or changes its mode: on
// core 3 the interface goes with the mode, and the responder freed after
// that walks a dead interface (panic in mdns_free(), seen on the first
// WiFi scan). The next mdnsSyncState() brings it back once the link is up.
void mdnsStop();
