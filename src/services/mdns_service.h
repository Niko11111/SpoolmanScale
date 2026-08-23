#pragma once

#include <stdbool.h>

// Makes the scale reachable as http://<name>.local/ and advertises its web
// interface as an _http._tcp service, so it also turns up in Home Assistant,
// Bonjour browsers and Safari rather than only at an address the user has to
// read off the device and retype.
//
// ESPmDNS ships with the Arduino core, so nothing is added to lib_deps.

// Reads the stored name. Called from loadPrefs() before WiFi comes up,
// because the name is also handed to the DHCP client as the hostname and
// that has to happen before WiFi.begin().
void mdnsLoadHostname();

// Default is "spoolmanscale". Never null, never empty.
const char* mdnsHostname();

// Validates, stores in NVS and restarts the responder under the new name.
// Returns false and changes nothing when the name is not a legal host label.
// Takes effect immediately; no reboot.
bool mdnsSetHostname(const char* name);

// True while the responder is up and the name actually resolves. The web
// screen falls back to showing the bare IP when it is not.
bool mdnsRunning();

// Idempotent, called once a second from appLoop() next to
// webServerSyncState(). Derives the responder and the advertised service
// from WiFi, the stored name and whether the web server is listening, so
// nothing has to be remembered at the point where any of those change.
void mdnsSyncState();

// Longest name accepted. A host label may be 63 characters, but the status
// bar has about 94 pixels for it and the point of the name is that someone
// can type it.
#define MDNS_HOSTNAME_MAX 20
