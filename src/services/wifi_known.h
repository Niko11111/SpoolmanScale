#pragma once

#include <stddef.h>
#include <stdint.h>

#include "services/wifi_known_rules.h"

// The remembered networks in NVS and the preferred one; the rules are in
// wifi_known_rules.h. Loop task only.
//
// cfg_wifi_ssid and cfg_wifi_password are the network in use. The preferred
// network is what the user chose last, stored under the keys "wifi_ssid" and
// "wifi_pass" as it always was, so a firmware that knows no list still finds
// it. The two differ only while the scale is on a fallback network.

// At boot, after the stored network was read into cfg_wifi_*.
void wifiKnownBoot();

// The user chose a network (setup screen, browser, Improv): it becomes the
// preferred one. It enters the list only once it connected.
void wifiKnownSetPreferred(const char* ssid, const char* pass);
const char* wifiPreferredSsid();
const char* wifiPreferredPass();
// Counts the choices, so the switching in app/wifi_fallback.cpp can tell that
// whatever it had under way was for an older one.
uint32_t wifiPreferredGeneration();

// The station is up on cfg_wifi_*: remembers it, at the front. Cheap when
// nothing changed, so it can run on every pass.
void wifiKnownNoteConnected();

const WifiKnownList& wifiKnownList();
// True when the network was in the list. A network the scale is on stays
// out of it until the user chooses it again. The preferred network can be
// forgotten too; it stays preferred until another is chosen, which is why
// the saved networks screen does not offer it.
bool wifiKnownForgetSsid(const char* ssid);
