#pragma once

#include <stdint.h>

#include "services/wifi_manager.h"

// What the browser asks of the WiFi (web/pages/page_config_wifi.cpp),
// carried out on the loop: a scan beside the link, and a try of another
// network that becomes the preferred one only once the scale is on it. One
// that does not come up within WIFI_TRY_GIVE_UP_MS leaves the scale on the
// network it was on, so a typo cannot lock the browser out. Loop task only;
// the HTTP handlers run there as well.

constexpr int WIFI_REMOTE_SCAN_MAX = 20;

enum WifiRemoteScan : uint8_t { WRS_NONE, WRS_WAITING, WRS_RUNNING, WRS_DONE, WRS_FAILED };
enum WifiRemoteTry  : uint8_t { WRT_NONE, WRT_WAITING, WRT_TRYING, WRT_UP, WRT_FAILED };

// False while one is under way already.
bool wifiRemoteScanRequest();
WifiRemoteScan wifiRemoteScanState();
// Strongest first, each SSID once. Valid while the state reads WRS_DONE.
const WifiScanEntry* wifiRemoteScanResults(int* n);

// False while a try is under way, or for a name or password that does not
// fit. An empty password takes the stored one of a known network.
bool wifiRemoteTryRequest(const char* ssid, const char* typed_pass);
WifiRemoteTry wifiRemoteTryState();
const char* wifiRemoteTrySsid();
// The network the scale was on when the try began.
const char* wifiRemoteTryFrom();

// radio_free: nothing else is using the radio (setup screens, Improv, the
// setup portal, roaming, the fallback). A try or a scan starts only then.
void wifiRemoteTick(bool radio_free);
// A try or a scan is under way: the reconnect watchdog and the roaming check
// leave the station alone.
bool wifiRemoteBusy();
