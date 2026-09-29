#pragma once

#include <Arduino.h>
#include <IPAddress.h>
#include <stdint.h>

void wifiManagerPrepareScan();
int wifiManagerScanNetworks();
// The same scan without holding the loop: start it, then poll. The poll says
// -1 while it runs and the network count once it is done; a scan that could
// not start, or failed, reads -2. The accessors below then work as after
// wifiManagerScanNetworks().
bool wifiManagerStartScanAsync();
int wifiManagerScanPoll();
String wifiManagerScannedSSID(int index);
int wifiManagerScannedRSSI(int index);
void wifiManagerClearScan();

// One network from wifiManagerScanSorted().
struct WifiScanEntry {
  char ssid[33];
  int  rssi;
  bool open;
};
// Scans (blocking, a few seconds) and fills out with at most max networks,
// strongest first, each SSID once, hidden ones left out. Returns the count,
// or the negative scan result when the scan failed. Does not reset the radio
// first: after a failed begin() call wifiManagerPrepareScan() before it.
int wifiManagerScanSorted(WifiScanEntry *out, int max);

// The access point of the WiFi setup portal. Access point alone, no station:
// a station searching for a network drags the channel along and the phone
// drops off. Stopping leaves the radio in station mode, ready for begin().
bool wifiManagerStartAp(const char* ssid, const char* password, IPAddress ip, IPAddress netmask);
void wifiManagerStopAp();

// Starts the association and returns at once; the link comes up later.
// Scans every channel and joins the strongest access point on the SSID.
// With a bssid (and its channel) it joins that one access point instead:
// the roaming check in services/wifi_roam.h, and nothing else.
void wifiManagerBegin(const char* ssid, const char* password,
                      int32_t channel = 0, const uint8_t* bssid = nullptr);
// The reason code of the last lost or refused association, 0 before any.
// 200 is the access point gone quiet (beacon timeout), 201 none found.
uint8_t wifiManagerLastDisconnectReason();
const char* wifiManagerReasonName(uint8_t reason);
// "aa:bb:cc:dd:ee:ff", or "?" for a null pointer.
void wifiManagerBssidStr(const uint8_t* bssid, char* out, size_t len);
// The access point the station is on: "aa:bb:.. ch 6, -58 dBm".
void wifiManagerLinkLine(char* out, size_t len);
// An async scan for one SSID only, while connected or not. Polled with
// wifiManagerScanPoll(), read with the accessors above plus these two.
bool wifiManagerStartSsidScan(const char* ssid, uint32_t ms_per_chan);
const uint8_t* wifiManagerScannedBSSID(int index);
int wifiManagerScannedChannel(int index);
// wifiManagerBegin() plus a wait of up to attempts * interval_ms.
bool wifiManagerConnect(const char* ssid, const char* password, int attempts = 20, uint32_t interval_ms = 500);
bool wifiManagerIsConnected();
IPAddress wifiManagerLocalIP();
IPAddress wifiManagerGatewayIP();
IPAddress wifiManagerDNSIP();
int wifiManagerRSSI();
// Station MAC, the address a router needs for a fixed DHCP reservation.
String wifiManagerMacAddress();

// Stable per-device identity derived from the eFuse MAC, "ssc-<12 hex>".
// Lives here rather than in a backend module because more than one thing
// needs it now: BamBuddy registers under it and mDNS advertises it.
//
// The exact spelling is load bearing. BamBuddy has devices registered under
// this string, so a changed format would register a second one beside them.
const char* wifiManagerDeviceId();
