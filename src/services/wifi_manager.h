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
void wifiManagerBegin(const char* ssid, const char* password);
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
