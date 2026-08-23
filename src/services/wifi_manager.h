#pragma once

#include <Arduino.h>
#include <IPAddress.h>
#include <stdint.h>

void wifiManagerPrepareScan();
int wifiManagerScanNetworks();
String wifiManagerScannedSSID(int index);
int wifiManagerScannedRSSI(int index);
void wifiManagerClearScan();

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
