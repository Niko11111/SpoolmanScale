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
