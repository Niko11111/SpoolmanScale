#include "wifi_manager.h"

#include <WiFi.h>

void wifiManagerPrepareScan() {
  WiFi.disconnect(true);
  delay(100);
  WiFi.mode(WIFI_STA);
  delay(100);
}

int wifiManagerScanNetworks() {
  return WiFi.scanNetworks();
}

String wifiManagerScannedSSID(int index) {
  return WiFi.SSID(index);
}

int wifiManagerScannedRSSI(int index) {
  return WiFi.RSSI(index);
}

void wifiManagerClearScan() {
  WiFi.scanDelete();
}

bool wifiManagerConnect(const char* ssid, const char* password, int attempts, uint32_t interval_ms) {
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  for (int i = 0; i < attempts; i++) {
    delay(interval_ms);
    if (WiFi.status() == WL_CONNECTED) return true;
  }
  return false;
}

bool wifiManagerIsConnected() {
  return WiFi.status() == WL_CONNECTED;
}

IPAddress wifiManagerLocalIP() {
  return WiFi.localIP();
}

IPAddress wifiManagerGatewayIP() {
  return WiFi.gatewayIP();
}

IPAddress wifiManagerDNSIP() {
  return WiFi.dnsIP();
}

int wifiManagerRSSI() {
  return WiFi.RSSI();
}

String wifiManagerMacAddress() {
  return WiFi.macAddress();
}
