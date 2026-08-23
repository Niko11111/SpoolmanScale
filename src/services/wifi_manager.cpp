#include "wifi_manager.h"

#include <WiFi.h>

#include "services/mdns_service.h"

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
  // Has to happen before begin(): the DHCP client sends it with the request,
  // so the router lists the scale by name instead of as "espressif". It
  // sticks to the netif, which is why the reconnect watchdog in appLoop()
  // does not need to repeat it.
  WiFi.setHostname(mdnsHostname());
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

const char* wifiManagerDeviceId() {
  static char id[20] = "";
  if (!id[0]) {
    // Mirrors the "sb-<mac>" of BamBuddy's own daemon so the two are
    // recognisable side by side in a device list.
    uint64_t mac = ESP.getEfuseMac();
    uint8_t b[6];
    for (int i = 0; i < 6; i++) b[i] = (uint8_t)(mac >> (8 * i));
    snprintf(id, sizeof(id), "ssc-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5]);
  }
  return id;
}
