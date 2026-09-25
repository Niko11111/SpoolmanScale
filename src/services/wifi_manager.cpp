#include "wifi_manager.h"

#include <WiFi.h>

#include "services/device_name.h"
#include "services/mdns_service.h"

void wifiManagerPrepareScan() {
  mdnsStop();
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

// Entries the RSSI sort covers. Networks beyond this stay in scan order, which
// only matters in places dense enough to see more than this many at once.
#define WIFI_MANAGER_SORT_MAX 64

int wifiManagerScanSorted(WifiScanEntry *out, int max) {
  const int n = WiFi.scanNetworks();
  if (n <= 0) {
    WiFi.scanDelete();
    return n;
  }

  // Sorting an index array leaves the scan results where the accessors
  // expect them.
  const int sort_n = n < WIFI_MANAGER_SORT_MAX ? n : WIFI_MANAGER_SORT_MAX;
  int idx[WIFI_MANAGER_SORT_MAX];
  for (int i = 0; i < sort_n; i++) idx[i] = i;
  for (int i = 0; i < sort_n - 1; i++) {
    for (int j = 0; j < sort_n - i - 1; j++) {
      if (WiFi.RSSI(idx[j]) < WiFi.RSSI(idx[j + 1])) {
        const int tmp = idx[j]; idx[j] = idx[j + 1]; idx[j + 1] = tmp;
      }
    }
  }

  int count = 0;
  for (int k = 0; k < sort_n && count < max; k++) {
    const String ssid = WiFi.SSID(idx[k]);
    if (ssid.length() == 0 || ssid.length() >= sizeof(out[0].ssid)) continue;
    bool seen = false;
    for (int s = 0; s < count && !seen; s++) seen = (strcmp(out[s].ssid, ssid.c_str()) == 0);
    if (seen) continue;
    strcpy(out[count].ssid, ssid.c_str());
    out[count].rssi = WiFi.RSSI(idx[k]);
    out[count].open = (WiFi.encryptionType(idx[k]) == WIFI_AUTH_OPEN);
    count++;
  }
  WiFi.scanDelete();
  return count;
}

void wifiManagerClearScan() {
  WiFi.scanDelete();
}

bool wifiManagerStartAp(const char* ssid, const char* password, IPAddress ip, IPAddress netmask) {
  mdnsStop();
  if (!WiFi.mode(WIFI_AP)) return false;
  if (!WiFi.softAP(ssid, password)) return false;
  // The scale is its own gateway: a phone only looks for a captive portal on
  // a network that claims a route out.
  return WiFi.softAPConfig(ip, ip, netmask);
}

void wifiManagerStopAp() {
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
}

void wifiManagerBegin(const char* ssid, const char* password) {
  WiFi.mode(WIFI_STA);
  // Has to happen before begin(): the DHCP client sends it with the request,
  // so the router lists the scale by name instead of as "espressif". It
  // sticks to the netif, which is why the reconnect watchdog in appLoop()
  // does not need to repeat it.
  WiFi.setHostname(deviceLabel());
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  // Modem sleep off. The loop serves every web request itself, and on core 3
  // a sleeping radio made each one crawl: /api/logs took 0.1 to 2.9 s instead
  // of 0.07 s, the log page's poll 0.7 s, and the UI stood still meanwhile.
  // Ping 76 ms -> 7 ms. Core 2 slept too and still answered in 0.1 s.
  // Bluetooth, once it runs next to WiFi, needs modem sleep back on for as
  // long as it is up (ESP-IDF coexistence).
  WiFi.setSleep(false);
#endif
  WiFi.begin(ssid, password);
}

bool wifiManagerConnect(const char* ssid, const char* password, int attempts, uint32_t interval_ms) {
  wifiManagerBegin(ssid, password);
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
