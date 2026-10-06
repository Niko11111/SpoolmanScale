#include "wifi_manager.h"

#include <WiFi.h>

#include "services/device_name.h"
#include "services/mdns_service.h"

// The name the DHCP client sends, so the router lists the scale by name
// instead of as "esp32s3-XXXXXX". Core 3 only stores it here and hands it to
// the station's netif when mode() switches the station on
// (WiFiGenericClass::mode()); a mode() that finds the station on already
// leaves the netif alone. Set after mode() on a cold start, the first DHCP
// request still carried the default. So it goes in before every mode() below
// that can switch the station on.
static void stageHostname() {
  WiFi.setHostname(deviceLabel());
}

void wifiManagerPrepareScan() {
  mdnsStop();
  WiFi.disconnect(true);
  delay(100);
  stageHostname();
  WiFi.mode(WIFI_STA);
  delay(100);
}

int wifiManagerScanNetworks() {
  return WiFi.scanNetworks();
}

bool wifiManagerStartScanAsync() {
  return WiFi.scanNetworks(true) == WIFI_SCAN_RUNNING;
}

int wifiManagerScanPoll() {
  return WiFi.scanComplete();
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
  stageHostname();
  WiFi.mode(WIFI_STA);
}

// Written from the WiFi event task, read from the loop. One byte, so no lock.
static volatile uint8_t s_last_disconnect_reason = 0;

static void onStaDisconnected(arduino_event_id_t event, arduino_event_info_t info) {
  (void)event;
  s_last_disconnect_reason = info.wifi_sta_disconnected.reason;
}

// Addresses handed out so far, written from the same task. One writer and a
// single word, so no lock either.
static volatile uint32_t s_got_ip_count = 0;

static void onStaGotIp(arduino_event_id_t event, arduino_event_info_t info) {
  (void)event;
  (void)info;
  s_got_ip_count = s_got_ip_count + 1;
}

void wifiManagerBegin(const char* ssid, const char* password,
                      int32_t channel, const uint8_t* bssid) {
  static bool event_registered = false;
  if (!event_registered) {
    WiFi.onEvent(onStaDisconnected, ARDUINO_EVENT_WIFI_STA_DISCONNECTED);
    WiFi.onEvent(onStaGotIp, ARDUINO_EVENT_WIFI_STA_GOT_IP);
    event_registered = true;
  }
  stageHostname();
  WiFi.mode(WIFI_STA);
  // The core's default is a fast scan, which joins the first access point it
  // hears on the SSID and never sorts by signal. With several access points
  // on one SSID that could be the weakest in the house, every time: a report
  // on 28.09.2026 had a scale retry the same dying one for 40 minutes. The
  // full scan costs a second or two per connect, in the background. The core
  // keeps the setting for its own reconnects, so boot, the watchdog and a
  // dropped link all get it from here.
  WiFi.setScanMethod(WIFI_ALL_CHANNEL_SCAN);
  WiFi.setSortMethod(WIFI_CONNECT_AP_BY_SIGNAL);
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  // Modem sleep off. The loop serves every web request itself, and on core 3
  // a sleeping radio made each one crawl: /api/logs took 0.1 to 2.9 s instead
  // of 0.07 s, the log page's poll 0.7 s, and the UI stood still meanwhile.
  // Ping 76 ms -> 7 ms. Core 2 slept too and still answered in 0.1 s.
  // Bluetooth, once it runs next to WiFi, needs modem sleep back on for as
  // long as it is up (ESP-IDF coexistence).
  WiFi.setSleep(false);
#endif
  WiFi.begin(ssid, password, channel, bssid);
}

uint8_t wifiManagerLastDisconnectReason() {
  return s_last_disconnect_reason;
}

const char* wifiManagerReasonName(uint8_t reason) {
  if (!reason) return "none";
  return WiFi.STA.disconnectReasonName((wifi_err_reason_t)reason);
}

void wifiManagerBssidStr(const uint8_t* bssid, char* out, size_t len) {
  if (!bssid) {
    snprintf(out, len, "?");
    return;
  }
  snprintf(out, len, "%02x:%02x:%02x:%02x:%02x:%02x",
           bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
}

void wifiManagerLinkLine(char* out, size_t len) {
  char b[18];
  wifiManagerBssidStr(WiFi.BSSID(), b, sizeof(b));
  snprintf(out, len, "%s ch %d, %d dBm", b, (int)WiFi.channel(), (int)WiFi.RSSI());
}

bool wifiManagerStartSsidScan(const char* ssid, uint32_t ms_per_chan) {
  return WiFi.scanNetworks(true, false, false, ms_per_chan, 0, ssid) == WIFI_SCAN_RUNNING;
}

const uint8_t* wifiManagerScannedBSSID(int index) {
  return WiFi.BSSID(index);
}

int wifiManagerScannedChannel(int index) {
  return WiFi.channel(index);
}

bool wifiManagerConnect(const char* ssid, const char* password, int attempts, uint32_t interval_ms) {
  const uint32_t ip_before = wifiManagerGotIpCount();
  wifiManagerBegin(ssid, password);
  for (int i = 0; i < attempts; i++) {
    delay(interval_ms);
    if (wifiManagerLinkUpSince(ip_before)) return true;
  }
  return false;
}

void wifiManagerStopConnect() {
  WiFi.disconnect();
}

uint32_t wifiManagerGotIpCount() {
  return s_got_ip_count;
}

bool wifiManagerLinkUpSince(uint32_t got_ip_count) {
  return WiFi.status() == WL_CONNECTED && s_got_ip_count != got_ip_count;
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
