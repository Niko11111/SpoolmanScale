#include "wifi_roam.h"

#include <Arduino.h>
#include <WiFi.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "services/wifi_manager.h"

// Overridable from a build flag, so a test does not have to wait half an hour
// for each round.
#ifndef WIFI_ROAM_INTERVAL_MS
#define WIFI_ROAM_INTERVAL_MS      (30UL * 60UL * 1000UL)
#endif
#ifndef WIFI_ROAM_LONE_INTERVAL_MS
#define WIFI_ROAM_LONE_INTERVAL_MS (6UL * 60UL * 60UL * 1000UL)
#endif
// Weaker than this counts as weak. Around -70 dBm web requests still work
// but start to need retries; the report behind this sat at -78.
#define WIFI_ROAM_RSSI_WEAK        (-70)
#define WIFI_ROAM_WEAK_HOLD_MS     (2UL * 60UL * 1000UL)
#define WIFI_ROAM_MARGIN_DB        10
#define WIFI_ROAM_SAMPLE_MS        10000UL
// Per channel, 13 channels: under two seconds for the whole scan.
#define WIFI_ROAM_SCAN_MS_PER_CHAN 120
#define WIFI_ROAM_SCAN_TIMEOUT_MS  10000UL
// Association, handshake and DHCP on the new access point.
#define WIFI_ROAM_SWITCH_MS        20000UL

enum RoamState : uint8_t { RS_IDLE, RS_SCANNING, RS_SWITCHING };

static RoamState s_state       = RS_IDLE;
static uint32_t  s_phase_start = 0;
static uint32_t  s_last_sample = 0;
static bool      s_weak        = false;
static uint32_t  s_weak_since  = 0;
static bool      s_scanned     = false;
static uint32_t  s_last_scan   = 0;
static bool      s_lone        = false;   // the last scan saw no second AP
static uint8_t   s_target[6]   = {0};

bool wifiRoamSwitching() { return s_state == RS_SWITCHING; }

static void sampleSignal(uint32_t now) {
  if (s_last_sample != 0 && now - s_last_sample < WIFI_ROAM_SAMPLE_MS) return;
  s_last_sample = now;
  const int rssi = WiFi.RSSI();
  // 0 is what the core answers when it has no reading.
  if (rssi != 0 && rssi < WIFI_ROAM_RSSI_WEAK) {
    if (!s_weak) {
      s_weak = true;
      s_weak_since = now;
    }
  } else {
    s_weak = false;
  }
}

// Reads the finished scan and, when it is worth it, starts the switch.
static void evaluateScan(int n, bool quiet, const char* ssid, const char* password,
                         uint32_t now) {
  uint8_t cur[6] = {0};
  if (WiFi.status() != WL_CONNECTED || !WiFi.BSSID(cur)) {
    wifiManagerClearScan();
    return;
  }
  // The current access point's figure from the same scan where it is in it,
  // so both sides of the comparison are measured the same way.
  int cur_rssi = WiFi.RSSI();
  int best = -1;
  int best_rssi = -128;
  int others = 0;
  for (int i = 0; i < n; i++) {
    const uint8_t* b = wifiManagerScannedBSSID(i);
    if (!b) continue;
    const int rssi = wifiManagerScannedRSSI(i);
    if (memcmp(b, cur, 6) == 0) {
      cur_rssi = rssi;
      continue;
    }
    others++;
    if (rssi > best_rssi) {
      best_rssi = rssi;
      best = i;
    }
  }
  s_lone = (others == 0);

  char cur_s[18];
  wifiManagerBssidStr(cur, cur_s, sizeof(cur_s));
  if (best < 0) {
    logSDf("WiFi roam: no other access point on this network, staying on %s, %d dBm",
           cur_s, cur_rssi);
    wifiManagerClearScan();
    return;
  }

  char best_s[18];
  wifiManagerBssidStr(wifiManagerScannedBSSID(best), best_s, sizeof(best_s));
  const int channel = wifiManagerScannedChannel(best);
  if (best_rssi - cur_rssi < WIFI_ROAM_MARGIN_DB) {
    logSDf("WiFi roam: %d other AP, best %s ch %d %d dBm, staying on %s %d dBm",
           others, best_s, channel, best_rssi, cur_s, cur_rssi);
    wifiManagerClearScan();
    return;
  }
  // Somebody picked the scale up while the scan ran.
  if (!quiet) {
    logSDf("WiFi roam: %s is better by %d dB, not switching while in use",
           best_s, best_rssi - cur_rssi);
    wifiManagerClearScan();
    return;
  }

  // Copied before the scan results are freed; the pointer lives in them.
  memcpy(s_target, wifiManagerScannedBSSID(best), 6);
  wifiManagerClearScan();
  logSDf("WiFi roam: switching from %s %d dBm to %s ch %d %d dBm",
         cur_s, cur_rssi, best_s, channel, best_rssi);
  s_state = RS_SWITCHING;
  s_phase_start = now;
  wifiManagerBegin(ssid, password, channel, s_target);
}

void wifiRoamTick(bool quiet, const char* ssid, const char* password) {
  if (!ssid || !ssid[0]) return;
  const uint32_t now = millis();

  if (s_state == RS_SWITCHING) {
    if (WiFi.status() == WL_CONNECTED) {
      char line[64];
      wifiManagerLinkLine(line, sizeof(line));
      const uint8_t* b = WiFi.BSSID();
      const bool on_target = b && memcmp(b, s_target, 6) == 0;
      // Not on the target: the old link would not let go, or the new one
      // failed and the core joined whatever it found. The line says where.
      logSDf("WiFi roam: %s after %lu ms, %s",
             on_target ? "switched" : "not on the chosen AP",
             (unsigned long)(now - s_phase_start), line);
      s_state = RS_IDLE;
      s_weak = false;
    } else if (now - s_phase_start >= WIFI_ROAM_SWITCH_MS) {
      const uint8_t reason = wifiManagerLastDisconnectReason();
      logSDf("WiFi roam: switch not done after %lu s (reason %u, %s), "
             "the normal reconnect takes over",
             (unsigned long)(WIFI_ROAM_SWITCH_MS / 1000), reason,
             wifiManagerReasonName(reason));
      s_state = RS_IDLE;
      s_weak = false;
    }
    return;
  }

  if (s_state == RS_SCANNING) {
    const int n = wifiManagerScanPoll();
    if (n == -1) {
      if (now - s_phase_start >= WIFI_ROAM_SCAN_TIMEOUT_MS) {
        logSD("WiFi roam: scan did not finish, dropped");
        wifiManagerClearScan();
        s_state = RS_IDLE;
      }
      return;
    }
    s_state = RS_IDLE;
    if (n < 0) {
      logSDf("WiFi roam: scan failed (%d)", n);
      wifiManagerClearScan();
      return;
    }
    evaluateScan(n, quiet, ssid, password, now);
    return;
  }

  if (WiFi.status() != WL_CONNECTED) {
    s_weak = false;
    return;
  }
  sampleSignal(now);
  if (!quiet || !s_weak || now - s_weak_since < WIFI_ROAM_WEAK_HOLD_MS) return;
  const uint32_t interval = s_lone ? WIFI_ROAM_LONE_INTERVAL_MS : WIFI_ROAM_INTERVAL_MS;
  if (s_scanned && now - s_last_scan < interval) return;

  s_scanned = true;
  s_last_scan = now;
  if (!wifiManagerStartSsidScan(ssid, WIFI_ROAM_SCAN_MS_PER_CHAN)) {
    logSD("WiFi roam: scan did not start");
    return;
  }
  s_state = RS_SCANNING;
  s_phase_start = now;
}
