#include "app/wifi_fallback.h"

#include <Arduino.h>
#include <stdio.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/psram_new.h"
#include "hardware/sd_logger.h"
#include "services/wifi_known.h"
#include "services/wifi_manager.h"
#include "services/wifi_roam.h"

// Scan entries read for the choice. A place with more networks than this in
// range is a trade fair; the first ones are the strongest anyway.
#define FB_SEEN_MAX            32
#define FB_SCAN_TIMEOUT_MS     15000UL
// Per channel when looking for the preferred network beside a link: under
// two seconds for all thirteen, as for the roaming check.
#define FB_RETURN_MS_PER_CHAN  120
// While a switch back is under way, the network the station is really on is
// asked at most this often.
#define FB_SETTLE_EVERY_MS     1000UL

enum FbState : uint8_t { FB_IDLE, FB_SCAN_OUTAGE, FB_SCAN_RETURN };

static FbState  s_state          = FB_IDLE;
static uint32_t s_phase_start    = 0;
static bool     s_in_outage      = false;
static uint32_t s_outage_since   = 0;
static bool     s_scanned        = false;   // in this outage
static uint32_t s_last_scan      = 0;
static bool     s_said_none      = false;   // in this outage
static bool     s_said_no_mem    = false;   // in this outage
static uint32_t s_last_switch    = 0;
static uint32_t s_return_gap     = WIFI_RETURN_FIRST_MS;
static bool     s_return_pending = false;   // switched back, not up there yet
static uint32_t s_pref_gen       = 0;

// What an outage scan found, read only to pick the next network. In PSRAM
// from the first outage on: 1.3 kB that internal RAM need not hold for a
// moment that may never come.
struct FbSeen {
  WifiSeen e[FB_SEEN_MAX];
  char     names[FB_SEEN_MAX][WIFI_KNOWN_SSID_BYTES];
};
static FbSeen* s_seen = nullptr;

bool wifiFallbackBusy() { return s_state != FB_IDLE; }

static bool onPreferred() { return strcmp(cfg_wifi_ssid, wifiPreferredSsid()) == 0; }

// A known network other than the one in use: only then can a scan lead anywhere.
static bool hasAlternative() {
  const WifiKnownList& l = wifiKnownList();
  for (int i = 0; i < l.n; i++) {
    if (strcmp(l.e[i].ssid, cfg_wifi_ssid) != 0) return true;
  }
  return false;
}

// The network in use changes in RAM only. The stored choice stays, so the
// next boot starts on the preferred network again.
static void switchTo(const char* ssid, const char* pass, uint32_t now) {
  snprintf(cfg_wifi_ssid, sizeof(cfg_wifi_ssid), "%s", ssid);
  snprintf(cfg_wifi_password, sizeof(cfg_wifi_password), "%s", pass);
  s_in_outage = false;   // the new network gets its own time
  s_last_switch = now;
  wifiManagerBegin(cfg_wifi_ssid, cfg_wifi_password);
}

static void returnFailed(const char* why) {
  s_return_pending = false;
  s_return_gap = wifiReturnNextGap(s_return_gap, true);
  logSDf("WiFi: %s %s, next look for it in %lu min", wifiPreferredSsid(), why,
         (unsigned long)(s_return_gap / 60000UL));
}

static int readSeen(int n) {
  if (!s_seen) return 0;   // outageTick() makes it before any scan
  int m = 0;
  for (int i = 0; i < n && m < FB_SEEN_MAX; i++) {
    const String ssid = wifiManagerScannedSSID(i);
    if (ssid.length() == 0 || ssid.length() >= WIFI_KNOWN_SSID_BYTES) continue;
    memcpy(s_seen->names[m], ssid.c_str(), ssid.length() + 1);
    s_seen->e[m].ssid = s_seen->names[m];
    s_seen->e[m].rssi = wifiManagerScannedRSSI(i);
    m++;
  }
  return m;
}

static void evaluateOutageScan(int n, uint32_t now) {
  const int m = n > 0 ? readSeen(n) : 0;
  wifiManagerClearScan();
  const WifiKnownList& l = wifiKnownList();
  const int pick = m > 0 ? wifiKnownPick(l, s_seen->e, m, wifiPreferredSsid(), cfg_wifi_ssid) : -1;
  const unsigned long gone_s = (now - s_outage_since) / 1000UL;
  if (pick < 0) {
    if (!s_said_none) {
      s_said_none = true;
      logSDf("WiFi: %s gone for %lu s, no other known network in range, still trying it",
             cfg_wifi_ssid, gone_s);
    }
    wifiManagerBegin(cfg_wifi_ssid, cfg_wifi_password);
    return;
  }
  if (s_return_pending) returnFailed("did not come up");
  const WifiKnownEntry next = l.e[pick];   // a copy: the list may change under it
  logSDf("WiFi: %s gone for %lu s, switching to the known network %s",
         cfg_wifi_ssid, gone_s, next.ssid);
  switchTo(next.ssid, next.pass, now);
}

static void evaluateReturnScan(int n, bool quiet, uint32_t now) {
  bool found = false;
  for (int i = 0; i < n && !found; i++) found = wifiManagerScannedSSID(i) == wifiPreferredSsid();
  wifiManagerClearScan();
  // Not in range: the next look waits longer. Coming home is not missed by
  // that - the network in use is then the one out of range, and its outage
  // finds the preferred one.
  if (!found) {
    s_return_gap = wifiReturnNextGap(s_return_gap, true);
    return;
  }
  // Somebody picked the scale up while the scan ran: the next look decides.
  if (!quiet) return;
  logSDf("WiFi: the preferred network %s is in range again, switching back from %s",
         wifiPreferredSsid(), cfg_wifi_ssid);
  s_return_pending = true;
  switchTo(wifiPreferredSsid(), wifiPreferredPass(), now);
}

static void pollScan(uint32_t now, bool quiet) {
  int n = wifiManagerScanPoll();
  if (n == -1) {
    if (now - s_phase_start < FB_SCAN_TIMEOUT_MS) return;
    logSD("WiFi: network scan did not finish, dropped");
    n = -2;
  }
  const FbState was = s_state;
  s_state = FB_IDLE;
  if (was == FB_SCAN_OUTAGE) {
    evaluateOutageScan(n, now);
  } else {
    evaluateReturnScan(n > 0 ? n : 0, quiet, now);
  }
}

static bool outageTick(uint32_t now) {
  if (!s_in_outage) {
    s_in_outage = true;
    s_outage_since = now;
    s_scanned = false;
    s_said_none = false;
    s_said_no_mem = false;
  }
  if (!hasAlternative()) return false;
  if (!s_seen) s_seen = psramNew<FbSeen>();
  if (!s_seen) {
    // No scan without a place for its result: the radio is not reset for
    // nothing every rescan, and the network in use keeps being tried.
    if (!s_said_no_mem) logSD("WiFi: no memory for a network scan, still trying the network in use");
    s_said_no_mem = true;
    return false;
  }
  const uint32_t give_up = s_return_pending ? WIFI_RETURN_GIVE_UP_MS : WIFI_FALLBACK_AFTER_MS;
  if (!wifiFallbackScanDue(now - s_outage_since, give_up, s_scanned, now - s_last_scan)) return false;
  s_scanned = true;
  s_last_scan = now;
  // The station is down: the radio is reset first, after a failed begin() a
  // scan finds nothing (ui/wifi_setup_screen.cpp).
  wifiManagerPrepareScan();
  if (!wifiManagerStartScanAsync()) {
    wifiManagerBegin(cfg_wifi_ssid, cfg_wifi_password);
    return true;
  }
  s_state = FB_SCAN_OUTAGE;
  s_phase_start = now;
  return true;
}

// Connected after a switch back: on the preferred network, or still on the
// old one because the core kept the old link (wifi_manager.h).
static void settleReturn(uint32_t now) {
  static uint32_t last_ms = 0;
  if (last_ms != 0 && now - last_ms < FB_SETTLE_EVERY_MS) return;
  last_ms = now;
  char on[WIFI_KNOWN_SSID_BYTES];
  wifiManagerCurrentSsid(on, sizeof(on));
  if (strcmp(on, cfg_wifi_ssid) == 0) {
    s_return_pending = false;
    s_return_gap = wifiReturnNextGap(s_return_gap, false);
    logSDf("WiFi: back on the preferred network %s", cfg_wifi_ssid);
    return;
  }
  if (now - s_last_switch < WIFI_RETURN_GIVE_UP_MS) return;
  const WifiKnownList& l = wifiKnownList();
  const int at = wifiKnownFind(l, on);
  if (at < 0) return;   // on a network the list does not know: leave it be
  returnFailed("could not take over the link");
  snprintf(cfg_wifi_ssid, sizeof(cfg_wifi_ssid), "%s", l.e[at].ssid);
  snprintf(cfg_wifi_password, sizeof(cfg_wifi_password), "%s", l.e[at].pass);
}

static void returnTick(uint32_t now, bool quiet) {
  if (onPreferred() || !wifiPreferredSsid()[0] || !quiet || wifiRoamBusy()) return;
  if (now - s_last_switch < s_return_gap) return;
  s_last_switch = now;   // the gap counts from this look as well
  if (!wifiManagerStartSsidScan(wifiPreferredSsid(), FB_RETURN_MS_PER_CHAN)) return;
  s_state = FB_SCAN_RETURN;
  s_phase_start = now;
}

bool wifiFallbackTick(bool connected, bool quiet) {
  const uint32_t now = millis();
  // A new choice by the user: what was under way belongs to the old one.
  if (s_pref_gen != wifiPreferredGeneration()) {
    s_pref_gen = wifiPreferredGeneration();
    s_in_outage = false;
    s_return_pending = false;
    s_return_gap = WIFI_RETURN_FIRST_MS;
  }
  if (s_state != FB_IDLE) {
    pollScan(now, quiet);
    return true;
  }
  if (!connected) return outageTick(now);
  s_in_outage = false;
  if (s_return_pending) settleReturn(now);
  wifiKnownNoteConnected();
  returnTick(now, quiet);
  return s_state != FB_IDLE;
}
