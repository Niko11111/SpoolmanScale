#include "services/wifi_remote.h"

#include <Arduino.h>
#include <stdio.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/app_settings.h"
#include "services/wifi_known.h"

// A try waits this long after the request, so the answer and the page's
// first look at the state leave over the old link before it goes.
#define WR_TRY_DELAY_MS     1500UL
#define WR_SCAN_TIMEOUT_MS 15000UL
// While a try runs, the network the station is on is asked at most this often.
#define WR_CHECK_EVERY_MS   500UL

static WifiRemoteScan s_scan       = WRS_NONE;
static uint32_t       s_scan_start = 0;
static WifiScanEntry  s_nets[WIFI_REMOTE_SCAN_MAX];
static int            s_net_n      = 0;

static WifiRemoteTry s_try        = WRT_NONE;
static uint32_t      s_try_asked  = 0;
static uint32_t      s_try_start  = 0;
static uint32_t      s_try_ip     = 0;   // addresses handed out before the try
static char          s_ssid[WIFI_KNOWN_SSID_BYTES] = "";
static char          s_pass[WIFI_KNOWN_PASS_BYTES] = "";
static char          s_from[WIFI_KNOWN_SSID_BYTES] = "";

bool wifiRemoteScanRequest() {
  if (s_scan == WRS_WAITING || s_scan == WRS_RUNNING) return false;
  s_scan = WRS_WAITING;
  return true;
}

WifiRemoteScan wifiRemoteScanState() { return s_scan; }

const WifiScanEntry* wifiRemoteScanResults(int* n) {
  *n = s_scan == WRS_DONE ? s_net_n : 0;
  return s_nets;
}

bool wifiRemoteTryRequest(const char* ssid, const char* typed_pass) {
  if (s_try == WRT_WAITING || s_try == WRT_TRYING) return false;
  if (!ssid || !ssid[0] || strlen(ssid) >= sizeof(s_ssid)) return false;
  const WifiPreferred pref = { wifiPreferredSsid(), wifiPreferredPass() };
  const char* pass = wifiTryPass(wifiKnownList(), ssid, typed_pass, pref);
  if (strlen(pass) >= sizeof(s_pass)) return false;
  snprintf(s_ssid, sizeof(s_ssid), "%s", ssid);
  snprintf(s_pass, sizeof(s_pass), "%s", pass);
  snprintf(s_from, sizeof(s_from), "%s", cfg_wifi_ssid);
  s_try = WRT_WAITING;
  s_try_asked = millis();
  return true;
}

WifiRemoteTry wifiRemoteTryState() { return s_try; }
const char* wifiRemoteTrySsid() { return s_ssid; }
const char* wifiRemoteTryFrom() { return s_from; }

bool wifiRemoteBusy() { return s_try == WRT_TRYING || s_scan == WRS_RUNNING; }

static void startScan(uint32_t now) {
  // Beside the link, the way the setup screen scans: the radio is reset only
  // for a station that is down, see doWifiScan().
  if (!wifiManagerIsConnected()) wifiManagerPrepareScan();
  if (!wifiManagerStartScanAsync()) {
    logSD("WiFi: browser scan could not start");
    s_scan = WRS_FAILED;
    return;
  }
  s_scan = WRS_RUNNING;
  s_scan_start = now;
}

static void pollScan(uint32_t now) {
  const int n = wifiManagerScanPoll();
  if (n == -1 && now - s_scan_start < WR_SCAN_TIMEOUT_MS) return;
  if (n > 0) {
    s_net_n = wifiManagerReadSorted(n, s_nets, WIFI_REMOTE_SCAN_MAX);
    s_scan = WRS_DONE;
    return;
  }
  wifiManagerClearScan();
  s_net_n = 0;
  // None in range is an answer as well; a scan that failed or hung is not.
  s_scan = n == 0 ? WRS_DONE : WRS_FAILED;
  if (n != 0) logSD("WiFi: browser scan failed or did not finish");
}

static void startTry(uint32_t now) {
  logSDf("WiFi: browser asked for %s, trying it, %s stays until it is up",
         s_ssid, s_from[0] ? s_from : "-");
  // After a failed begin() the radio needs its reset, as in Improv.
  if (!wifiManagerIsConnected()) wifiManagerPrepareScan();
  s_try_ip = wifiManagerGotIpCount();
  wifiManagerBegin(s_ssid, s_pass);
  s_try = WRT_TRYING;
  s_try_start = now;
}

static void pollTry(uint32_t now) {
  static uint32_t last_check = 0;
  if (now - last_check < WR_CHECK_EVERY_MS) return;
  last_check = now;
  char on[WIFI_KNOWN_SSID_BYTES];
  wifiManagerCurrentSsid(on, sizeof(on));
  const WifiTryVerdict v =
      wifiTryVerdict(wifiManagerLinkUpSince(s_try_ip), on, s_ssid, now - s_try_start);
  if (v == WIFI_TRY_WAIT) return;
  if (v == WIFI_TRY_UP) {
    // Now the choice is stored, and becomes the preferred network.
    saveWifiCredentials(s_ssid, s_pass);
    logSDf("WiFi: on %s as the browser asked, IP %s", s_ssid,
           wifiManagerLocalIP().toString().c_str());
    s_try = WRT_UP;
  } else {
    logSDf("WiFi: %s did not come up in %lu s, back to %s", s_ssid,
           (unsigned long)(WIFI_TRY_GIVE_UP_MS / 1000UL), cfg_wifi_ssid);
    // Still on the old link when begin() gave up. Otherwise the attempt is
    // stopped and the reconnect watchdog takes the old network back up, as
    // after Improv. A begin() of the old one straight into the driver's
    // search for the new one left the station down for good (14.11.2026:
    // reason 36, no link in three minutes).
    if (strcmp(on, cfg_wifi_ssid) != 0) wifiManagerStopConnect();
    s_try = WRT_FAILED;
  }
  memset(s_pass, 0, sizeof(s_pass));
}

void wifiRemoteTick(bool radio_free) {
  const uint32_t now = millis();
  if (s_scan == WRS_RUNNING) pollScan(now);
  if (s_try == WRT_TRYING) pollTry(now);
  if (!radio_free || wifiRemoteBusy()) return;
  // A try first: a scan the page asked for before it is moot once it begins.
  if (s_try == WRT_WAITING && now - s_try_asked >= WR_TRY_DELAY_MS) {
    if (s_scan == WRS_WAITING) s_scan = WRS_NONE;
    startTry(now);
    return;
  }
  if (s_scan == WRS_WAITING && s_try != WRT_WAITING) startScan(now);
}
