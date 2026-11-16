#include "services/wifi_known.h"

#include <Arduino.h>
#include <stdio.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/psram_new.h"
#include "hardware/sd_logger.h"
#include "services/prefs_store.h"
#include "services/wifi_manager.h"

// NVS: the count, then one SSID and one password key per entry, "wk_s0".
#define WK_KEY_COUNT  "wk_n"
#define WK_KEY_BYTES  8
// While cfg_wifi_* is not what the list holds first, the network the station
// is really on is asked at most this often: during a switch the core still
// reports the old link as up.
#define WK_VERIFY_EVERY_MS 1000UL

// In PSRAM from wifiKnownBoot() on, before the web server can ask for it.
// Read on every loop pass while connected, 0.5 kB that internal RAM need not
// hold; nullptr only when neither heap had room, and then no network is known.
static WifiKnownList* s_list = nullptr;
static const WifiKnownList kNoneKnown = {};
static char s_pref_ssid[WIFI_KNOWN_SSID_BYTES] = "";
static char s_pref_pass[WIFI_KNOWN_PASS_BYTES] = "";
static uint32_t s_pref_gen = 0;
// Forgotten while the scale is on it: not remembered again on the next pass,
// only once the user chooses it again.
static char s_forgotten[WIFI_KNOWN_SSID_BYTES] = "";

static void keyOf(char* out, char kind, int i) {
  snprintf(out, WK_KEY_BYTES, "wk_%c%d", kind, i);
}

static void copyStr(char* out, size_t n, const char* in) {
  snprintf(out, n, "%s", in ? in : "");
}

static void loadList() {
  s_list->n = 0;
  const int n = prefsGetInt(WK_KEY_COUNT, 0);
  for (int i = 0; i < n && i < WIFI_KNOWN_MAX; i++) {
    char ks[WK_KEY_BYTES], kp[WK_KEY_BYTES];
    keyOf(ks, 's', i);
    keyOf(kp, 'p', i);
    const String ssid = prefsGetString(ks, "");
    if (ssid.length() == 0 || ssid.length() >= WIFI_KNOWN_SSID_BYTES) continue;
    WifiKnownEntry& e = s_list->e[s_list->n++];
    copyStr(e.ssid, sizeof(e.ssid), ssid.c_str());
    copyStr(e.pass, sizeof(e.pass), prefsGetString(kp, "").c_str());
  }
}

static void saveList() {
  for (int i = 0; i < WIFI_KNOWN_MAX; i++) {
    char ks[WK_KEY_BYTES], kp[WK_KEY_BYTES];
    keyOf(ks, 's', i);
    keyOf(kp, 'p', i);
    if (i < s_list->n) {
      prefsPutString(ks, s_list->e[i].ssid);
      prefsPutString(kp, s_list->e[i].pass);
    } else if (prefsHasKey(ks)) {
      prefsRemoveKey(ks);
      prefsRemoveKey(kp);
    }
  }
  prefsPutInt(WK_KEY_COUNT, s_list->n);
}

void wifiKnownBoot() {
  copyStr(s_pref_ssid, sizeof(s_pref_ssid), cfg_wifi_ssid);
  copyStr(s_pref_pass, sizeof(s_pref_pass), cfg_wifi_password);
  s_list = psramNew<WifiKnownList>();
  if (!s_list) {
    logSD("WiFi: no memory for the known networks, only the stored one is used");
    return;
  }
  loadList();
  logSDf("WiFi: %d known network(s), preferred %s", s_list->n, s_pref_ssid[0] ? s_pref_ssid : "-");
}

void wifiKnownSetPreferred(const char* ssid, const char* pass) {
  copyStr(s_pref_ssid, sizeof(s_pref_ssid), ssid);
  copyStr(s_pref_pass, sizeof(s_pref_pass), pass);
  s_pref_gen++;
  s_forgotten[0] = '\0';
}

const char* wifiPreferredSsid() { return s_pref_ssid; }
const char* wifiPreferredPass() { return s_pref_pass; }
uint32_t wifiPreferredGeneration() { return s_pref_gen; }

void wifiKnownNoteConnected() {
  if (!s_list || !cfg_wifi_ssid[0] || strcmp(s_forgotten, cfg_wifi_ssid) == 0) return;
  if (s_list->n > 0 && strcmp(s_list->e[0].ssid, cfg_wifi_ssid) == 0 &&
      strcmp(s_list->e[0].pass, cfg_wifi_password) == 0) {
    return;
  }
  // Only once the station is on that network: a begin() to a new one with a
  // wrong password leaves the old link up, and the wrong password must not
  // become the remembered one.
  static unsigned long last_verify_ms = 0;
  if (last_verify_ms != 0 && millis() - last_verify_ms < WK_VERIFY_EVERY_MS) return;
  last_verify_ms = millis();
  char on[WIFI_KNOWN_SSID_BYTES];
  wifiManagerCurrentSsid(on, sizeof(on));
  if (strcmp(on, cfg_wifi_ssid) != 0) return;
  if (!wifiKnownRemember(*s_list, cfg_wifi_ssid, cfg_wifi_password)) return;
  saveList();
  logSDf("WiFi: %s remembered, %d known network(s)", cfg_wifi_ssid, s_list->n);
}

const WifiKnownList& wifiKnownList() { return s_list ? *s_list : kNoneKnown; }

bool wifiKnownForgetSsid(const char* ssid) {
  if (!s_list || !ssid || !wifiKnownForget(*s_list, ssid)) return false;
  copyStr(s_forgotten, sizeof(s_forgotten), ssid);
  saveList();
  logSDf("WiFi: %s forgotten, %d known network(s)", ssid, s_list->n);
  return true;
}
