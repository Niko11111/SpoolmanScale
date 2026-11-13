#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// ============================================================
//  THE NETWORKS THE SCALE KNOWS, AND WHICH ONE IT TRIES
//
//  Every network the scale was on is remembered with its password, the one
//  used last first, so going back to a network never asks for the password
//  again. Nobody manages the list: a full one drops the network unused the
//  longest.
//
//  The network the user chose last stays preferred. Out of range for
//  WIFI_FALLBACK_AFTER_MS, the scale takes the strongest other known network
//  in range; once the preferred one is back and nobody is using the scale it
//  returns (Nikolai, 13.11.2026). A router restart leaves it where it was.
//
//  Pure logic, tested in test/test_wifi_known_rules.py.
// ============================================================

constexpr int    WIFI_KNOWN_MAX        = 5;
constexpr size_t WIFI_KNOWN_SSID_BYTES = 33;   // 32 characters, as 802.11 allows
constexpr size_t WIFI_KNOWN_PASS_BYTES = 65;   // 64, a WPA2 key in hex

// How long the network in use may be gone before another is looked for:
// longer than a router takes to restart.
constexpr uint32_t WIFI_FALLBACK_AFTER_MS  = 2UL * 60UL * 1000UL;
// While none is found, the next look at most this often.
constexpr uint32_t WIFI_FALLBACK_RESCAN_MS = 30UL * 1000UL;
// After a switch back to the preferred network, how long it gets to come up
// before the scale goes back to the one that worked.
constexpr uint32_t WIFI_RETURN_GIVE_UP_MS  = 30UL * 1000UL;
// How often a scale on another network looks for the preferred one, and how
// far that stretches while the preferred one is seen but refuses the scale.
constexpr uint32_t WIFI_RETURN_FIRST_MS    = 5UL * 60UL * 1000UL;
constexpr uint32_t WIFI_RETURN_MAX_MS      = 60UL * 60UL * 1000UL;

struct WifiKnownEntry {
  char ssid[WIFI_KNOWN_SSID_BYTES];
  char pass[WIFI_KNOWN_PASS_BYTES];
};

struct WifiKnownList {
  WifiKnownEntry e[WIFI_KNOWN_MAX];
  int n;
};

// One network a scan saw; an SSID may come more than once, one per access point.
struct WifiSeen {
  const char* ssid;
  int rssi;
};

inline int wifiKnownFind(const WifiKnownList& l, const char* ssid) {
  for (int i = 0; i < l.n; i++) {
    if (strcmp(l.e[i].ssid, ssid) == 0) return i;
  }
  return -1;
}

// Puts the network first with this password and moves the ones before it down;
// a full list drops its last. True when anything changed, so the caller writes
// the store only then.
inline bool wifiKnownRemember(WifiKnownList& l, const char* ssid, const char* pass) {
  if (!ssid || !pass || !ssid[0]) return false;
  if (strlen(ssid) >= WIFI_KNOWN_SSID_BYTES || strlen(pass) >= WIFI_KNOWN_PASS_BYTES) return false;
  const int at = wifiKnownFind(l, ssid);
  if (at == 0 && strcmp(l.e[0].pass, pass) == 0) return false;
  const int last = at >= 0 ? at : (l.n < WIFI_KNOWN_MAX ? l.n : WIFI_KNOWN_MAX - 1);
  for (int i = last; i > 0; i--) l.e[i] = l.e[i - 1];
  memcpy(l.e[0].ssid, ssid, strlen(ssid) + 1);
  memcpy(l.e[0].pass, pass, strlen(pass) + 1);
  if (at < 0 && l.n < WIFI_KNOWN_MAX) l.n++;
  return true;
}

// True when the network was in the list.
inline bool wifiKnownForget(WifiKnownList& l, const char* ssid) {
  const int at = wifiKnownFind(l, ssid);
  if (at < 0) return false;
  for (int i = at; i < l.n - 1; i++) l.e[i] = l.e[i + 1];
  l.n--;
  return true;
}

// The strongest reading of an SSID in the scan, or INT32_MIN when it is not in it.
inline int wifiSeenRssi(const WifiSeen* seen, int nseen, const char* ssid) {
  int best = INT32_MIN;
  for (int i = 0; i < nseen; i++) {
    if (strcmp(seen[i].ssid, ssid) == 0 && seen[i].rssi > best) best = seen[i].rssi;
  }
  return best;
}

// The known network to try instead of `failing`: the preferred one when the
// scan sees it, else the strongest other one in range. -1 when there is none.
inline int wifiKnownPick(const WifiKnownList& l, const WifiSeen* seen, int nseen,
                         const char* preferred, const char* failing) {
  int best = -1;
  int best_rssi = INT32_MIN;
  for (int i = 0; i < l.n; i++) {
    if (failing && strcmp(l.e[i].ssid, failing) == 0) continue;
    const int rssi = wifiSeenRssi(seen, nseen, l.e[i].ssid);
    if (rssi == INT32_MIN) continue;
    if (preferred && strcmp(l.e[i].ssid, preferred) == 0) return i;
    if (rssi > best_rssi) {
      best_rssi = rssi;
      best = i;
    }
  }
  return best;
}

// Whether an outage on the network in use calls for a look at the others.
inline bool wifiFallbackScanDue(uint32_t outage_ms, uint32_t give_up_ms,
                                bool scanned, uint32_t since_scan_ms) {
  if (outage_ms < give_up_ms) return false;
  return !scanned || since_scan_ms >= WIFI_FALLBACK_RESCAN_MS;
}

// The wait before the next look for the preferred network: doubled after a
// switch back that did not come up, back to the start after one that did.
inline uint32_t wifiReturnNextGap(uint32_t gap, bool failed) {
  if (!failed) return WIFI_RETURN_FIRST_MS;
  return gap >= WIFI_RETURN_MAX_MS / 2 ? WIFI_RETURN_MAX_MS : gap * 2;
}
