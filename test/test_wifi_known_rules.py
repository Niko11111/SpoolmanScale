"""Compile the production rules for the remembered WiFi networks and check
the order of the list, what a full one drops, which network a scale falls
back to, how its look for the preferred one stretches, and how a network
chosen in the browser is tried (services/wifi_known_rules.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/wifi_known_rules.h"
#include <cassert>
#include <cstring>

static bool is(const WifiKnownList& l, int i, const char* ssid, const char* pass) {
  return strcmp(l.e[i].ssid, ssid) == 0 && strcmp(l.e[i].pass, pass) == 0;
}

int main() {
  WifiKnownList l = {};

  // The one used last comes first.
  assert(wifiKnownRemember(l, "Home", "h1"));
  assert(wifiKnownRemember(l, "Shop", "s1"));
  assert(l.n == 2 && is(l, 0, "Shop", "s1") && is(l, 1, "Home", "h1"));

  // Connected again to the first: nothing to write.
  assert(!wifiKnownRemember(l, "Shop", "s1"));

  // Back home: moved up, not added twice.
  assert(wifiKnownRemember(l, "Home", "h1"));
  assert(l.n == 2 && is(l, 0, "Home", "h1") && is(l, 1, "Shop", "s1"));

  // A changed password replaces the old one.
  assert(wifiKnownRemember(l, "Shop", "s2"));
  assert(l.n == 2 && is(l, 0, "Shop", "s2"));

  // A full list drops the one unused the longest.
  assert(wifiKnownRemember(l, "A", "a"));
  assert(wifiKnownRemember(l, "B", "b"));
  assert(wifiKnownRemember(l, "C", "c"));
  assert(l.n == WIFI_KNOWN_MAX);
  assert(wifiKnownRemember(l, "D", "d"));
  assert(l.n == WIFI_KNOWN_MAX && is(l, 0, "D", "d") && wifiKnownFind(l, "Home") < 0);

  // Nothing that would not fit, and no empty name.
  char longest[WIFI_KNOWN_SSID_BYTES + 1];
  memset(longest, 'x', sizeof(longest) - 1);
  longest[sizeof(longest) - 1] = '\0';
  assert(!wifiKnownRemember(l, longest, "p"));
  assert(!wifiKnownRemember(l, "", "p"));

  // Forgetting closes the gap.
  assert(wifiKnownForget(l, "B"));
  assert(!wifiKnownForget(l, "B"));
  // D, C, A, Shop: the order of the rest stays.
  assert(l.n == WIFI_KNOWN_MAX - 1 && wifiKnownFind(l, "A") == 2 && wifiKnownFind(l, "Shop") == 3);

  // Falling back: the preferred network wins whenever it is in range,
  // otherwise the strongest other known one, never the one that fails.
  WifiKnownList k = {};
  wifiKnownRemember(k, "Guest", "g");
  wifiKnownRemember(k, "Shop", "s");
  wifiKnownRemember(k, "Home", "h");
  const WifiSeen seen[] = { {"Guest", -50}, {"Shop", -80}, {"Shop", -60}, {"Stranger", -30} };
  assert(wifiKnownPick(k, seen, 4, "Shop", "Home") == wifiKnownFind(k, "Shop"));
  assert(wifiKnownPick(k, seen, 4, "Home", "Home") == wifiKnownFind(k, "Guest"));
  // The strongest access point of an SSID counts: Shop at -60 beats Guest at -65.
  const WifiSeen seen2[] = { {"Guest", -65}, {"Shop", -80}, {"Shop", -60} };
  assert(wifiKnownPick(k, seen2, 3, "Home", "Home") == wifiKnownFind(k, "Shop"));
  // Nothing known in range.
  const WifiSeen none[] = { {"Stranger", -30} };
  assert(wifiKnownPick(k, none, 1, "Home", "Home") == -1);
  // The failing network is never picked, even when it is the preferred one.
  const WifiSeen home_only[] = { {"Home", -40} };
  assert(wifiKnownPick(k, home_only, 1, "Home", "Home") == -1);

  // The look for another network waits out a router restart, then repeats.
  assert(!wifiFallbackScanDue(WIFI_FALLBACK_AFTER_MS - 1, WIFI_FALLBACK_AFTER_MS, false, 0));
  assert(wifiFallbackScanDue(WIFI_FALLBACK_AFTER_MS, WIFI_FALLBACK_AFTER_MS, false, 0));
  assert(!wifiFallbackScanDue(WIFI_FALLBACK_AFTER_MS, WIFI_FALLBACK_AFTER_MS, true, WIFI_FALLBACK_RESCAN_MS - 1));
  assert(wifiFallbackScanDue(WIFI_FALLBACK_AFTER_MS, WIFI_FALLBACK_AFTER_MS, true, WIFI_FALLBACK_RESCAN_MS));

  // A return that failed stretches the next look up to an hour; one that
  // worked starts over.
  uint32_t gap = WIFI_RETURN_FIRST_MS;
  gap = wifiReturnNextGap(gap, true);
  assert(gap == 2 * WIFI_RETURN_FIRST_MS);
  for (int i = 0; i < 10; i++) gap = wifiReturnNextGap(gap, true);
  assert(gap == WIFI_RETURN_MAX_MS);
  assert(wifiReturnNextGap(gap, false) == WIFI_RETURN_FIRST_MS);

  // A network chosen in the browser counts only once the station is on it:
  // the old link coming back hands out an address too.
  assert(wifiTryVerdict(true, "New", "New", 1000) == WIFI_TRY_UP);
  assert(wifiTryVerdict(true, "Old", "New", 1000) == WIFI_TRY_WAIT);
  assert(wifiTryVerdict(false, "New", "New", 1000) == WIFI_TRY_WAIT);
  assert(wifiTryVerdict(true, "Old", "New", WIFI_TRY_GIVE_UP_MS) == WIFI_TRY_FAILED);
  assert(wifiTryVerdict(true, "New", "New", WIFI_TRY_GIVE_UP_MS) == WIFI_TRY_UP);

  // Typed wins; an empty field takes the stored password, the preferred
  // network's as well when the list does not hold it; else an open network.
  const WifiPreferred pref = {"Pref", "pp"};
  assert(strcmp(wifiTryPass(k, "Shop", "typed", pref), "typed") == 0);
  assert(strcmp(wifiTryPass(k, "Shop", "", pref), "s") == 0);
  assert(strcmp(wifiTryPass(k, "Shop", nullptr, pref), "s") == 0);
  assert(strcmp(wifiTryPass(k, "Pref", "", pref), "pp") == 0);
  assert(strcmp(wifiTryPass(k, "Cafe", "", pref), "") == 0);
  assert(strcmp(wifiTryPass(k, "Cafe", "", WifiPreferred{nullptr, nullptr}), "") == 0);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", "-Wall", f"-I{root / 'src'}", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("wifi known rules: ok")
