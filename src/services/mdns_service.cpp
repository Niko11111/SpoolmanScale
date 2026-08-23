#include "services/mdns_service.h"

#include <Arduino.h>
#include <ESPmDNS.h>
#include <WiFi.h>
#include <ctype.h>
#include <mdns.h>
#include <string.h>

#include "app/app_state.h"
#include "app_config.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/prefs_store.h"
#include "services/wifi_manager.h"
#include "web/web_server.h"

// Default is the product name, spelled the way the docs spell it. Two scales
// out of the box therefore claim the same name; that is the price of a name
// worth typing, and the fix is to rename one of them in the browser. The
// name is logged on every start so the case is visible when it happens.
#define MDNS_HOSTNAME_DEFAULT "spoolmanscale"

static char s_hostname[MDNS_HOSTNAME_MAX + 1] = MDNS_HOSTNAME_DEFAULT;
static bool s_running       = false;
static bool s_service_added = false;
// What the TXT record currently claims, so the backend name is only rewritten
// when it actually changed rather than once a second.
static int  s_txt_backend   = -1;

const char* mdnsHostname() { return s_hostname; }
bool        mdnsRunning()  { return s_running; }

// RFC 1123 host label: letters, digits and hyphens, not starting or ending
// with one. Case is folded because mDNS compares case-insensitively and the
// responder lowercases the name anyway - accepting "Waage" and then
// answering to "waage" would just look like the setting had not been saved.
static bool normalise(const char* in, char* out, size_t out_size) {
  if (!in) return false;
  size_t n = 0;
  for (const char* p = in; *p; p++) {
    // Whitespace is refused rather than stripped. Silently turning "my scale"
    // into "myscale" and reporting success would leave the user looking at a
    // name they did not choose. Callers trim the ends first.
    if (n + 1 >= out_size) return false;        // too long
    char c = (char)tolower((unsigned char)*p);
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
    if (!ok) return false;
    out[n++] = c;
  }
  out[n] = '\0';
  if (n == 0) return false;
  if (out[0] == '-' || out[n - 1] == '-') return false;
  return true;
}

static void stopResponder() {
  if (!s_running) return;
  MDNS.end();
  s_running       = false;
  s_service_added = false;
  s_txt_backend   = -1;
}

void mdnsLoadHostname() {
  String stored = prefsGetString("mdns_host", MDNS_HOSTNAME_DEFAULT);
  char buf[MDNS_HOSTNAME_MAX + 1];
  // A stored name that no longer validates falls back rather than leaving the
  // device unreachable by name - the only way to get one in is through the
  // validator, so this covers a shortened limit rather than bad input.
  if (!normalise(stored.c_str(), buf, sizeof(buf))) {
    strncpy(s_hostname, MDNS_HOSTNAME_DEFAULT, sizeof(s_hostname) - 1);
    s_hostname[sizeof(s_hostname) - 1] = '\0';
    return;
  }
  strncpy(s_hostname, buf, sizeof(s_hostname) - 1);
  s_hostname[sizeof(s_hostname) - 1] = '\0';
}

bool mdnsSetHostname(const char* name) {
  char buf[MDNS_HOSTNAME_MAX + 1];
  if (!normalise(name, buf, sizeof(buf))) return false;
  if (strcmp(buf, s_hostname) == 0) return true;

  strncpy(s_hostname, buf, sizeof(s_hostname) - 1);
  s_hostname[sizeof(s_hostname) - 1] = '\0';
  prefsPutString("mdns_host", s_hostname);
  logSDf("mDNS: hostname set to %s.local", s_hostname);

  // Dropped rather than renamed in place: mdns_hostname_set() leaves the
  // advertised service pointing at the old name. The next sync brings both
  // back up together, within a second and without a reboot.
  stopResponder();
  mdnsSyncState();
  return true;
}

// The service is advertised only while there is something behind it. Without
// this a Bonjour browser would list a scale whose page refuses to load
// whenever the web server is down.
static void addService() {
  if (!MDNS.addService("http", "tcp", 80)) return;
  s_service_added = true;
  MDNS.addServiceTxt("http", "tcp", "fw",    FW_VERSION);
  MDNS.addServiceTxt("http", "tcp", "id",    wifiManagerDeviceId());
  MDNS.addServiceTxt("http", "tcp", "model", "WT32-SC01-Plus");
  MDNS.addServiceTxt("http", "tcp", "backend", backendName());
  s_txt_backend = (int)backendMode();
}

// ESPmDNS has no removeService, so this reaches past it into the IDF
// component it wraps. Same for the TXT update below.
static void removeService() {
  mdns_service_remove("_http", "_tcp");
  s_service_added = false;
  s_txt_backend   = -1;
}

void mdnsSyncState() {
  const bool link_up = wifi_ok && (WiFi.status() == WL_CONNECTED);

  if (!link_up) {
    stopResponder();
    return;
  }

  if (!s_running) {
    if (!MDNS.begin(s_hostname)) {
      // Not fatal and not retried on a timer of its own: the next pass tries
      // again a second later, and the IP address on screen still works.
      logSDf("mDNS: failed to start as %s.local", s_hostname);
      return;
    }
    // The instance name is what a browser shows in a device list, so it is
    // the product name rather than the host label.
    MDNS.setInstanceName("SpoolmanScale");
    s_running = true;
    logSDf("mDNS: responding as %s.local", s_hostname);
    Serial.printf("mDNS: http://%s.local/\n", s_hostname);
  }

  const bool serving = webServerIsListening();
  if (serving && !s_service_added)      addService();
  else if (!serving && s_service_added) removeService();

  // A backend switch changes what the record claims. Compared rather than
  // rewritten every pass, because setting a TXT item republishes it.
  if (s_service_added && s_txt_backend != (int)backendMode()) {
    s_txt_backend = (int)backendMode();
    mdns_service_txt_item_set("_http", "_tcp", "backend", backendName());
  }
}
