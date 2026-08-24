#include "services/mdns_service.h"

#include <Arduino.h>
#include <ESPmDNS.h>
#include <WiFi.h>
#include <mdns.h>
#include <string.h>

#include "app/app_state.h"
#include "app_config.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/device_name.h"
#include "services/wifi_manager.h"
#include "web/web_server.h"

static bool s_running       = false;
static bool s_service_added = false;
// What the TXT record currently claims, so the backend name is only rewritten
// when it actually changed rather than once a second.
static int  s_txt_backend   = -1;
// The name the responder actually came up under. Compared against the stored
// label every pass, so a rename needs no notification of its own - this is
// the same "derive it, remember nothing" line webServerSyncState() follows.
static char s_advertised[DEVICE_LABEL_MAX + 1] = "";

bool mdnsRunning() { return s_running; }

static void stopResponder() {
  if (!s_running) return;
  MDNS.end();
  s_running       = false;
  s_service_added = false;
  s_txt_backend   = -1;
  s_advertised[0] = '\0';
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

  if (!link_up || !deviceMdnsEnabled()) {
    stopResponder();
    return;
  }

  // Dropped rather than renamed in place: mdns_hostname_set() leaves the
  // advertised service pointing at the old name. Both come back up together
  // further down this same pass.
  if (s_running && strcmp(s_advertised, deviceLabel()) != 0) stopResponder();

  if (!s_running) {
    char name[DEVICE_FQDN_MAX + 1];
    deviceMdnsName(name, sizeof(name));
    if (!MDNS.begin(deviceLabel())) {
      // Not fatal and not retried on a timer of its own: the next pass tries
      // again a second later, and the IP address on screen still works.
      logSDf("mDNS: failed to start as %s", name);
      return;
    }
    // The instance name is what a browser shows in a device list, so it is
    // the product name rather than the host label.
    MDNS.setInstanceName("SpoolmanScale");
    s_running = true;
    strncpy(s_advertised, deviceLabel(), sizeof(s_advertised) - 1);
    s_advertised[sizeof(s_advertised) - 1] = '\0';
    logSDf("mDNS: responding as %s", name);
    Serial.printf("mDNS: http://%s/\n", name);
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
