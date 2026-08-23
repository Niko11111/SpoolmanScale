#include "web/web_server.h"

#include <Arduino.h>
#include <WebServer.h>

#include "app/app_state.h"
#include "services/backend.h"
#include "services/filaman_api.h"
#include "services/remote_link.h"
#include "services/tag_write.h"
#include "services/wifi_manager.h"
#include "web/web_access.h"
#include "web/web_assets.h"
#include "web/web_pages.h"
#include "web/web_shell.h"

// ArduinoJson has to come after lang.h anywhere the T() macro is in scope.
// Nothing here includes lang.h, so the plain include is safe.
#include <ArduinoJson.h>

static WebServer ota_server(80);
static bool ota_server_running  = false;
static bool routes_registered   = false;

// True while the scale has to stay reachable for FilaMan's device protocol.
// In Spoolman and BamBuddy mode this is never true and nothing changes.
static bool remoteLinkNeedsServer() {
  return wifi_ok && backendIsFilaMan() && filamanDeviceToken()[0];
}

// The one condition that decides whether port 80 is open. The master switch
// owns it; the remote link can force it up on its own, because a user who
// switches the web interface off did not ask for FilaMan to stop being able
// to drive the scale. Everything except GATE_ALWAYS still answers 403 in
// that state, so nothing becomes reachable that the switch was meant to
// close.
static bool serverShouldRun() {
  return wifi_ok && (webMasterEnabled() || remoteLinkNeedsServer());
}

static void registerRoutes();

static void serverEnsureRunning() {
  if (ota_server_running) return;
  registerRoutes();
  ota_server.begin();
  ota_server_running = true;
  Serial.printf("Web server listening: http://%s/\n",
                wifiManagerLocalIP().toString().c_str());
}

static void serverEnsureStopped() {
  if (!ota_server_running) return;
  ota_server.stop();
  ota_server_running = false;
  Serial.println("Web server stopped");
}

// Idempotent, called once a second from appLoop() and once more whenever a
// screen wants the state to settle now. The only owner of the socket: there
// used to be a second automaton in web_access.cpp with its own copy of this
// state, and the copies drifted until port 80 stayed shut until reboot.
void webServerSyncState() {
  if (serverShouldRun()) serverEnsureRunning();
  else                   serverEnsureStopped();
}

bool webServerIsListening() { return ota_server_running; }

// Registered exactly once. This used to run on every visit to the web screen,
// which appended another handler set to WebServer's list each time and never
// freed the previous ones - WebServer::stop() does not release them.
static void registerRoutes() {
  if (routes_registered) return;
  routes_registered = true;

  registerAssetRoutes(ota_server);

  // Every page and every endpoint it owns, straight from the one table. The
  // page route itself is wrapped here so the gate check and the chrome happen
  // in one place and cannot be forgotten in a new page.
  for (size_t i = 0; i < WEB_PAGE_COUNT; i++) {
    const WebPage &p = *WEB_PAGES[i];
    ota_server.on(p.path, HTTP_GET, [&p]() {
      // A page that does not apply to this device is absent, not refused:
      // there is no backend page at all on Spoolman.
      if (p.applies && !p.applies()) {
        ota_server.send(404, "text/plain", "Not found");
        return;
      }
      if (!webRequire(ota_server, p.gate, webPageLabel(p))) return;
      String html = webShellHead(webPageLabel(p));
      html += webShellPageCss();
      html += webShellNav(p.path);
      html += webShellLinks();
      html += p.body();
      html += webShellFoot();
      ota_server.send(200, "text/html", html);
    });
    if (p.routes) p.routes(ota_server);
  }


  // FilaMan remote link trigger. GATE_ALWAYS, the only level that ignores
  // the master switch: this one has to answer whenever the scale is awake,
  // that is the whole point of keeping the socket up.
  //
  // FilaMan sends this fire and forget and waits five seconds, so nothing
  // here may block. The request is only parked, appLoop() picks it up.
  // Nothing is ever written to the tag, the trigger is read as "the spool on
  // the scale belongs to this id".
  // FilaMan's "import from tag". Parked like the write trigger, because the
  // read cannot happen inside the handler.
  ota_server.on("/api/v1/rfid/scan-request", HTTP_POST, []() {
    tagScanRequest();
    ota_server.send(200, "application/json", "{\"status\":\"ok\"}");
  });


  ota_server.on("/api/v1/rfid/write", HTTP_POST, []() {
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, ota_server.arg("plain"));
    if (err) {
      ota_server.send(400, "application/json", "{\"status\":\"error\"}");
      return;
    }

    const int spool_id    = doc["spool_id"]    | 0;
    const int location_id = doc["location_id"] | 0;

    // FilaMan's backend expands the trigger into a full OpenSpool record
    // before forwarding it. Keep it verbatim: the server decided what belongs
    // on the tag. An older server sends only the id and nothing is written.
    const char *proto = doc["protocol"] | "";
    tagRemotePayloadSet(strcmp(proto, "openspool") == 0
                        ? ota_server.arg("plain").c_str() : "");

    if (spool_id > 0) {
      remoteLinkSetPending(spool_id);
      ota_server.send(200, "application/json", "{\"status\":\"ok\"}");
      return;
    }
    if (location_id > 0) {
      // Locations are a FilaMan concept the scale does not handle yet.
      // Turning the request down beats ignoring it: the web UI would
      // otherwise poll for a full minute before its own timeout.
      remote_link_reject_pending = true;
      ota_server.send(200, "application/json", "{\"status\":\"ok\"}");
      return;
    }
    ota_server.send(400, "application/json", "{\"status\":\"error\"}");
  });
}

void handleOtaServerClient() {
  if (ota_server_running) ota_server.handleClient();
}
