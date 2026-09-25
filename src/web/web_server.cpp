#include "web/web_server.h"

#include <Arduino.h>
#include <WebServer.h>
#include <WiFi.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/filaman_api.h"
#include "services/remote_link.h"
#include "services/setup_portal.h"
#include "services/tag_write.h"
#include "services/wifi_manager.h"
#include "web/web_access.h"
#include "web/web_assets.h"
#include "web/web_static.h"
#include "web/web_pages.h"
#include "web/web_portal.h"
#include "web/web_shell.h"

// ArduinoJson has to come after lang.h anywhere the T() macro is in scope.
// Nothing here includes lang.h, so the plain include is safe.
#include <ArduinoJson.h>
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

// How long an accepted socket may stay silent before it is dropped. The
// library waits HTTP_MAX_DATA_WAIT, five seconds, and serves one connection
// at a time - so a socket a browser opened and never used (Chrome opens
// spares on hover and on navigation) parked every other request for those
// five seconds, and with the accept backlog at four the browser saw
// "site not reachable" in between. A real request follows the handshake
// within milliseconds on a LAN; a second is patience enough.
#define WEB_IDLE_CLIENT_MS 1000

// The library's handleClient() with that one number changed. Everything it
// touches is protected and the method is virtual, so this is an override
// rather than a patched copy of the library.
class ScaleWebServer : public WebServer {
 public:
  using WebServer::WebServer;

  // Nagle off for the accepted sockets: every reply here is small and the
  // browser waits for the last packet of it.
  void tune() { _server.setNoDelay(true); }

  void handleClient() override {
    if (_currentStatus == HC_NONE) {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
      _currentClient = _server.accept();
#else
      _currentClient = _server.available();
#endif
      if (!_currentClient) {
        if (_nullDelay) delay(1);
        return;
      }
      _currentStatus = HC_WAIT_READ;
      _statusChange  = millis();
    }

    bool keepCurrentClient = false;
    bool callYield = false;

    if (_currentClient.connected() && _currentStatus == HC_WAIT_READ) {
      if (_currentClient.available()) {
        if (_parseRequest(_currentClient)) {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
          // Core 3 counts this timeout in milliseconds, and keeps the
          // response headers of every request in a list that the library's
          // own handleClient() empties. Left out, each request kept its
          // headers for good: about 170 bytes of internal heap per request.
          _currentClient.setTimeout(HTTP_MAX_SEND_WAIT);
          _contentLength = CONTENT_LENGTH_NOT_SET;
          _responseCode  = 0;
          _clearResponseHeaders();
#else
          _currentClient.setTimeout(HTTP_MAX_SEND_WAIT / 1000);
          _contentLength = CONTENT_LENGTH_NOT_SET;
#endif
          const String req_uri = uri();
          const uint32_t t0 = millis();
          _handleRequest();
          const uint32_t took = millis() - t0;
          if (took >= 300) {
            logSDf("[verbose] web: %s from %s took %u ms", req_uri.c_str(),
                   _currentClient.remoteIP().toString().c_str(), (unsigned)took);
          }
        }
      } else {
        // An idle socket keeps its second only while nobody is waiting behind
        // it. Browsers open connections on speculation and leave them empty;
        // one of those at the front of a one-client server held the tab the
        // user actually clicked for up to a second. hasClient() accepts the
        // next connection into the server's own slot, so nothing is lost by
        // asking.
        if (millis() - _statusChange <= WEB_IDLE_CLIENT_MS && !_server.hasClient())
          keepCurrentClient = true;
        callYield = true;
      }
    }

    if (!keepCurrentClient) {
      _currentClient = WiFiClient();
      _currentStatus = HC_NONE;
      _currentUpload.reset();
      _currentRaw.reset();
    }
    if (callYield) yield();
  }
};

static ScaleWebServer ota_server(80);
static bool ota_server_running  = false;
static bool routes_registered   = false;

// While the WiFi setup portal runs, port 80 serves its form instead. The
// access point is the only network then, the main interface has nothing to
// offer on it, and its host check would refuse every request a phone sends.
// A server object of its own, because routes cannot be taken off one.
static ScaleWebServer portal_server(80);
static bool portal_server_running    = false;
static bool portal_routes_registered = false;

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
  // The headers webRequire() reads. Authorization is collected by the library
  // on its own; Origin has to be asked for, and asked for before begin().
  static const char *HDR_KEYS[] = { "Origin" };
  ota_server.collectHeaders(HDR_KEYS, 1);
  ota_server.begin();
  ota_server.tune();
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

static void portalEnsureRunning() {
  if (portal_server_running) return;
  if (!portal_routes_registered) {
    portal_routes_registered = true;
    registerPortalRoutes(portal_server);
  }
  portal_server.begin();
  portal_server.tune();
  portal_server_running = true;
  Serial.printf("Setup portal listening: http://%s/\n", setupPortalIP().toString().c_str());
}

static void portalEnsureStopped() {
  if (!portal_server_running) return;
  portal_server.stop();
  portal_server_running = false;
  Serial.println("Setup portal stopped");
}

// Idempotent, called once a second from appLoop() and once more whenever a
// screen wants the state to settle now. The only owner of the socket: there
// used to be a second automaton in web_access.cpp with its own copy of this
// state, and the copies drifted until port 80 stayed shut until reboot. The
// setup portal is one more state of the same socket, not a second owner:
// each server is stopped before the other one binds the port.
void webServerSyncState() {
  if (setupPortalActive()) {
    serverEnsureStopped();
    portalEnsureRunning();
    return;
  }
  portalEnsureStopped();
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
  registerStaticRoutes(ota_server);

  // Every page and every endpoint it owns, straight from the one table. The
  // page route itself is wrapped here so the gate check and the chrome happen
  // in one place and cannot be forgotten in a new page.
  for (size_t i = 0; i < WEB_PAGE_COUNT; i++) {
    // Captured as a pointer by value, not as a reference to the loop
    // variable. The descriptor itself lives in ROM either way, but a
    // by-value pointer says so at the capture and leaves nothing to reason
    // about once the loop has ended.
    const WebPage *pg = WEB_PAGES[i];
    ota_server.on(pg->path, HTTP_GET, [pg]() {
      // A page that does not apply to this device is absent, not refused:
      // there is no backend page at all on Spoolman.
      if (pg->applies && !pg->applies()) {
        ota_server.send(404, "text/plain", "Not found");
        return;
      }
      if (!webRequire(ota_server, pg->gate, webPageLabel(*pg))) return;
      String html = webShellHead(webPageLabel(*pg));
      html += webShellHeader();
      html += webShellNav(pg->path);
      html += pg->body();
      html += webShellFoot();   // links and disclaimer close the page
      ota_server.send(200, "text/html", html);
    });
    if (pg->routes) pg->routes(ota_server);
  }


  // The two FilaMan device endpoints. GATE_ALWAYS, the only level that ignores
  // the master switch: these have to answer whenever the scale is awake, that
  // is the whole point of keeping the socket up. What the gate does ask is
  // that the caller is the configured FilaMan server - see webRequire().
  //
  // FilaMan sends both fire and forget and waits five seconds, so nothing here
  // may block. A request is only parked and appLoop() picks it up, because the
  // NFC bus belongs to the loop task.

  // "Import from tag": whatever is on the reader is sent back on the next tick.
  ota_server.on("/api/v1/rfid/scan-request", HTTP_POST, []() {
    if (!webRequire(ota_server, GATE_ALWAYS, "FilaMan")) return;
    tagScanRequest();
    ota_server.send(200, "application/json", "{\"status\":\"ok\"}");
  });


  ota_server.on("/api/v1/rfid/write", HTTP_POST, []() {
    if (!webRequire(ota_server, GATE_ALWAYS, "FilaMan")) return;
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, ota_server.arg("plain"));
    if (err) {
      ota_server.send(400, "application/json", "{\"status\":\"error\"}");
      return;
    }

    const int spool_id    = doc["spool_id"]    | 0;
    const int location_id = doc["location_id"] | 0;

    // FilaMan's backend can expand the trigger into a full record before
    // forwarding it, under either of two protocol names. Keep what it sent:
    // the server decided what belongs on the tag.
    //
    // It only does that with "write extended data" turned on in its admin
    // settings, which is off by default - so a bare trigger carrying nothing
    // but the id is the normal case, not an old server. The scale then builds
    // the record itself from the spool record, the same one the tag page
    // writes, and the setting stops mattering.
    const char *proto = doc["protocol"] | "";
    const bool has_record = !strcmp(proto, "openspool") || !strcmp(proto, "filaman");
    tagRemotePayloadSet(has_record ? ota_server.arg("plain").c_str() : "",
                        spool_id);

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
  if (ota_server_running)    ota_server.handleClient();
  if (portal_server_running) portal_server.handleClient();
}
