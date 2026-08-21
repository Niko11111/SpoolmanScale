#include "web_access.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "ota_web_server.h"
#include "prefs_store.h"

// Master defaults ON so browsing the device address gives you something rather
// than a dead port. The two gates default OFF: everything behind them either
// changes device state or writes firmware.
static bool master_on      = true;
static bool maintenance_on = false;

bool webMasterEnabled()      { return master_on; }
bool webMaintenanceEnabled() { return maintenance_on; }

void webAccessLoad() {
  master_on      = prefsGetBool("web_master", true);
  maintenance_on = prefsGetBool("web_maint",  false);
}

static bool server_started = false;

void webSetMasterEnabled(bool on) {
  master_on = on;
  prefsPutBool("web_master", on);
  if (!on) { stopOtaServer(); server_started = false; }
}

void webServerTick() {
  if (master_on && wifi_ok) {
    if (!server_started) { startOtaServer(); server_started = true; }
  } else if (server_started) {
    stopOtaServer();
    server_started = false;
  }
}

void webSetMaintenanceEnabled(bool on) {
  maintenance_on = on;
  prefsPutBool("web_maint", on);
}

void webSendDisabled(WebServer &srv, const char *what, const char *menu) {
  String h;
  h.reserve(2200);
  h += F("<!DOCTYPE html><html><head><meta charset='utf-8'>"
         "<meta name='viewport' content='width=device-width,initial-scale=1'>"
         "<title>SpoolmanScale</title><style>"
         "*{box-sizing:border-box;margin:0;padding:0}"
         "body{background:#06080f;color:#e8f0ff;font-family:-apple-system,BlinkMacSystemFont,"
         "'Segoe UI',sans-serif;min-height:100vh;display:flex;flex-direction:column;"
         "align-items:center;justify-content:center;padding:32px 16px;text-align:center}"
         ".card{background:#0c1828;border:1px solid #1a3060;border-radius:14px;"
         "padding:28px;max-width:440px}"
         "h1{color:#f0b838;font-size:20px;margin-bottom:12px}"
         "p{color:#c8d8f0;font-size:14px;line-height:1.6;margin-bottom:10px}"
         ".path{font-family:ui-monospace,Consolas,monospace;color:#28d49a;"
         "background:#0a1828;border:1px solid #1a3060;border-radius:6px;"
         "padding:8px 12px;display:inline-block;margin:6px 0}"
         "a{color:#28d49a;text-decoration:none;font-size:14px}"
         "a:hover{text-decoration:underline}"
         "</style></head><body><div class='card'>");
  h += "<h1>";
  h += what;
  h += F(" is switched off</h1>"
         "<p>This section is disabled on the device, so it is not being served.</p>"
         "<p>Turn it on here:</p><div class='path'>");
  h += menu;
  h += F("</div><p>Then reload this page.</p>"
         "<p><a href='/'>&#8592; Back to status</a></p>"
         "</div></body></html>");
  srv.send(403, "text/html", h);
}
