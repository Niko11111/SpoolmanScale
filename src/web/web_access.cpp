#include "web/web_access.h"

#include <Arduino.h>

#include "services/prefs_store.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

// Master defaults ON so browsing the device address gives you something
// rather than a dead port. The two writing gates default OFF: everything
// behind them either changes how the scale behaves or writes firmware, and
// neither should become reachable just because the server is up.
static bool master_on      = true;
static bool config_on      = false;
static bool maintenance_on = false;

bool webMasterEnabled()      { return master_on; }
bool webConfigEnabled()      { return config_on; }
bool webMaintenanceEnabled() { return maintenance_on; }

void webAccessLoad() {
  master_on      = prefsGetBool("web_master", true);
  config_on      = prefsGetBool("web_config", false);
  maintenance_on = prefsGetBool("web_maint",  false);
}

// Nothing here touches the socket. Whether the server listens is derived
// once a second in webServerSyncState() from these switches plus the remote
// link, so there is exactly one place that opens and closes port 80. The
// previous version kept its own copy of that state here and went out of sync
// the moment the web screen closed the server behind its back.
void webSetMasterEnabled(bool on) {
  master_on = on;
  prefsPutBool("web_master", on);
}

void webSetConfigEnabled(bool on) {
  config_on = on;
  prefsPutBool("web_config", on);
}

void webSetMaintenanceEnabled(bool on) {
  maintenance_on = on;
  prefsPutBool("web_maint", on);
}

bool webGateOpen(WebGate g) {
  switch (g) {
    case GATE_ALWAYS: return true;
    case GATE_OPEN:   return master_on;
    case GATE_CONFIG: return master_on && config_on;
    case GATE_MAINT:  return master_on && maintenance_on;
  }
  return false;
}

bool webRequire(WebServer &srv, WebGate g, const char *what) {
  if (webGateOpen(g)) return true;
  // An /api/* caller is a script, not a reader. Handing it a kilobyte of
  // styled HTML it will never render only makes the failure harder to see in
  // a console.
  if (srv.uri().startsWith("/api/")) {
    srv.send(403, "text/plain", T(STR_W_OFF_BODY));
  } else {
    webSendDisabled(srv, what, T(STR_W_OFF_PATH));
  }
  return false;
}

void webSendDisabled(WebServer &srv, const char *what, const char *menu) {
  char title[80];
  snprintf(title, sizeof(title), T(STR_W_OFF_TITLE), what ? what : "");

  String h;
  h.reserve(2000);
  h += F("<!DOCTYPE html><html><head><meta charset='utf-8'>"
         "<meta name='viewport' content='width=device-width,initial-scale=1'>"
         "<link rel='icon' type='image/png' href='/favicon.png'>"
         "<title>SpoolmanScale</title><style>"
         "*{box-sizing:border-box;margin:0;padding:0}"
         "body{background:#06080f;color:#e8f0ff;"
         "font-family:ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif;"
         "min-height:100vh;display:flex;flex-direction:column;align-items:center;"
         "justify-content:center;padding:32px 16px;text-align:center}"
         ".card{background:#0c1828;border:1px solid #14243c;border-radius:14px;"
         "padding:28px;max-width:460px}"
         "h1{color:#f0b838;font-size:19px;margin-bottom:12px}"
         "p{color:#c8d8f0;font-size:14px;line-height:1.6;margin-bottom:10px}"
         ".path{font-family:ui-monospace,Menlo,Consolas,monospace;color:#28d49a;"
         "background:#0a1220;border:1px solid #14243c;border-radius:8px;"
         "padding:8px 12px;display:inline-block;margin:6px 0;font-size:13px}"
         "a{color:#28d49a;text-decoration:none;font-size:14px}"
         "a:hover{text-decoration:underline}"
         "</style></head><body><div class='card'><h1>");
  h += title;
  h += F("</h1><p>");
  h += T(STR_W_OFF_BODY);
  h += F("</p><p>");
  h += T(STR_W_OFF_WHERE);
  h += F("</p><div class='path'>");
  h += (menu && menu[0]) ? menu : T(STR_W_OFF_PATH);
  h += F("</div><p>");
  h += T(STR_W_OFF_RELOAD);
  h += F("</p><p><a href='/'>&#8592; ");
  h += T(STR_W_BACK_STATUS);
  h += F("</a></p></div></body></html>");
  srv.send(403, "text/html", h);
}
