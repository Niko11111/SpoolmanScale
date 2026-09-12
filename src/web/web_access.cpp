#include "web/web_access.h"

#include "services/ota_state.h"

#include <Arduino.h>
#include <WiFi.h>
#include <string.h>
#include "mbedtls/base64.h"

#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/device_name.h"
#include "services/prefs_store.h"
#include "services/wifi_manager.h"
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
static char s_pass[WEB_PASS_MAX + 1] = "";

bool webMasterEnabled()      { return master_on; }
bool webConfigEnabled()      { return config_on; }
bool webMaintenanceEnabled() { return maintenance_on; }
bool webHasPassword()        { return s_pass[0] != '\0'; }

// Keeps the digits, drops the rest, and treats anything shorter than the
// minimum as no password: a two digit lock would only look like one.
static void passFromString(const char *in) {
  size_t n = 0;
  for (const char *p = in ? in : ""; *p && n < WEB_PASS_MAX; p++) {
    if (*p >= '0' && *p <= '9') s_pass[n++] = *p;
  }
  s_pass[n] = '\0';
  if (n < WEB_PASS_MIN) s_pass[0] = '\0';
}

void webSetPassword(const char *digits) {
  passFromString(digits);
  prefsPutString("web_pass", s_pass);
  logSDf("Web: password %s", s_pass[0] ? "set" : "removed");
}

void webAccessLoad() {
  master_on      = prefsGetBool("web_master", true);
  config_on      = prefsGetBool("web_config", false);
  maintenance_on = prefsGetBool("web_maint",  false);
  passFromString(prefsGetString("web_pass", "").c_str());
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

// ---------------------------------------------------------------------------
// Who is asking. The gates say whether a feature is on; none of them ever
// said who was allowed to use it. Three questions are asked before the gate:
//
//  - Is the Host header one of our own names? A page on attacker.example can
//    have its DNS flip to this scale's LAN address (DNS rebinding) and then
//    read every reply as if it were same-origin. Its requests still carry
//    Host: attacker.example, which is the one thing it cannot change.
//  - For a request that changes something: does the Origin header, when the
//    browser sends one, name us? Every cross-site POST a browser makes
//    carries the origin of the page that made it, and /app.js posts
//    text/plain, which needs no preflight - so without this check any web
//    page the owner visits could repoint the backend, restart the scale or
//    submit a firmware image through a hidden form.
//  - For the two writing gates: the password, when one is set.
//
// FilaMan's device protocol is a different case. It is driven from a server,
// not a browser, and had no check at all: anything on the LAN could start a
// remote link and, with the options set, have a record written to the tag on
// the pad. It now has to prove it is the configured server - by the device
// token if it sends one, otherwise by coming from that server's address
// without a browser's Origin.
// ---------------------------------------------------------------------------

enum WebVerdict : uint8_t {
  WEB_OK = 0,
  WEB_FLASHING,      // an image is being written, nothing else is served
  WEB_NO_PROTOCOL,   // device protocol route, but no FilaMan configured
  WEB_BAD_TOKEN,     // device protocol route from something that is not FilaMan
  WEB_BAD_HOST,      // Host header is not one of our names
  WEB_BAD_ORIGIN,    // a browser's cross-site POST
  WEB_GATE_SHUT,     // the switch on the device is off
  WEB_NEED_AUTH      // password set, none or a wrong one sent
};

static void lowerTrim(String &s) {
  s.trim();
  s.toLowerCase();
  while (s.endsWith(".")) s.remove(s.length() - 1);
}

// The names this scale answers to: its address, its full name, its bare
// label and its mDNS name. A port suffix is ignored, the case too.
static bool hostIsOurs(const String &host_in) {
  // No Host header at all is not a browser. Nothing that rebinding or a
  // cross-site form can produce comes without one.
  if (host_in.length() == 0) return true;
  String host = host_in;
  const int colon = host.indexOf(':');
  if (colon >= 0) host = host.substring(0, colon);
  lowerTrim(host);
  if (host.length() == 0) return false;

  if (host == wifiManagerLocalIP().toString()) return true;

  String s = deviceFqdn();  lowerTrim(s); if (s.length() && host == s) return true;
  s = deviceLabel();        lowerTrim(s); if (s.length() && host == s) return true;
  char m[DEVICE_FQDN_MAX + 1];
  deviceMdnsName(m, sizeof(m));
  s = m;                    lowerTrim(s); if (s.length() && host == s) return true;
  return false;
}

// "http://<one of our names>[:port]". Anything else - https, "null" from a
// sandboxed frame, another host - is a page that is not ours.
static bool originIsOurs(const String &origin) {
  if (!origin.startsWith("http://")) return false;
  String h = origin.substring(7);
  const int slash = h.indexOf('/');
  if (slash >= 0) h = h.substring(0, slash);
  return h.length() > 0 && hostIsOurs(h);
}

// "Authorization: Basic base64(user:password)". The user name is not looked
// at: the device has one password and no accounts.
static bool passwordOk(WebServer &srv) {
  if (!srv.hasHeader("Authorization")) return false;
  String a = srv.header("Authorization");
  a.trim();
  if (!a.startsWith("Basic ")) return false;
  a = a.substring(6);
  a.trim();
  unsigned char out[64];
  size_t olen = 0;
  if (mbedtls_base64_decode(out, sizeof(out) - 1, &olen,
                            (const unsigned char *)a.c_str(), a.length()) != 0) {
    return false;
  }
  out[olen] = '\0';
  const char *colon = strchr((const char *)out, ':');
  const char *pw = colon ? colon + 1 : (const char *)out;
  return strcmp(pw, s_pass) == 0;
}

// "Authorization: Device <token>", the same token the scale sends FilaMan on
// every heartbeat. The scheme word is not checked, only the token: what
// matters is that the caller holds it, and nothing but FilaMan does.
static bool deviceTokenOk(WebServer &srv) {
  const char *tok = filamanDeviceToken();
  if (!tok[0] || !srv.hasHeader("Authorization")) return false;
  String a = srv.header("Authorization");
  a.trim();
  const int sp = a.indexOf(' ');
  if (sp < 0) return false;
  String v = a.substring(sp + 1);
  v.trim();
  return v.equals(tok);
}

// Whether the request comes from the address the FilaMan host resolves to.
// Resolved once per host string and kept; a failed resolution is retried on
// the next request rather than cached, so a DNS hiccup at the first call
// does not shut the protocol for the session.
static bool fromBackendHost(WebServer &srv) {
  static char      cached_for[64] = "";
  static IPAddress cached_ip;
  static bool      cached_ok = false;

  char host[64];
  strncpy(host, backendHost(), sizeof(host) - 1);
  host[sizeof(host) - 1] = '\0';
  char *colon = strchr(host, ':');
  if (colon) *colon = '\0';
  if (!host[0]) return false;

  if (!cached_ok || strcmp(cached_for, host) != 0) {
    cached_ok = cached_ip.fromString(host);
    if (!cached_ok) cached_ok = (WiFi.hostByName(host, cached_ip) == 1);
    strncpy(cached_for, host, sizeof(cached_for) - 1);
    cached_for[sizeof(cached_for) - 1] = '\0';
  }
  return cached_ok && srv.client().remoteIP() == cached_ip;
}

static WebVerdict verdict(WebServer &srv, WebGate g) {
  // Writing firmware holds the loop, and the progress view is served from
  // inside that loop so the bar can move. Nothing else is: a page built while
  // an image is being written would come out of the same heap, and a
  // /status.json answered mid-flash would tell the waiting browser the device
  // is back when it has not even rebooted yet.
  if (gh_flash_active && srv.uri() != "/api/ota/progress") return WEB_FLASHING;

  if (g == GATE_ALWAYS) {
    if (!backendIsFilaMan() || !filamanDeviceToken()[0]) return WEB_NO_PROTOCOL;
    if (deviceTokenOk(srv)) return WEB_OK;
    if (!srv.hasHeader("Origin") && fromBackendHost(srv)) return WEB_OK;
    return WEB_BAD_TOKEN;
  }

  if (!hostIsOurs(srv.hostHeader())) return WEB_BAD_HOST;
  if (srv.method() != HTTP_GET && srv.hasHeader("Origin") &&
      !originIsOurs(srv.header("Origin"))) {
    return WEB_BAD_ORIGIN;
  }
  if (!webGateOpen(g)) return WEB_GATE_SHUT;
  if (g >= GATE_CONFIG && webHasPassword() && !passwordOk(srv)) return WEB_NEED_AUTH;
  return WEB_OK;
}

bool webAllowed(WebServer &srv, WebGate g) {
  return verdict(srv, g) == WEB_OK;
}

// One line per refusal, but not one per poll: a status page left open under a
// name the scale does not know would otherwise write every two seconds.
static void logRefusal(WebServer &srv, const char *why) {
  static unsigned long last_ms = 0;
  if (last_ms && millis() - last_ms < 10000UL) return;
  last_ms = millis();
  logSDf("Web: %s refused (%s) from %s, host '%s'", srv.uri().c_str(), why,
         srv.client().remoteIP().toString().c_str(), srv.hostHeader().c_str());
}

bool webRequire(WebServer &srv, WebGate g, const char *what) {
  const bool api = srv.uri().startsWith("/api/");
  switch (verdict(srv, g)) {
    case WEB_OK:
      return true;
    case WEB_FLASHING:
      srv.send(503, "text/plain", "flashing");
      return false;
    case WEB_NO_PROTOCOL:
      srv.send(404, "text/plain", "Not found");
      return false;
    case WEB_BAD_TOKEN:
      logRefusal(srv, "device token");
      srv.send(401, "application/json", "{\"status\":\"error\",\"error\":\"unauthorized\"}");
      return false;
    case WEB_BAD_HOST:
      logRefusal(srv, "host");
      srv.send(403, "text/plain; charset=utf-8", T(STR_W_BAD_HOST));
      return false;
    case WEB_BAD_ORIGIN:
      logRefusal(srv, "origin");
      srv.send(403, "text/plain; charset=utf-8", T(STR_W_BAD_ORIGIN));
      return false;
    case WEB_GATE_SHUT:
      // An /api/* caller is a script, not a reader. Handing it a kilobyte of
      // styled HTML it will never render only makes the failure harder to
      // see in a console.
      if (api) srv.send(403, "text/plain", T(STR_W_OFF_BODY));
      else     webSendDisabled(srv, what, T(STR_W_OFF_PATH));
      return false;
    case WEB_NEED_AUTH:
      // The browser turns this into its own password prompt on a page, and
      // sends the answer along with everything it asks for afterwards.
      srv.requestAuthentication(BASIC_AUTH, "SpoolmanScale", T(STR_W_AUTH_NEEDED));
      return false;
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
