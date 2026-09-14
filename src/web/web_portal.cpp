#include "web/web_portal.h"

#include <Arduino.h>
#include <WebServer.h>
#include <cstring>

#include "services/setup_portal.h"
#include "web/web_shell.h"
// Last, as everywhere in web/: T() is a macro.
#include "lang.h"

#define PORTAL_SSID_MAX      32
#define PORTAL_PASS_MIN      8
#define PORTAL_PASS_MAX      64    // 63 characters, or 64 as hex
#define PORTAL_PAGE_RESERVE  3072

// The colours of the device's own setup screens. Inputs at 16 px, so iOS does
// not zoom into the form when a field gets focus.
static const char PORTAL_CSS[] PROGMEM =
  "body{margin:0;background:#0a1020;color:#e8f0ff;font:16px/1.45 -apple-system,system-ui,sans-serif}"
  "main{max-width:420px;margin:0 auto;padding:24px 16px}"
  "h1{color:#28d49a;font-size:22px;margin:0 0 8px}"
  "p{color:#c8d8f0}"
  "label{display:block;margin:18px 0 6px;color:#c8d8f0;font-size:14px}"
  "select,input{box-sizing:border-box;width:100%;padding:12px;font-size:16px;border-radius:8px;"
  "border:1px solid #2a4080;background:#1e2e4a;color:#fff}"
  "button{margin-top:26px;width:100%;padding:14px;font-size:17px;border-radius:10px;"
  "border:1px solid #2a5030;background:#1a3020;color:#40c080}"
  ".err{background:#3a1010;color:#ff8080;padding:10px 12px;border-radius:8px}";

static const char PAGE_END[] = "</main></body></html>";

static String pageStart() {
  String h;
  h.reserve(PORTAL_PAGE_RESERVE);
  h += F("<!doctype html><html lang='");
  h += (g_lang == LANG_DE) ? "de" : "en";
  h += F("'><head><meta charset='utf-8'>"
         "<meta name='viewport' content='width=device-width,initial-scale=1'>"
         "<title>SpoolmanScale</title><style>");
  h += FPSTR(PORTAL_CSS);
  h += F("</style></head><body><main><h1>SpoolmanScale</h1>");
  return h;
}

// The form. After an error it keeps the network chosen and the name typed;
// the password is never sent back.
static String formPage(const char *error, const String &selected, const String &typed) {
  String h = pageStart();
  h += F("<p>");
  h += T(STR_PORTAL_PAGE_INTRO);
  h += F("</p>");
  if (error) {
    h += F("<p class='err'>");
    h += error;
    h += F("</p>");
  }

  h += F("<form method='post' action='/wifi'><label for='net'>");
  h += T(STR_PORTAL_PAGE_NETWORK);
  h += F("</label><select id='net' name='net'><option value=''>");
  h += T(STR_PORTAL_PAGE_CHOOSE);
  h += F("</option>");
  for (int i = 0; i < setupPortalNetworkCount(); i++) {
    const char *ssid = setupPortalNetwork(i);
    const String esc = htmlEsc(ssid);
    h += F("<option value='");
    h += esc;
    h += '\'';
    if (selected == ssid) h += F(" selected");
    h += '>';
    h += esc;
    h += F("</option>");
  }
  h += F("</select>");

  h += F("<label for='ssid'>");
  h += T(STR_PORTAL_PAGE_OTHER);
  h += F("</label><input id='ssid' name='ssid' autocapitalize='none' autocorrect='off' spellcheck='false' maxlength='");
  h += PORTAL_SSID_MAX;
  h += F("' value='");
  h += htmlEsc(typed.c_str());
  h += F("'>");

  h += F("<label for='pass'>");
  h += T(STR_PORTAL_PAGE_PASS);
  h += F("</label><input id='pass' name='pass' type='password' autocapitalize='none' autocorrect='off' spellcheck='false' maxlength='");
  h += PORTAL_PASS_MAX;
  h += F("'><button type='submit'>");
  h += T(STR_PORTAL_PAGE_SUBMIT);
  h += F("</button></form>");
  h += PAGE_END;
  return h;
}

static void sendPage(WebServer &srv, int code, const String &html) {
  // A portal sheet keeps pages longer than a browser; list and errors are
  // per request.
  srv.sendHeader("Cache-Control", "no-store");
  srv.send(code, "text/html; charset=utf-8", html);
}

void registerPortalRoutes(WebServer &srv) {
  srv.on("/", HTTP_GET, [&srv]() {
    sendPage(srv, 200, formPage(nullptr, String(), String()));
  });

  srv.on("/wifi", HTTP_POST, [&srv]() {
    const String net = srv.arg("net");
    String typed = srv.arg("ssid");
    typed.trim();
    // A typed name wins over the list: the field exists for the network the
    // list does not show.
    const String ssid = typed.length() ? typed : net;
    const String pass = srv.arg("pass");

    if (ssid.length() == 0 || ssid.length() > PORTAL_SSID_MAX) {
      sendPage(srv, 400, formPage(T(STR_PORTAL_PAGE_ERR_SSID), net, typed));
      return;
    }
    // Empty is an open network. Otherwise WPA2's limits, checked here so the
    // phone is told, rather than the display reporting a failed connect later.
    if (pass.length() > 0 && (pass.length() < PORTAL_PASS_MIN || pass.length() > PORTAL_PASS_MAX)) {
      sendPage(srv, 400, formPage(T(STR_PORTAL_PAGE_ERR_PASS), net, typed));
      return;
    }

    char msg[384];
    snprintf(msg, sizeof(msg), T(STR_PORTAL_PAGE_DONE), htmlEsc(ssid.c_str()).c_str());
    String h = pageStart();
    h += F("<p>");
    h += msg;
    h += F("</p>");
    h += PAGE_END;
    sendPage(srv, 200, h);
    // Only now the answer is out. The access point closes a moment later,
    // see setupPortalTick().
    setupPortalSubmit(ssid.c_str(), pass.c_str());
  });

  // Everything else goes to the form, above all the probes a phone sends to
  // find out whether a network has a portal: the redirect is what makes it
  // show one.
  srv.onNotFound([&srv]() {
    char url[32];
    setupPortalUrl(url, sizeof(url));
    srv.sendHeader("Location", url);
    srv.sendHeader("Cache-Control", "no-store");
    srv.send(302, "text/plain", "");
  });
}
