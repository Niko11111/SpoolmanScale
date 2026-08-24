// Settings: the device name, the list limits and the display gain. Three
// small cards rather than three thin pages - an eighth tab would cost more
// than it returns.
//
// The device name came from a page of its own. It belongs here: it is a
// setting like the others, and the device has no way to type it - the address
// screen carries a twelve key numeric pad, so letters cannot be entered there
// at all.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>

#include "hardware/display.h"
#include "hardware/sd_logger.h"
#include "services/list_limits.h"
#include "services/mdns_service.h"
#include "services/prefs_store.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

static const char* label() { return T(STR_W_NAV_SETTINGS); }

static String body() {
  char hint[220];
  snprintf(hint, sizeof(hint), T(STR_W_DEVNAME_HINT), MDNS_HOSTNAME_MAX);

  String h;
  h.reserve(4200);

  h += F("<div class='grid'><div class='card wide'><h2>");
  h += T(STR_W_C_DEVNAME);
  h += F("</h2><div class='field'><div class='inrow'>"
         "<input id='hn' type='text' maxlength='");
  h += String(MDNS_HOSTNAME_MAX);
  h += F("' spellcheck='false' value='");
  h += mdnsHostname();
  h += F("'><span class='suffix'>.local</span><button onclick='setHn()'>");
  h += T(STR_W_SAVE);
  h += F("</button></div><span class='msg' id='hn-s'></span>"
         "<span class='hint'>");
  h += hint;
  h += F("</span></div></div>");

  h += F("<div class='card'><h2>");
  h += T(STR_W_C_LIMITS);
  h += F("</h2><div class='field'><label>");
  h += T(STR_W_LIMIT_SPOOLS);
  h += F("</label><div class='inrow'><input id='ll' type='number' min='5' max='100' value='");
  h += String(spool_list_limit);
  h += F("'><span class='hint' style='flex:1'>");
  h += T(STR_W_LIMIT_HINT);
  h += F("</span></div></div><div class='field'><label>");
  h += T(STR_W_LIMIT_LOCS);
  h += F("</label><div class='inrow'><input id='lc' type='number' min='5' max='100' value='");
  h += String(location_list_limit);
  h += F("'><span class='hint' style='flex:1'>");
  h += T(STR_W_LIMIT_WARN);
  h += F("</span></div></div>"
         "<button class='quiet block' onclick='setLimits()'>");
  h += T(STR_W_SAVE);
  h += F("</button><span class='msg' id='ll-s'></span></div>");

  h += F("<div class='card'><h2>");
  h += T(STR_W_C_DISPLAY);
  h += F("</h2><div class='field'><label>");
  h += T(STR_W_GAIN);
  h += F("</label><div class='range'>"
         "<input id='gn' type='range' min='100' max='300' step='5' value='");
  h += String(displayGetUiGain());
  h += F("' oninput='this.nextElementSibling.value=this.value'><output>");
  h += String(displayGetUiGain());
  h += F("</output></div><span class='hint'>");
  h += T(STR_W_GAIN_HINT);
  h += F("</span></div>"
         "<button class='quiet block' onclick='setGain()'>");
  h += T(STR_W_SAVE);
  h += F("</button><span class='msg' id='gn-s'></span></div></div>");

  // Its own script. When the pages were split the shared block stayed behind
  // on one of them and every Save button here called a function that was no
  // longer on the page.
  h += F("<script>const M={ok:");
  h += jsStr(T(STR_W_SAVED));
  h += F(",err:");
  h += jsStr(T(STR_W_ERROR));
  h += F(",now:");
  h += jsStr(T(STR_W_DEVNAME_NOW));
  h += F("};"
         "function flash(id,t,bad){const e=document.getElementById(id);"
         "e.textContent=t;e.className='msg'+(bad?' bad':'');"
         "setTimeout(()=>{e.textContent='';},4000);}"
         "function setHn(){const v=document.getElementById('hn').value;"
         "fetch('/api/hostname',{method:'POST',headers:{'Content-Type':'text/plain'},body:v})"
         ".then(r=>r.text().then(t=>({ok:r.ok,t}))).then(r=>flash('hn-s',r.t,!r.ok));}"
         "function clamp(el){let v=parseInt(el.value)||5;"
         "if(v<5)v=5;if(v>100)v=100;el.value=v;return v;}"
         "function setLimits(){"
         "const a=clamp(document.getElementById('ll')),b=clamp(document.getElementById('lc'));"
         "Promise.all(["
         "fetch('/api/listlimit',{method:'POST',headers:{'Content-Type':'text/plain'},body:String(a)}),"
         "fetch('/api/loclimit',{method:'POST',headers:{'Content-Type':'text/plain'},body:String(b)})"
         "]).then(rs=>flash('ll-s',rs.every(r=>r.ok)?M.ok:M.err,!rs.every(r=>r.ok)));}"
         "function setGain(){const v=document.getElementById('gn').value;"
         "fetch('/api/gain',{method:'POST',headers:{'Content-Type':'text/plain'},body:String(v)})"
         ".then(r=>flash('gn-s',r.ok?M.ok:M.err,!r.ok));}"
         "</script>");
  return h;
}

static void routes(WebServer &srv) {
  srv.on("/api/hostname", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    srv.send(200, "application/json",
             String("{\"host\":\"") + mdnsHostname() + "\",\"mdns\":"
             + (mdnsRunning() ? "true" : "false") + "}");
  });

  srv.on("/api/hostname", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    String name = srv.arg("plain");
    name.trim();
    if (!mdnsSetHostname(name.c_str())) {
      // Named rather than a bare "invalid": the rule is not obvious and the
      // field has just been typed.
      srv.send(400, "text/plain", T(STR_W_DEVNAME_BAD));
      return;
    }
    logSDf("Web: device name set to %s", mdnsHostname());
    srv.send(200, "text/plain", String(T(STR_W_DEVNAME_NOW)) + " http://"
                                + mdnsHostname() + ".local/");
  });

  srv.on("/api/listlimit", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    srv.send(200, "application/json", String("{\"limit\":") + spool_list_limit + "}");
  });
  srv.on("/api/listlimit", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    int v = srv.arg("plain").toInt();
    if (v < 5) v = 5;
    if (v > 100) v = 100;
    spool_list_limit = v;
    prefsPutInt("spool_limit", v);
    logSDf("Web: spool list limit -> %d", v);
    srv.send(200, "application/json", String("{\"limit\":") + v + "}");
  });

  srv.on("/api/loclimit", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    srv.send(200, "application/json", String("{\"limit\":") + location_list_limit + "}");
  });
  srv.on("/api/loclimit", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    int v = srv.arg("plain").toInt();
    if (v < 5) v = 5;
    if (v > 100) v = 100;
    location_list_limit = v;
    prefsPutInt("loc_limit", v);
    logSDf("Web: location list limit -> %d", v);
    srv.send(200, "application/json", String("{\"limit\":") + v + "}");
  });

  srv.on("/api/gain", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    int v = srv.arg("plain").toInt();
    if (v < 100) v = 100;
    if (v > 300) v = 300;
    displaySetUiGain((uint16_t)v);
    prefsPutUInt("ui_gain", (uint32_t)v);
    logSDf("Web: UI gain -> %d", v);
    srv.send(200, "application/json", String("{\"gain\":") + v + "}");
  });
}

extern const WebPage PAGE_CONFIG;
const WebPage PAGE_CONFIG = {
  "/config", label,  GATE_CONFIG, nullptr,
  body, routes
};
