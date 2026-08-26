// Settings: the device name, the list limits and the display gain. Three
// small cards rather than three thin pages - an eighth tab would cost more
// than it returns.
//
// The device name came from a page of its own. It belongs here: it is a
// setting like the others, and the device has no way to type it - the address
// screen carries a twelve key numeric pad, so letters cannot be entered there
// at all. It takes a whole name, "scale" or "scale.home.arpa": ".local" is
// what mDNS answers to, not the only address a network can have.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>

#include "app/app_state.h"
#include "hardware/display.h"
#include "hardware/sd_logger.h"
#include "services/device_name.h"
#include "services/list_limits.h"
#include "services/mdns_service.h"
#include "services/prefs_store.h"
#include "services/user_options.h"
#include "services/time_service.h"
#include "services/wifi_manager.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

static const char* label() { return T(STR_W_NAV_SETTINGS); }


// The other addresses that reach the same scale, in the order someone would
// try them. Both are listed because neither always works: a .local name is
// lost on some Android builds, and a DNS name only exists where the network
// serves it.
static String altAddresses() {
  String a;
  if (deviceDomain()[0] && mdnsRunning()) {
    char m[DEVICE_FQDN_MAX + 1];
    deviceMdnsName(m, sizeof(m));
    a = m;
  }
  if (wifi_ok) {
    if (a.length()) a += " · ";
    a += wifiManagerLocalIP().toString();
  }
  return a;
}

// The verdict under the field, already translated and already filled in.
// Building it here rather than in the page keeps every user facing word on
// the T() side, the way the rest of the firmware does it.
static String dnsVerdict(bool &bad, bool &waiting) {
  bad = waiting = false;
  if (!deviceDomain()[0]) return String();
  switch (deviceDnsState()) {
    // UNKNOWN with a domain set means the verdict is still being worked out -
    // either the tick has not started the lookup yet or the answer is on its
    // way. Both read the same to someone waiting for it.
    case DEV_DNS_UNKNOWN:
    case DEV_DNS_CHECKING:
      waiting = true;
      return String(T(STR_W_DEVNAME_DNS_WAIT));
    case DEV_DNS_MATCH:
      return String(T(STR_W_DEVNAME_DNS_OK));
    case DEV_DNS_OTHER: {
      bad = true;
      char b[160];
      snprintf(b, sizeof(b), T(STR_W_DEVNAME_DNS_OTHER),
               deviceDnsIP().toString().c_str());
      return String(b);
    }
    case DEV_DNS_FAIL:
      bad = true;
      return String(T(STR_W_DEVNAME_DNS_NONE));
    default:
      return String();
  }
}

// One shape for the card, whether it is rendered into the page or fetched
// after a save. Two builders would drift.
static String nameStateJson() {
  bool bad = false, waiting = false;
  const String verdict = dnsVerdict(bad, waiting);
  String j = "{\"name\":\"" + jsonEsc(deviceFqdn()) + "\"";
  j += ",\"mdns\":"    + String(deviceMdnsEnabled() ? "true" : "false");
  j += ",\"mdnsRun\":" + String(mdnsRunning() ? "true" : "false");
  j += ",\"also\":\""   + jsonEsc(altAddresses().c_str()) + "\"";
  j += ",\"dnsMsg\":\"" + jsonEsc(verdict.c_str()) + "\"";
  j += ",\"dnsBad\":"  + String(bad ? "true" : "false");
  j += ",\"dnsWait\":" + String(waiting ? "true" : "false");
  j += "}";
  return j;
}

static String body() {
  String h;
  h.reserve(7400);

  h += F("<div class='grid'><div class='card wide'><h2>");
  h += T(STR_W_C_DEVNAME);
  h += F("</h2><div class='field'><div class='inrow'>"
         "<input id='hn' type='text' maxlength='");
  h += String(DEVICE_FQDN_MAX);
  h += F("' spellcheck='false' placeholder='scale.home.arpa' value='");
  h += deviceFqdn();
  h += F("'><button id='hn-b'>");
  h += T(STR_W_SAVE);
  // One message line, not two. It carries the DNS verdict, and a save
  // overwrites it for a moment before the verdict comes back - the two are
  // never needed at the same time, and an empty .msg reserves a line whether
  // it says anything or not.
  //
  // Both lines are filled in here as well as by paint(). Everything this card
  // shows is known at render time, and a page that arrives blank and then
  // fills itself in reads as a page that is broken for a moment.
  bool bad = false, waiting = false;
  const String verdict = dnsVerdict(bad, waiting);
  const String also    = altAddresses();

  h += F("</button></div><span class='msg");
  if (bad) h += F(" bad");
  h += F("' id='hn-s'>");
  h += verdict;
  h += F("</span><span class='hint' id='hn-a'>");
  if (also.length()) { h += T(STR_W_DEVNAME_ALSO); h += ": "; h += also; }
  h += F("</span><span class='hint'>");
  h += T(STR_W_DEVNAME_HINT);
  h += F("</span></div>");

  // Second field rather than a second card: it is the same subject, and the
  // switch only makes sense next to the name it applies to.
  //
  // Rendered with its state here rather than filled in by the script: a
  // control that arrives blank and then jumps is worse than one that is a
  // frame late. The shape is .switch/.check from the stylesheet now - it used
  // to be an inline style copied between this page and page_tags.cpp.
  h += F("<div class='field'>"
         "<label class='check'><span class='switch'>"
         "<input id='md' type='checkbox'");
  if (deviceMdnsEnabled()) h += F(" checked");
  h += F("><i></i></span>");
  h += T(STR_W_MDNS);
  h += F("</label><span class='hint'>");
  h += T(STR_W_MDNS_HINT);
  h += F("</span><span class='msg' id='md-s'></span></div></div>");

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
         "<button id='ll-b' class='quiet block'>");
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
         "<button id='gn-b' class='quiet block'>");
  h += T(STR_W_SAVE);
  h += F("</button><span class='msg' id='gn-s'></span></div>");

  // The zone the device writes every timestamp in, the SD log and the drying
  // day count included. It belongs here rather than next to the log: it
  // changes behaviour, it is not a property of one page.
  h += F("<div class='card'><h2>");
  h += T(STR_TZ_TITLE);
  // The index, not the POSIX string. One of those is "<-03>3", and a value
  // carrying angle brackets through an HTML attribute is a fight not worth
  // having when the server has the table anyway.
  h += F("</h2><div class='field'>"
         "<select id='tz'>");
  {
    const int cur = timeZoneIndex();
    if (cur < 0) {
      // A zone that is not in the table can only come from a hand written
      // preference. Shown so it is not silently replaced by the first entry,
      // and inert so it cannot be picked again.
      h += F("<option value='-1' selected disabled>");
      h += timeZoneName();
      h += F("</option>");
    }
    for (size_t i = 0; i < TZ_COUNT; i++) {
      h += F("<option value='");
      h += String((unsigned)i);
      h += F("'");
      if (cur == (int)i) h += F(" selected");
      h += F(">");
      h += TZ_LIST[i].name;
      h += F(" (");
      h += TZ_LIST[i].offset;
      h += F(")</option>");
    }
  }
  h += F("</select><span class='hint'>");
  h += T(STR_W_TZ_NOTE);
  h += F("</span></div><span class='msg' id='tz-s'></span></div>");

  // ---- how the panel behaves --------------------------------------------
  // Waking on load had been documented in user_options.h since it was written
  // and was never switchable: loadPrefs() read it, display_power.cpp acted on
  // it, and no line in the firmware ever wrote it. This is that missing half.
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_C_PANEL);
  h += F("</h2><div class='field'>"
         "<label class='check'><span class='switch'>"
         "<input id='wk' type='checkbox'");
  if (g_wake_on_load) h += F(" checked");
  h += F("><i></i></span>");
  h += T(STR_W_WAKE);
  h += F("</label><span class='hint'>");
  h += T(STR_W_WAKE_HINT);
  h += F("</span><span class='msg' id='wk-s'></span></div></div></div>");

  // Its own script. When the pages were split the shared block stayed behind
  // on one of them and every Save button here called a function that was no
  // longer on the page.
  //
  // Every handler is bound here rather than written into an onclick attribute:
  // a page body is JavaScript inside a C++ string literal, and an attribute is
  // the one place where the two levels of quoting collide.
  // $, flash, post and postFlash come from /app.js. A save answer stands for
  // four seconds and then gives the line back to whatever belongs there - for
  // the name field that is the DNS verdict, which load() repaints, and the
  // two share one line. That is what flash()'s after() argument is for.
  h += F("<script>");
  h += webShellJsStrings();
  h += F("const M={also:");
  h += jsStr(T(STR_W_DEVNAME_ALSO));
  h += F("};"
         // Repainting from one object keeps the verdict, the switch and the
         // fallback addresses from ever disagreeing with each other.
         "let poll=0;"
         // Never while the field has focus. paint() runs from a poll every
         // two seconds during a DNS check, and it would rewrite the name out
         // from under someone in the middle of typing the next one.
         "function paint(d){"
         "if(document.activeElement!==$('hn'))$('hn').value=d.name;"
         "$('hn-s').textContent=d.dnsMsg;"
         "$('hn-s').className='msg'+(d.dnsBad?' bad':'');"
         "$('hn-a').textContent=d.also?M.also+': '+d.also:'';"
         "$('md').checked=d.mdns;"
         "if(d.dnsWait&&poll<10){poll++;setTimeout(load,2000);}else if(!d.dnsWait){poll=0;}}"
         "function load(){getJson('/api/hostname').then(d=>{if(d)paint(d);});}"
         // A rejected name keeps its message: handing the line back would
         // paint the verdict of the name that is still stored, and that reads
         // as if the bad one had been taken.
         "$('hn-b').addEventListener('click',()=>{"
         "post('/api/hostname',$('hn').value).then(r=>{poll=0;"
         "flash('hn-s',r.text||WS.err,!r.ok,4000,r.ok?load:null);});});"
         // The box already shows what the user asked for, so a failure has to
         // put it back. A checkbox claiming a state the scale is not in is
         // worse than no answer at all.
         "$('md').addEventListener('change',()=>{"
         "const want=$('md').checked;"
         "post('/api/mdns',want?'1':'0').then(r=>{"
         "if(!r.ok||!r.json){$('md').checked=!want;"
         "flash('md-s',WS.err,true,4000);return;}"
         "paint(r.json);flash('md-s',WS.ok,false,4000);});});"
         "function clamp(el){let v=parseInt(el.value)||5;"
         "if(v<5)v=5;if(v>100)v=100;el.value=v;return v;}"
         // Two values, one button: both go out together and the line reports
         // the pair, so a half success cannot read as a whole one.
         "function setLimits(){"
         "Promise.all([post('/api/listlimit',clamp($('ll'))),"
         "post('/api/loclimit',clamp($('lc')))])"
         ".then(rs=>{const ok=rs.every(r=>r.ok);"
         "flash('ll-s',ok?WS.ok:WS.err,!ok,4000);});}"
         "function setGain(){postFlash('/api/gain',$('gn').value,'gn-s',4000);}"
         // The zone applies the moment it is picked, so there is no Save
         // button to bind: the select is the control.
         "$('tz').addEventListener('change',()=>{"
         "postFlash('/api/timezone',$('tz').value,'tz-s',4000);});"
         // Same shape as the mDNS switch: the box already shows what was
         // asked for, so a failure has to put it back.
         "$('wk').addEventListener('change',()=>{"
         "const want=$('wk').checked;"
         "post('/api/wakeload',want?'1':'0').then(r=>{"
         "if(!r.ok)$('wk').checked=!want;"
         "flash('wk-s',r.ok?WS.ok:WS.err,!r.ok,4000);});});"
         "$('ll-b').addEventListener('click',setLimits);"
         "$('gn-b').addEventListener('click',setGain);"
         "load();"
         "</script>");
  return h;
}

static void routes(WebServer &srv) {
  srv.on("/api/hostname", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    srv.send(200, "application/json", nameStateJson());
  });

  srv.on("/api/hostname", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    String name = srv.arg("plain");
    name.trim();
    if (!deviceSetName(name.c_str())) {
      // Named rather than a bare "invalid": the rule is not obvious and the
      // field has just been typed.
      srv.send(400, "text/plain", T(STR_W_DEVNAME_BAD));
      return;
    }
    logSDf("Web: device name set to %s", deviceFqdn());
    // The responder restarts on the next sync pass, so the URL named here is
    // the one that will answer a second from now rather than the one that
    // does this instant. The message also carries the note about the router,
    // which is the one moment it is worth reading - it used to sit under the
    // field for good.
    char url[DEVICE_FQDN_MAX + 16];
    snprintf(url, sizeof(url), "http://%s/", deviceFqdn());
    char msg[DEVICE_FQDN_MAX + 160];
    snprintf(msg, sizeof(msg), T(STR_W_DEVNAME_NOW), url);
    srv.send(200, "text/plain", msg);
  });

  // Takes the state it should be in, not a toggle. /api/verbose on the log
  // page toggles because a button has no state of its own, but this is a
  // checkbox: a request that arrives twice would flip twice and leave the box
  // disagreeing with the scale. The answer carries the whole card back, so
  // the page never has to work out what it now looks like.
  srv.on("/api/mdns", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    String want = srv.arg("plain");
    want.trim();
    deviceSetMdnsEnabled(want == "1");
    // Ask the one owner of the responder to act on it now, so the addresses
    // in the reply already tell the truth.
    mdnsSyncState();
    deviceNameTick();
    logSDf("Web: mDNS -> %s", deviceMdnsEnabled() ? "on" : "off");
    srv.send(200, "application/json", nameStateJson());
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
    // loadPrefs() reads "list_limit" as a uchar. This wrote a different key
    // as an int32, so the value looked saved and was gone after the next
    // boot - and nothing else in the firmware writes these two.
    prefsPutUChar("list_limit", (uint8_t)v);
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
    prefsPutUChar("loc_limit", (uint8_t)v);
    logSDf("Web: location list limit -> %d", v);
    srv.send(200, "application/json", String("{\"limit\":") + v + "}");
  });

  // Applied at once: timeZoneSet() hands the string to the C library, so the
  // next line written to the log is already in the new zone. No restart.
  srv.on("/api/timezone", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "timezone")) return;
    if (!srv.hasArg("plain")) { srv.send(400, "text/plain", "no body"); return; }
    // An index into the table, so nothing that reaches setenv() comes from
    // the request. A malformed TZ string would silently mean UTC, which reads
    // as the setting having been lost.
    const long idx = strtol(srv.arg("plain").c_str(), nullptr, 10);
    if (idx < 0 || idx >= (long)TZ_COUNT) {
      srv.send(400, "text/plain", "unknown zone");
      return;
    }
    timeZoneSet(TZ_LIST[idx].tz);
    logSDf("Time zone set to %s (%s)", TZ_LIST[idx].name, TZ_LIST[idx].tz);
    srv.send(200, "text/plain", TZ_LIST[idx].name);
  });

  // State, not a toggle: the browser sends what it wants to be, so two tabs
  // open on the same page cannot talk past each other. Same choice /api/mdns
  // made for the same reason.
  srv.on("/api/wakeload", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    const bool on = (srv.arg("plain").toInt() != 0);
    g_wake_on_load = on;
    prefsPutBool("wake_load", on);
    logSDf("Web: wake on load -> %s", on ? "ON" : "OFF");
    srv.send(200, "application/json", on ? "{\"ok\":true,\"v\":1}"
                                         : "{\"ok\":true,\"v\":0}");
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
