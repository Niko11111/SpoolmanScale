// Backend: where the inventory lives and, where one is needed, how to get in.
//
// The path is deliberately neutral. It used to be "/backend" named
// "/filaman", which was already wrong once BamBuddy arrived - the device
// screen linked BamBuddy users to a FilaMan URL and the tab that would have
// taken them there was hidden from them.
//
// The address field is the point of this page. On the device the address is
// typed on a twelve key numeric pad, so a host name cannot be entered there
// at all - which is exactly what someone running their services behind a
// reverse proxy needs, because a proxy tells its backends apart by the Host
// header and the proxy's own IP reaches none of them.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/filaman_api.h"
#include "services/settings_registry.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

// Spoolman has no credentials, but it does have an address, so the page
// exists in every mode now. It used to be skipped unless the backend was
// FilaMan.
static const char* label() { return T(STR_W_NAV_BACKEND); }

static String body() {
  const bool creds = backendIsFilaMan() || backendIsBamBuddy();

  String h;
  h.reserve(5900);
  h += F("<div class='grid'>");

  // ---- which backend ----------------------------------------------------
  // Above the address, because the address only means something once it is
  // known which server it points at - the same order the device setup asks in.
  //
  // Each backend keeps its own address and its own credentials, so switching
  // loses nothing and switching back finds everything where it was.
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_C_BACKEND);
  h += F("</h2><div class='btabs'>");
  for (uint8_t m = 0; m < 3; m++) {
    const bool on = (backendMode() == (BackendMode)m);
    h += F("<button class='btab");
    if (on) h += F(" on");
    h += F("' data-m='");
    h += String((int)m);
    h += F("'");
    if (on) h += F(" disabled");
    h += F(">");
    h += backendModeName((BackendMode)m);
    h += F("</button>");
  }
  h += F("</div><span class='msg' id='bm-s'></span>"
         "<p class='note'>");
  h += T(STR_W_BACKEND_NOTE);
  h += F("</p></div>");

  // ---- address ----------------------------------------------------------
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_C_BACKEND_ADDR);
  h += F("</h2><div class='field'><label>");
  h += T(STR_W_HOST_LABEL);
  h += F(" &middot; ");
  h += backendName();
  h += F("</label><div class='inrow'>"
         "<input id='hs' type='text' maxlength='63' spellcheck='false' value='");
  h += backendHost();
  h += F("' placeholder='spoolman.local:7912'>"
         "<button onclick='setHost()'>");
  h += T(STR_W_SAVE);
  h += F("</button></div><span class='msg' id='hs-s'></span>"
         "<span class='hint'>");
  h += T(STR_W_HOST_HINT);
  h += F(" ");
  h += T(STR_W_HOST_PORTHINT);
  h += F("</span></div><div class='rows' style='margin-top:16px'><div class='row'>"
         "<span class='k'>URL</span><span class='v mono'>");
  h += backendBaseUrl();
  h += F("</span></div><div class='row'><span class='k'>");
  h += T(STR_W_R_REACHABLE);
  h += F("</span><span class='v'><span class='pill ");
  h += sm_reachable ? F("ok'>") : F("bd'>");
  h += T(sm_reachable ? STR_W_S_YES : STR_W_S_NO);
  h += F("</span></span></div></div></div>");

  // ---- credentials, only where there are any ----------------------------
  if (!creds) {
    h += F("<div class='card wide'><h2>");
    h += T(STR_W_C_CREDS);
    h += F("</h2><p class='hint'>");
    h += T(STR_W_NO_CREDS);
    h += F("</p></div>");
  } else if (backendIsBamBuddy()) {
    // One key rather than two, and it may legitimately stay empty: an
    // instance with authentication switched off answers without it.
    h += F("<div class='card wide'><h2>");
    h += T(STR_W_C_CREDS);
    h += F("</h2><div class='field'><label>");
    h += T(STR_W_APIKEY);
    h += F(" &middot; ");
    h += T(bambuddyApiKey()[0] ? STR_W_SET : STR_W_UNSET);
    h += F("</label><div class='inrow'>"
           "<input id='bk' type='password' placeholder='bb_...' value='");
    h += bambuddyApiKey()[0] ? F("________________") : F("");
    h += F("'><button onclick='setBb()'>");
    h += T(STR_W_SAVE);
    h += F("</button></div><span class='msg' id='bk-s'></span></div>"
           "<p class='note'>");
    h += T(STR_W_BB_SETUP);
    h += F("</p></div>");
  } else {
    h += F("<div class='card wide'><h2>");
    h += T(STR_W_C_CREDS);
    h += F("</h2><div class='field'><label>");
    h += T(STR_W_APIKEY);
    h += F(" &middot; ");
    h += T(filamanApiKey()[0] ? STR_W_SET : STR_W_UNSET);
    h += F("</label><div class='inrow'>"
           "<input id='fk' type='password' placeholder='fm_...' value='");
    h += filamanApiKey()[0] ? F("________________") : F("");
    h += F("'><button onclick='setKey()'>");
    h += T(STR_W_SAVE);
    h += F("</button></div><span class='msg' id='fk-s'></span></div>"
           "<div class='field'><label>");
    h += T(STR_W_DEVICE_CODE);
    h += F(" &middot; ");
    h += T(filamanDeviceToken()[0] ? STR_W_SET : STR_W_UNSET);
    h += F("</label><div class='inrow'>"
           "<input id='fc' type='text' maxlength='12' spellcheck='false' placeholder='ABC123'>"
           "<button onclick='reg()'>");
    h += T(STR_W_REGISTER);
    h += F("</button></div><span class='msg' id='fc-s'></span></div>"
           "<p class='note'>");
    h += T(STR_W_FM_SETUP);
    h += F("</p></div>");
  }

  // ---- more options, filled from /api/settings --------------------------
  // Server rendered as an empty card with one line of prose, then filled by
  // the script. The rows themselves are not built here on purpose: there is
  // one renderer for every kind of option, so an option added to the registry
  // shows up in the browser without a line being written here.
  h += F("<div class='card wide'><h2>");
  h += T(STR_BTN_MORE_OPTIONS);
  h += F("</h2><div id='os'><p class='hint'>");
  h += T(STR_W_LOADING);
  h += F("</p></div></div>");

  // $, flash and post come from /app.js. Only the one string this page has
  // beyond the shared pair stays here.
  h += F("</div><script>");
  h += webShellJsStrings();
  h += F("const M={test:");
  h += jsStr(T(STR_W_HOST_TESTING));
  h += F(",dev:");  h += jsStr(T(STR_W_ON_DEVICE));
  h += F(",none:"); h += jsStr(T(STR_W_NO_OPTIONS));
  h += F(",swap:"); h += jsStr(T(STR_W_BACKEND_ASK));
  h += F("};"
         // No ms: these answers stand. /api/host replies with the result of a
         // real health check and /api/filaman/register with the HTTP status of
         // the registration - neither is worth clearing after four seconds.
         "function setHost(){flash('hs-s',M.test,false);"
         "postFlash('/api/host',$('hs').value,'hs-s');}"
         // A stored key is shown as underscores so its length gives nothing
         // away. Sending those back would overwrite the real one with them.
         "function guard(v){return v.indexOf('_')!==0;}"
         "function setBb(){const v=$('bk').value;"
         "if(!guard(v))return;postFlash('/api/bambuddy/key',v,'bk-s');}"
         "function setKey(){const v=$('fk').value;"
         "if(!guard(v))return;postFlash('/api/filaman/key',v,'fk-s');}"
         "function reg(){flash('fc-s',M.test,false);"
         "postFlash('/api/filaman/register',$('fc').value,'fc-s');}"

         // ---- the options, one renderer for every kind --------------------
         // Nothing here knows any individual setting. Adding one to the
         // registry puts it on this page with no change to this file, which is
         // the whole reason the table exists.
         //
         // Built with createElement rather than innerHTML: the names and the
         // help texts are translated prose that goes through no escaping on
         // the way here, and a quotation mark in one of them would end the
         // attribute it landed in.
         "function orow(d){"
         "const r=document.createElement('div');r.className='orow';"
         "const l=document.createElement('div');l.className='ol';"
         "const n=document.createElement('span');n.className='on';"
         "n.textContent=d.name;l.appendChild(n);"
         "if(d.sub){const sb=document.createElement('span');sb.className='os';"
         "sb.textContent=d.sub;l.appendChild(sb);}"
         "r.appendChild(l);"
         "const v=document.createElement('div');v.className='ov';"

         // A switch, the same shape the rest of the interface uses.
         "if(d.kind==='bool'){"
         "const w=document.createElement('label');w.className='switch';"
         "const c=document.createElement('input');c.type='checkbox';c.checked=!!d.v;"
         "c.addEventListener('change',()=>{"
         "const want=c.checked;"
         "post('/api/settings',d.id+'='+(want?1:0)).then(r2=>{"
         // The box already shows what the user asked for, so a failure has to
         // put it back. A switch claiming a state the scale is not in is worse
         // than no answer at all.
         "if(!r2.ok){c.checked=!want;flash('os-s',WS.err,true,4000);return;}"
         "flash('os-s',WS.ok,false,4000);load();});});"
         "w.appendChild(c);w.appendChild(document.createElement('i'));"
         "v.appendChild(w);}"

         // A choice. An option the scale cannot reach right now is offered but
         // inert, the way the device screen leaves it visible and explains why.
         "else if(d.kind==='enum'){"
         "const sel=document.createElement('select');"
         "(d.opts||[]).forEach((o,i)=>{"
         "const op=document.createElement('option');"
         "op.value=i;op.textContent=o;"
         "if(d.na&&d.na.indexOf(i)>=0)op.disabled=true;"
         "if(i===d.v)op.selected=true;sel.appendChild(op);});"
         "sel.addEventListener('change',()=>{"
         "post('/api/settings',d.id+'='+sel.value).then(r2=>{"
         "flash('os-s',r2.ok?WS.ok:WS.err,!r2.ok,4000);load();});});"
         "v.appendChild(sel);}"

         // Everything else lives on the device: a create assistant, a numeric
         // window, a screen that reads the server as it opens. Saying so beats
         // showing a control that cannot work here.
         "else{const t=document.createElement('span');t.className='od';"
         "t.textContent=M.dev;v.appendChild(t);}"

         "r.appendChild(v);"
         "const wrap=document.createElement('div');wrap.appendChild(r);"
         "if(d.info){"
         "const q=document.createElement('button');"
         "q.className='quiet oq';q.textContent='?';q.title=M.dev;"
         "const p=document.createElement('p');p.className='oi';p.textContent=d.info;"
         "q.addEventListener('click',()=>p.classList.toggle('open'));"
         "v.insertBefore(q,v.firstChild);wrap.appendChild(p);}"
         "return wrap;}"

         // Switching moves the scale to a different inventory, so it asks
         // first - the action stays possible, the intent has to be deliberate.
         // The reload is what redraws address, credentials and options for the
         // backend now active; the device needs a moment to settle first.
         "document.querySelectorAll('.btab').forEach(b=>{"
         "b.addEventListener('click',()=>{"
         "const n=b.textContent;"
         "if(!confirm(M.swap.replace('%s',n)))return;"
         "flash('bm-s',M.test,false);"
         "post('/api/backend/mode',b.dataset.m).then(r=>{"
         "if(!r.ok){flash('bm-s',WS.err,true,4000);return;}"
         "setTimeout(()=>location.reload(),1200);});});});"

         "function load(){getJson('/api/settings').then(d=>{"
         "const c=$('os');if(!c)return;c.textContent='';"
         "if(!d){const e=document.createElement('p');e.className='hint';"
         "e.textContent=WS.err;c.appendChild(e);return;}"
         "if(!d.length){const e=document.createElement('p');e.className='hint';"
         "e.textContent=M.none;c.appendChild(e);return;}"
         "d.forEach(x=>c.appendChild(orow(x)));"
         "const m=document.createElement('span');m.className='msg';m.id='os-s';"
         "c.appendChild(m);});}"
         "load();"
         "</script>");
  return h;
}

// The registry as JSON, filtered to what belongs on screen right now: this
// backend, and applies(). Built by hand rather than with ArduinoJson - it is a
// flat list of short fields, and a document big enough to hold every info text
// would come off the same internal heap the rest of the firmware needs.
static String settingsJson() {
  String j;
  j.reserve(2400);
  j += '[';
  bool first = true;
  for (size_t i = 0; i < SETTINGS_COUNT; i++) {
    const SettingDesc &s = SETTINGS[i];
    if (!settingVisible(s)) continue;
    if (!first) j += ',';
    first = false;

    // A row with a screen behind it that is not a plain choice is the device's
    // business: the screens carry create assistants and numeric pads.
    const bool device_only = (s.kind == SET_SUBMENU);

    char sub[64];
    settingSubtitle(s, sub, sizeof(sub));

    j += F("{\"id\":\"");   j += s.id;
    j += F("\",\"kind\":\"");
    j += device_only ? F("submenu") : (s.kind == SET_BOOL ? F("bool") : F("enum"));
    j += F("\",\"v\":");    j += String(settingGet(s));
    j += F(",\"name\":\"");  j += jsonEsc(T((StringID)s.str_name));
    j += F("\",\"sub\":\"");  j += jsonEsc(sub);
    j += F("\"");
    if (s.str_info) {
      j += F(",\"info\":\""); j += jsonEsc(T((StringID)s.str_info)); j += F("\"");
    }
    if (!device_only && s.opt_str && s.opt_count) {
      j += F(",\"opts\":[");
      for (uint8_t v = 0; v < s.opt_count; v++) {
        if (v) j += ',';
        j += F("\""); j += jsonEsc(T((StringID)s.opt_str[v])); j += F("\"");
      }
      j += ']';
      // Which of them cannot be picked right now, so the browser can offer the
      // choice and still refuse it - the same thing the device screen does by
      // leaving the row visible and inert.
      if (s.opt_ok) {
        j += F(",\"na\":[");
        bool f2 = true;
        for (uint8_t v = 0; v < s.opt_count; v++) {
          if (s.opt_ok(v)) continue;
          if (!f2) j += ',';
          f2 = false;
          j += String(v);
        }
        j += ']';
      }
    }
    j += '}';
  }
  j += ']';
  return j;
}

static void routes(WebServer &srv) {
  // Switching the backend. Only the intent is recorded: this runs in the loop
  // task, already deep in the WebServer stack, and backendApplyMode() rebuilds
  // screens and makes requests of its own. appLoop() carries it out.
  srv.on("/api/backend/mode", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_BACKEND))) return;
    const long m = srv.arg("plain").toInt();
    if (m < 0 || m > 2) { srv.send(400, "text/plain", T(STR_W_ERROR)); return; }
    if ((BackendMode)m == backendMode()) {
      srv.send(200, "text/plain", backendName());
      return;
    }
    pending_backend_mode = (uint8_t)m;
    backend_mode_change_pending = true;
    logSDf("Web: backend -> %s", backendModeName((BackendMode)m));
    srv.send(200, "text/plain", backendModeName((BackendMode)m));
  });

  srv.on("/api/settings", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_BACKEND))) return;
    srv.send(200, "application/json", settingsJson());
  });

  // "<id>=<value>", the same plain text body every other setting route on this
  // page takes. settingSet() is the only thing that writes an option, so this
  // cannot forget what a device callback does - it runs the same code.
  srv.on("/api/settings", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_BACKEND))) return;
    String body = srv.arg("plain");
    const int eq = body.indexOf('=');
    if (eq <= 0) { srv.send(400, "text/plain", T(STR_W_ERROR)); return; }

    String id = body.substring(0, eq);
    id.trim();
    const SettingDesc *s = settingById(id.c_str());
    // Not visible means not settable: a value the scale is not offering right
    // now must not be reachable by guessing its id.
    if (!s || !settingVisible(*s) || s->kind == SET_SUBMENU) {
      srv.send(404, "text/plain", T(STR_W_ERROR));
      return;
    }
    const long v = body.substring(eq + 1).toInt();
    if (v < 0 || v > 255) { srv.send(400, "text/plain", T(STR_W_ERROR)); return; }
    if (s->opt_ok && !s->opt_ok((uint8_t)v)) {
      srv.send(400, "text/plain", T(STR_W_ERROR));
      return;
    }

    settingSet(*s, (uint8_t)v);
    logSDf("Web: %s -> %ld", s->id, v);
    srv.send(200, "text/plain", T(STR_W_SAVED));
  });

  // Address. Sanitised in backendSetHost(), but https has to be refused here:
  // only the caller can say so, and letting it through would send the request
  // as plain http to port 80 and fail in a way that looks like the server is
  // down.
  srv.on("/api/host", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_BACKEND))) return;
    String host = srv.arg("plain");
    host.trim();
    if (host.startsWith("https://") || host.startsWith("HTTPS://")) {
      srv.send(400, "text/plain", T(STR_W_HOST_HTTPS));
      return;
    }
    char clean[64];
    if (backendCleanHost(host.c_str(), clean, sizeof(clean)) == 0) {
      srv.send(400, "text/plain", T(STR_W_HOST_EMPTY));
      return;
    }
    backendSetHost(clean);
    logSDf("Web: %s host -> %s", backendName(), clean);

    // Answered with the result of an actual request rather than a bare
    // "saved": a typo here is only visible when something tries to use it.
    const int code = backendGetHealthCode(backendBaseUrl(), 4000);
    sm_reachable = (code == 200);
    String msg = String(sm_reachable ? T(STR_W_HOST_OK) : T(STR_W_HOST_FAIL))
               + " - " + backendBaseUrl();
    if (!sm_reachable) msg += " (HTTP " + String(code) + ")";
    srv.send(200, "text/plain", msg);
  });

  srv.on("/api/filaman/key", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_BACKEND))) return;
    String key = srv.arg("plain");
    key.trim();
    if (key.length() < 8) { srv.send(400, "text/plain", T(STR_W_ERROR)); return; }
    filamanSetApiKey(key.c_str());
    srv.send(200, "text/plain", T(STR_W_SAVED));
  });

  // An empty value is accepted and clears it, because an instance without
  // authentication needs none - unlike FilaMan, where a missing credential
  // is always a mistake.
  srv.on("/api/bambuddy/key", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_BACKEND))) return;
    String key = srv.arg("plain");
    key.trim();
    if (key.length() > 0 && key.length() < 8) {
      srv.send(400, "text/plain", T(STR_W_ERROR));
      return;
    }
    bambuddySetApiKey(key.c_str());
    srv.send(200, "text/plain", T(STR_W_SAVED));
  });

  srv.on("/api/filaman/register", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_BACKEND))) return;
    String code = srv.arg("plain");
    code.trim();
    code.toUpperCase();   // codes are shown uppercase in the FilaMan admin
    if (code.length() < 4) { srv.send(400, "text/plain", T(STR_W_ERROR)); return; }
    if (strlen(backendBaseUrl()) <= 7) {
      srv.send(400, "text/plain", T(STR_W_HOST_EMPTY));
      return;
    }

    char token[80] = "";
    char errmsg[96] = "";
    int rc = filamanRegisterDevice(backendBaseUrl(), code.c_str(),
                                   token, sizeof(token), errmsg, sizeof(errmsg));
    if (rc != 200 || !token[0]) {
      // Always name the URL that was actually contacted. A missing port
      // silently sends the request to whatever runs on port 80, and the
      // answer then looks like a FilaMan problem when it is not.
      String msg = String("HTTP ") + rc + " - " + backendBaseUrl()
                 + "/api/v1/devices/register";
      if (errmsg[0]) msg += String(" - ") + errmsg;
      srv.send(200, "text/plain", msg);
      return;
    }
    filamanSetDeviceToken(token);
    srv.send(200, "text/plain", T(STR_W_SAVED));
  });
}

extern const WebPage PAGE_BACKEND;
const WebPage PAGE_BACKEND = {
  "/backend", label, GATE_CONFIG, nullptr,
  body, routes
};
