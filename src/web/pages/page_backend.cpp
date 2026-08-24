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
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/filaman_api.h"
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

  h += F("</div><script>const M={ok:");
  h += jsStr(T(STR_W_SAVED));
  h += F(",err:");   h += jsStr(T(STR_W_ERROR));
  h += F(",test:");  h += jsStr(T(STR_W_HOST_TESTING));
  h += F("};"
         "function flash(id,t,bad){const e=document.getElementById(id);"
         "e.textContent=t;e.className='msg'+(bad?' bad':'');}"
         "function post(u,v,id){"
         "fetch(u,{method:'POST',headers:{'Content-Type':'text/plain'},body:v})"
         ".then(r=>r.text().then(t=>({ok:r.ok,t}))).then(r=>flash(id,r.t||M.ok,!r.ok));}"
         "function setHost(){const v=document.getElementById('hs').value;"
         "flash('hs-s',M.test,false);post('/api/host',v,'hs-s');}"
         // A stored key is shown as underscores so its length gives nothing
         // away. Sending those back would overwrite the real one with them.
         "function guard(v){return v.indexOf('_')!==0;}"
         "function setBb(){const v=document.getElementById('bk').value;"
         "if(!guard(v))return;post('/api/bambuddy/key',v,'bk-s');}"
         "function setKey(){const v=document.getElementById('fk').value;"
         "if(!guard(v))return;post('/api/filaman/key',v,'fk-s');}"
         "function reg(){const v=document.getElementById('fc').value;"
         "flash('fc-s',M.test,false);post('/api/filaman/register',v,'fc-s');}"
         "</script>");
  return h;
}

static void routes(WebServer &srv) {
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
