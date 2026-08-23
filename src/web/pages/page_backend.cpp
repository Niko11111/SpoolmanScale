// Backend credentials. The path is deliberately neutral: it used to be
// "/filaman", which was already wrong once BamBuddy arrived - the device
// screen linked BamBuddy users to a FilaMan URL and the tab that would have
// taken them there was hidden from them.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>
#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/filaman_api.h"
#include "web/web_access.h"

// Spoolman has nothing to enter, so the page does not exist there at all.
static bool applies() { return backendIsFilaMan() || backendIsBamBuddy(); }

// The tab says which backend it belongs to. A BamBuddy user following a tab
// labelled "FilaMan" has every reason to think they are in the wrong place.
static const char* label() { return backendIsBamBuddy() ? "BamBuddy" : "FilaMan"; }

static String body() {
  String html;
  if (backendIsFilaMan()) html +=
      "<div class='card'>"
      "<h2>FilaMan</h2>"
      "<p style='font-size:12px;color:#4a6fa0;margin-bottom:14px'>"
      "The scale needs two credentials. The <b>device token</b> identifies it when "
      "reporting weights, the <b>API key</b> is used for everything else. "
      "<span onclick=\"h('p')\" style='cursor:pointer;color:#28d49a;border:1px solid #28d49a;"
      "border-radius:50%;padding:0 6px;font-size:11px'>?</span> "
      "Tip for a tighter setup.</p>"
      "<div id='h-p' style='display:none;font-size:12px;color:#8ab0d8;background:#06080f;"
      "border-left:2px solid #28d49a;border-radius:4px;padding:10px 12px;margin-bottom:14px'>"
      "An API key has no permissions of its own. It inherits them from the user who "
      "created it, so a key made from an admin account can do everything that account "
      "can. If you would rather keep that narrow:<br><br>"
      "1. Create a new FilaMan user without admin rights.<br>"
      "2. Create a role and give it at least these permissions:<br>"
      "&nbsp;&nbsp;<b>Read</b> spools:read, spool_events:read, locations:read, "
      "filaments:read, manufacturers:read<br>"
      "&nbsp;&nbsp;<b>Write</b> spools:update, spools:create, spools:archive, "
      "spools:move_location, filaments:update, manufacturers:update<br>"
      "3. Assign the role to that user.<br>"
      "4. Sign in <i>as that user</i> and create the API key there. A role has no "
      "effect on a key created by somebody else.<br><br>"
      "SpoolmanScale never deletes anything and never calls an admin endpoint. "
      "Weight reports go through the device token, not the key.<br><br>"
      "<i>The list is derived from the endpoints the firmware calls. It has not been "
      "verified against a restricted account yet, so if something stops working, "
      "widen the role and please report it.</i></div>"
      "<div style='margin-bottom:12px'>"
      "<label style='font-size:13px;color:#c8d8f0;display:block;margin-bottom:6px'>"
      "API key - create it in FilaMan under API keys "
      "<span onclick=\"h('k')\" style='cursor:pointer;color:#28d49a;border:1px solid #28d49a;"
      "border-radius:50%;padding:0 6px;font-size:11px;margin-left:4px'>?</span></label>"
      "<div id='h-k' style='display:none;font-size:12px;color:#8ab0d8;background:#06080f;"
      "border-left:2px solid #28d49a;border-radius:4px;padding:8px 10px;margin-bottom:8px'>"
      "Open FilaMan in another tab. At the bottom of the left sidebar there is a gear icon. "
      "Click it, choose <b>API keys</b>, and create a new key. Copy the value it shows you "
      "right away, FilaMan will not display it a second time.</div>"
      "<div style='display:flex;gap:10px;align-items:center'>"
      "<input id='fm-key' type='password' placeholder='uak.1....' value='"
      + String(filamanApiKey()[0] ? "________________" : "") + "'"
      " style='flex:1;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;"
      "border-radius:8px;padding:8px 10px;font-size:14px'>"
      "<button class='btn-toggle' onclick='setKey()'>Save</button>"
      "</div>"
      "<span id='fm-key-s' style='font-size:12px;color:#28d49a'></span>"
      "</div>"
      "<div>"
      "<label style='font-size:13px;color:#c8d8f0;display:block;margin-bottom:6px'>"
      "Device code - 6 characters from FilaMan admin. Current token: "
      + String(filamanDeviceToken()[0] ? "set" : "missing")
      + "<span onclick=\"h('d')\" style='cursor:pointer;color:#28d49a;border:1px solid #28d49a;"
      "border-radius:50%;padding:0 6px;font-size:11px;margin-left:4px'>?</span></label>"
      "<div id='h-d' style='display:none;font-size:12px;color:#8ab0d8;background:#06080f;"
      "border-left:2px solid #28d49a;border-radius:4px;padding:8px 10px;margin-bottom:8px'>"
      "In FilaMan go to the <b>Admin</b> area and open <b>Devices</b>. Add a new device there. "
      "FilaMan then shows a 6 character code. Enter it below and press Register device. "
      "Each code can only be used once, so if it is refused, have FilaMan issue a fresh one."
      "</div>"
      "<div style='display:flex;gap:10px;align-items:center'>"
      "<input id='fm-code' type='text' maxlength='6' placeholder='AA5354'"
      " style='width:110px;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;"
      "border-radius:8px;padding:8px 10px;font-size:16px;letter-spacing:2px'>"
      "<button class='btn-toggle' onclick='reg()'>Register device</button>"
      "</div>"
      "<span id='fm-reg-s' style='font-size:12px;color:#28d49a'></span>"
      "</div></div>"
      "<script>"
      // Both credentials sit in places of FilaMan that are easy to miss, so
      // each has a question mark that folds a short pointer open.
      "function h(i){var e=document.getElementById('h-'+i);"
      "e.style.display=(e.style.display==='none'?'block':'none');}"
      "function setKey(){var v=document.getElementById('fm-key').value;"
      "if(v.indexOf('_')===0){return;}"
      "fetch('/api/filaman/key',{method:'POST',body:v})"
      ".then(r=>r.text()).then(t=>{document.getElementById('fm-key-s').textContent=t;});}"
      "function reg(){var c=document.getElementById('fm-code').value;"
      "document.getElementById('fm-reg-s').textContent='Registering...';"
      "fetch('/api/filaman/register',{method:'POST',body:c})"
      ".then(r=>r.text()).then(t=>{document.getElementById('fm-reg-s').textContent=t;});}"
      "</script>";
    // BamBuddy credentials. One key rather than two, and it may legitimately
    // stay empty: an instance with authentication switched off answers
    // without it.
    //
    // This card was lost when the single page was split into sections - the
    // BamBuddy branch was left as a bare "</script>" with no form in it, so a
    // BamBuddy user had nowhere to enter the key and the device screen sent
    // them to exactly this page.
  if (backendIsBamBuddy()) html +=
      "<div class='card'>"
      "<h2>BamBuddy</h2>"
      "<p style='font-size:12px;color:#4a6fa0;margin-bottom:14px'>"
      "The scale needs one API key. Leave it empty if your BamBuddy runs with "
      "authentication switched off. "
      "<span onclick=\"bh()\" style='cursor:pointer;color:#28d49a;border:1px solid #28d49a;"
      "border-radius:50%;padding:0 6px;font-size:11px'>?</span></p>"
      "<div id='h-bb' style='display:none;font-size:12px;color:#8ab0d8;background:#06080f;"
      "border-left:2px solid #28d49a;border-radius:4px;padding:8px 10px;margin-bottom:12px'>"
      "In BamBuddy open <b>Settings</b>, then <b>API Keys</b>, and create a key. "
      "Tick <b>Read Status</b> and <b>Manage Inventory</b> - the first lets the scale "
      "read spools and detect whether your inventory is local or on Spoolman, the second "
      "lets it write weights back. The key is shown once, copy it right away.</div>"
      "<label style='font-size:13px;color:#c8d8f0;display:block;margin-bottom:6px'>"
      "API key. Currently: "
      + String(bambuddyApiKey()[0] ? "set" : "empty")
      + "</label>"
      "<div style='display:flex;gap:10px;align-items:center'>"
      "<input id='bb-key' type='password' placeholder='bb_...' value='"
      + String(bambuddyApiKey()[0] ? "________________" : "") + "'"
      " style='flex:1;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;"
      "border-radius:8px;padding:8px 10px;font-size:14px'>"
      "<button class='btn-toggle' onclick='setBb()'>Save</button>"
      "</div>"
      "<span id='bb-key-s' style='font-size:12px;color:#28d49a'></span>"
      "</div>"
      "<script>"
      "function bh(){var e=document.getElementById('h-bb');"
      "e.style.display=(e.style.display==='none'?'block':'none');}"
      "function setBb(){var v=document.getElementById('bb-key').value;"
      "if(v.indexOf('_')===0){return;}"
      "fetch('/api/bambuddy/key',{method:'POST',body:v})"
      ".then(r=>r.text()).then(t=>{document.getElementById('bb-key-s').textContent=t;});}"
      "</script>";
  return html;
}

static void routes(WebServer &srv) {
  // List limit: GET returns current value, POST sets new value
  // FilaMan: store the API key. The value is never echoed back to the page,
  // the input shows a placeholder when one is already stored.
  srv.on("/api/filaman/key", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "Backend setup")) return;
    String key = srv.arg("plain");
    key.trim();
    if (key.length() < 8) { srv.send(400, "text/plain", "Key too short"); return; }
    filamanSetApiKey(key.c_str());
    srv.send(200, "text/plain", "Saved");
  });

  // BamBuddy: store the API key. An empty value is accepted and clears it,
  // because an instance without authentication needs none - unlike FilaMan,
  // where a missing credential is always a mistake.
  srv.on("/api/bambuddy/key", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "Backend setup")) return;
    String key = srv.arg("plain");
    key.trim();
    if (key.length() > 0 && key.length() < 8) {
      srv.send(400, "text/plain", "Key too short");
      return;
    }
    bambuddySetApiKey(key.c_str());
    srv.send(200, "text/plain", key.length() ? "Saved" : "Cleared");
  });

  // FilaMan: exchange the 6 character device code for a device token.
  srv.on("/api/filaman/register", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "Backend setup")) return;
    String code = srv.arg("plain");
    code.trim();
    code.toUpperCase();   // codes are shown uppercase in the FilaMan admin
    if (code.length() < 4) { srv.send(400, "text/plain", "Code too short"); return; }
    if (strlen(backendBaseUrl()) <= 7) {
      srv.send(200, "text/plain", "Set the FilaMan address on the device first");
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
      String msg = String("Failed (HTTP ") + rc + ") calling "
                 + backendBaseUrl() + "/api/v1/devices/register";
      if (errmsg[0]) msg += String(" - ") + errmsg;
      if (!strchr(backendHost(), ':')) {
        msg += " - the address has no port, FilaMan usually runs on :8002";
      } else if (rc == 404) {
        msg += " - codes are single use, create a new device or rotate the token in FilaMan";
      } else if (rc == 403) {
        msg += " - this device already has a token, rotate it in FilaMan to get a fresh code";
      }
      srv.send(200, "text/plain", msg);
      return;
    }
    filamanSetDeviceToken(token);
    srv.send(200, "text/plain", "Device registered");
  });
}

extern const WebPage PAGE_BACKEND;
const WebPage PAGE_BACKEND = {
  "/backend", nullptr, label, GATE_CONFIG, applies,
  body, routes
};
