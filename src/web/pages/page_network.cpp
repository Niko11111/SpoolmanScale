// Network identity. The device name is the one setting that is easier to
// change here than on the scale: it is text, and the scale has a numeric
// keypad for addresses and a full keyboard only for the WiFi password.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/mdns_service.h"
#include "services/wifi_manager.h"
#include "web/web_access.h"

static String body() {
  String html;
  html +=
      "<div class='card'>"
      "<h2>Device name</h2>"
      "<p style='font-size:12px;color:#4a6fa0;margin-bottom:14px'>"
      "Lets you reach the scale by name instead of by an address the router "
      "is free to change. Letters, digits and hyphens, up to "
      + String(MDNS_HOSTNAME_MAX) + " characters.</p>"
      "<div style='display:flex;gap:10px;align-items:center'>"
      "<input id='hn-in' type='text' maxlength='" + String(MDNS_HOSTNAME_MAX) + "'"
      " value='" + String(mdnsHostname()) + "'"
      " style='flex:1;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;"
      "border-radius:8px;padding:8px 10px;font-size:14px'>"
      "<button class='btn-toggle' onclick='setHn()'>Save</button>"
      "</div>"
      "<span id='hn-s' style='font-size:12px;color:#28d49a'></span>"
      "<p class='hint' style='text-align:left;margin-top:12px'>"
      + String(mdnsRunning()
          ? "Reachable now at <b>http://" + String(mdnsHostname()) + ".local/</b>. "
          : "The responder is not running, so only the IP address works right now. ")
      + "A new name takes effect at once, without a restart. The name the "
      "router lists follows on the next time the scale connects. Windows, "
      "macOS and iOS resolve .local names on their own; some Android "
      "versions do not, which is why the address is still shown on the "
      "device.</p>"
      "</div>"
      "<script>"
      "function setHn(){var v=document.getElementById('hn-in').value;"
      "fetch('/api/hostname',{method:'POST',body:v})"
      ".then(r=>r.text().then(t=>({ok:r.ok,t:t})))"
      ".then(r=>{var s=document.getElementById('hn-s');"
      "s.style.color=r.ok?'#28d49a':'#ff8080';s.textContent=r.t;});}"
      "</script>";
  return html;
}

static void routes(WebServer &srv) {
  srv.on("/api/hostname", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "Network")) return;
    String j = String("{\"host\":\"") + mdnsHostname() + "\",\"mdns\":"
             + (mdnsRunning() ? "true" : "false") + "}";
    srv.send(200, "application/json", j);
  });

  srv.on("/api/hostname", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "Network")) return;
    String name = srv.arg("plain");
    name.trim();
    if (!mdnsSetHostname(name.c_str())) {
      // Named rather than a bare "invalid", because the rule is not obvious
      // and the field has just been retyped.
      srv.send(400, "text/plain",
               "Letters, digits and hyphens only, not starting or ending "
               "with a hyphen");
      return;
    }
    logSDf("Web: device name set to %s", mdnsHostname());
    srv.send(200, "text/plain", String("Saved. Now at http://")
                                + mdnsHostname() + ".local/");
  });
}

extern const WebPage PAGE_NETWORK;
const WebPage PAGE_NETWORK = {
  "/network", "Network", nullptr, GATE_CONFIG, nullptr,
  body, routes
};
