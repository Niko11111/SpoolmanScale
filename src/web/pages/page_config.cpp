// List limits and the display gain. Two cards rather than two pages: both
// are small, and an eighth tab costs more than it returns.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>
#include "hardware/display.h"
#include "hardware/sd_logger.h"
#include "services/list_limits.h"
#include "services/prefs_store.h"
#include "web/web_access.h"

static String body() {
  String html;
  html +=
      "<div class='card'>"
      "<h2>List Limits</h2>"
      "<p style='font-size:12px;color:#4a6fa0;margin-bottom:14px'>Controls how many items are shown in picker lists. Increase carefully.</p>"
      "<div style='margin-bottom:12px'>"
      "<label style='font-size:13px;color:#c8d8f0;display:block;margin-bottom:6px'>Spool list (link/copy) - Default: 16</label>"
      "<div style='display:flex;gap:10px;align-items:center'>"
      "<input id='ll-in' type='number' min='5' max='100' value='"+String(spool_list_limit)+"'"
      " style='width:72px;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;"
      "border-radius:8px;padding:8px 10px;font-size:16px'>"
      "<button class='btn-toggle' onclick='setLL()'>Save</button>"
      "<span id='ll-s' style='font-size:12px;color:#28d49a;line-height:36px'></span>"
      "</div></div>"
      "<div>"
      "<label style='font-size:13px;color:#c8d8f0;display:block;margin-bottom:6px'>Location list - Default: 30 (too many may cause reboot)</label>"
      "<div style='display:flex;gap:10px;align-items:center'>"
      "<input id='locl-in' type='number' min='5' max='100' value='"+String(location_list_limit)+"'"
      " style='width:72px;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;"
      "border-radius:8px;padding:8px 10px;font-size:16px'>"
      "<button class='btn-toggle' onclick='setLocL()'>Save</button>"
      "<span id='locl-s' style='font-size:12px;color:#28d49a;line-height:36px'></span>"
      "</div></div></div>";
  html +=
      "<div class='card'>"
      "<h2>Display</h2>"
      "<p style='font-size:12px;color:#4a6fa0;margin-bottom:14px'>Gamma lift applied to every pixel. 100 is off; higher raises shadows and midtones without touching white, which brightens the whole UI at once. Independent of the backlight.</p>"
      "<div style='display:flex;gap:10px;align-items:center'>"
      "<input id='gain-in' type='range' min='100' max='300' step='5' value='"+String(displayGetUiGain())+"'"
      " oninput=\"document.getElementById('gain-v').textContent=this.value\" style='flex:1'>"
      "<span id='gain-v' style='font-size:14px;color:#e8f0ff;width:38px;text-align:right'>"+String(displayGetUiGain())+"</span>"
      "<button class='btn-toggle' onclick='setGain()'>Save</button>"
      "<span id='gain-s' style='font-size:12px;color:#28d49a;line-height:36px'></span>"
      "</div></div>";
  return html;
}

static void routes(WebServer &srv) {
  srv.on("/api/gain", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "Display")) return;
    if (!srv.hasArg("plain")) { srv.send(400, "application/json", "{\"error\":\"no body\"}"); return; }
    int val = srv.arg("plain").toInt();
    if (val < 100) val = 100;
    if (val > 300) val = 300;
    displaySetUiGain((uint16_t)val);
    prefsPutUInt("ui_gain", (uint32_t)val);
    char json[32]; snprintf(json, sizeof(json), "{\"gain\":%d}", val);
    logSDf("Webserver: ui_gain set to %d", val);
    srv.send(200, "application/json", json);
  });

  srv.on("/api/listlimit", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "Configuration")) return;
    char json[32];
    snprintf(json, sizeof(json), "{\"limit\":%d}", spool_list_limit);
    srv.send(200, "application/json", json);
  });

  srv.on("/api/listlimit", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "Configuration")) return;
    if (!srv.hasArg("plain")) { srv.send(400, "application/json", "{\"error\":\"no body\"}"); return; }
    int val = srv.arg("plain").toInt();
    if (val < 5) val = 5;
    if (val > 100) val = 100;
    spool_list_limit = val;
    prefsPutUChar("list_limit", (uint8_t)val);
    char json[32]; snprintf(json, sizeof(json), "{\"limit\":%d}", spool_list_limit);
    logSDf("Webserver: list_limit set to %d", spool_list_limit);
    srv.send(200, "application/json", json);
  });

  srv.on("/api/loclimit", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "Configuration")) return;
    char json[32];
    snprintf(json, sizeof(json), "{\"limit\":%d}", location_list_limit);
    srv.send(200, "application/json", json);
  });

  srv.on("/api/loclimit", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "Configuration")) return;
    if (!srv.hasArg("plain")) { srv.send(400, "application/json", "{\"error\":\"no body\"}"); return; }
    int val = srv.arg("plain").toInt();
    if (val < 5) val = 5;
    if (val > 100) val = 100;
    location_list_limit = val;
    prefsPutUChar("loc_limit", (uint8_t)val);
    char json[32]; snprintf(json, sizeof(json), "{\"limit\":%d}", location_list_limit);
    logSDf("Webserver: loc_limit set to %d", location_list_limit);
    srv.send(200, "application/json", json);
  });
}

extern const WebPage PAGE_CONFIG;
const WebPage PAGE_CONFIG = {
  "/config", "Settings", nullptr, GATE_CONFIG, nullptr,
  body, routes
};
