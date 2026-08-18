#include "web_home.h"
#include <mbedtls/base64.h>

#include <Arduino.h>

#include "app/app_state.h"
#include "app_config.h"
#include "backend.h"
#include "hardware/sd_logger.h"
#include "web_access.h"
#include "web_shell.h"
#include "wifi_manager.h"

static String jsonEsc(const char *s) {
  String o;
  for (const char *p = s ? s : ""; *p; p++) {
    if (*p == '"' || *p == '\\') { o += '\\'; o += *p; }
    else if ((uint8_t)*p < 0x20)  { o += ' '; }
    else                          { o += *p; }
  }
  return o;
}

static String uptimeStr() {
  uint32_t s = millis() / 1000UL;
  uint32_t d = s / 86400UL; s %= 86400UL;
  uint32_t h = s / 3600UL;  s %= 3600UL;
  uint32_t m = s / 60UL;
  char b[32];
  if (d)      snprintf(b, sizeof(b), "%lud %luh %lum", (unsigned long)d, (unsigned long)h, (unsigned long)m);
  else if (h) snprintf(b, sizeof(b), "%luh %lum", (unsigned long)h, (unsigned long)m);
  else        snprintf(b, sizeof(b), "%lum", (unsigned long)m);
  return String(b);
}

static const char* rssiWord(int r) {
  if (r >= -50) return "excellent";
  if (r >= -65) return "good";
  if (r >= -75) return "fair";
  return "weak";
}

static String statusJson() {
  String j = "{";
  j += "\"version\":\"" + jsonEsc(FW_VERSION) + "\"";
  j += ",\"uptime\":\"" + uptimeStr() + "\"";
  j += ",\"wifi\":" + String(wifi_ok ? "true" : "false");
  j += ",\"ssid\":\"" + jsonEsc(cfg_wifi_ssid) + "\"";
  if (wifi_ok) {
    const int r = wifiManagerRSSI();
    j += ",\"rssi\":" + String(r);
    j += ",\"rssiWord\":\"" + String(rssiWord(r)) + "\"";
    j += ",\"ip\":\"" + wifiManagerLocalIP().toString() + "\"";
    j += ",\"gw\":\"" + wifiManagerGatewayIP().toString() + "\"";
    j += ",\"dns\":\"" + wifiManagerDNSIP().toString() + "\"";
  }
  j += ",\"backend\":\"" + jsonEsc(backendName()) + "\"";
  j += ",\"backendUrl\":\"" + jsonEsc(backendBaseUrl()) + "\"";
  j += ",\"backendOk\":" + String(sm_reachable ? "true" : "false");
  j += ",\"scale\":" + String(scl_ok ? "true" : "false");
  j += ",\"nfc\":" + String(nfc_ok ? "true" : "false");
  j += ",\"sd\":" + String(sd_available ? "true" : "false");
  j += ",\"scans\":" + String(scan_count);
  j += ",\"maint\":" + String(webMaintenanceEnabled() ? "true" : "false");
  j += ",\"themeOn\":" + String(webThemeEnabled() ? "true" : "false");
  j += ",\"filaman\":" + String(backendIsFilaMan() ? "true" : "false");
  j += ",\"fmKey\":" + String(filamanApiKey()[0] ? "true" : "false");
  j += ",\"fmToken\":" + String(filamanDeviceToken()[0] ? "true" : "false");
  j += "}";
  return j;
}

// Uses the shared shell, so the logo, palette, community links and disclaimer
// are the same ones the rest of the pages carry rather than a lookalike.
static String homePage() {
  String h;
  h.reserve(6000);
  h += webShellHead("Status");
  h += F("<style>"
         ".row{display:flex;justify-content:space-between;align-items:center;gap:12px;"
         "padding:7px 0;border-bottom:1px solid #0f1e30;font-size:14px}"
         ".row:last-child{border-bottom:none}"
         ".k{color:#4a6fa0}"
         ".v{color:#c8d8f0;font-family:ui-monospace,Consolas,monospace;text-align:right;"
         "word-break:break-all}"
         ".ok{color:#40c080}.bad{color:#ff8080}.warn{color:#f0b838}"
         ".tbtn{padding:8px 14px;background:#0a1828;color:#28d49a;border:1px solid #1a3060;"
         "border-radius:8px;font-size:13px;cursor:pointer;font-family:inherit}"
         ".tbtn:hover{background:#1a3060}"
         "</style>");
  h += webShellNav("/");
  h += webShellLinks();

  h += F("<div class='card'><h2>Status</h2><div id='st'></div></div>");
  // Not a second navigation -- the tabs above already do that. This says which
  // sections are actually being served, which the tabs cannot show.
  h += F("<div class='card'><h2>Web access</h2><div id='acc'></div>"
         "<p class='hint' id='hint' style='text-align:left;margin-top:12px'></p></div>");

  h += F("<div class='card'><h2>Device</h2>"
         "<button class='tbtn' onclick='doRestart()'>Restart device</button>"
         "<p class='hint' style='text-align:left'>Settings are kept in NVS, so a restart "
         "loses nothing. The main screen adopts a new palette on the way back up.</p></div>");

  h += F("<script>"
         "function row(k,v){return \"<div class='row'><span class='k'>\"+k+"
         "\"</span><span class='v'>\"+v+\"</span></div>\"}"
         "function yn(b){return b?\"<span class='ok'>yes</span>\":\"<span class='bad'>no</span>\"}"
         "function onoff(b){return b?\"<span class='ok'>on</span>\":\"<span class='warn'>off</span>\"}"
         "async function tick(){"
         "let d;try{d=await(await fetch('/status.json')).json()}catch(e){return}"
         "let s='';"
         "s+=row('WiFi',d.wifi?(d.ssid+\" <span class='k'>\"+d.rssi+\" dBm, \"+d.rssiWord+\"</span>\")"
         ":\"<span class='bad'>not connected</span>\");"
         "if(d.wifi){s+=row('IP',d.ip);s+=row('Gateway',d.gw);s+=row('DNS',d.dns)}"
         "s+=row(d.backend,d.backendUrl);"
         "s+=row(d.backend+' reachable',yn(d.backendOk));"
         "if(d.filaman){s+=row('FilaMan API key',yn(d.fmKey));"
         "s+=row('FilaMan device token',yn(d.fmToken))}"
         "s+=row('Scale',yn(d.scale));"
         "s+=row('NFC reader',yn(d.nfc));"
         "s+=row('SD card',yn(d.sd));"
         "s+=row('Tags scanned',d.scans);"
         "s+=row('Uptime',d.uptime);"
         "document.getElementById('st').innerHTML=s;"
         "let a='';"
         "a+=row('Setup, firmware and logs',onoff(d.maint));"
         "a+=row('Theme editor',onoff(d.themeOn));"
         "document.getElementById('acc').innerHTML=a;"
         "document.getElementById('hint').textContent=(d.maint&&d.themeOn)?"
         "'Both sections are being served.':"
         "'A section that is off is not served at all. Turn it on under "
         "Settings > System > Web interface on the scale.';}"
         "tick();setInterval(tick,5000);"
         "</script>");
  h += webShellRestartUi();
  h += webShellFoot();
  return h;
}

void registerHomeRoutes(WebServer &srv) {
  // Decoded on demand rather than kept in RAM: a browser asks for this once and
  // then caches it, so holding 5 kB permanently to save a rare decode is a bad
  // trade on a device with 320 kB.
  srv.on("/favicon.jpg", HTTP_GET, [&srv]() {
    const char *b64 = webShellLogoBase64();
    const size_t b64len = strlen(b64);
    size_t need = 0;
    mbedtls_base64_decode(nullptr, 0, &need, (const unsigned char *)b64, b64len);
    uint8_t *buf = (uint8_t *)malloc(need);
    if (!buf) { srv.send(500, "text/plain", "out of memory"); return; }
    size_t out = 0;
    if (mbedtls_base64_decode(buf, need, &out, (const unsigned char *)b64, b64len) != 0) {
      free(buf);
      srv.send(500, "text/plain", "logo decode failed");
      return;
    }
    srv.sendHeader("Cache-Control", "public, max-age=604800");
    srv.setContentLength(out);
    srv.send(200, "image/jpeg", "");
    srv.sendContent((const char *)buf, out);
    free(buf);
  });

  srv.on("/", HTTP_GET, [&srv]() {
    srv.send(200, "text/html", homePage());
  });
  // Restarting is not destructive -- settings live in NVS -- but it is still a
  // remote action, so it needs one of the gates open rather than being exposed
  // whenever the landing page is reachable.
  srv.on("/api/restart", HTTP_POST, [&srv]() {
    if (!webMaintenanceEnabled() && !webThemeEnabled()) {
      webSendDisabled(srv, "Restart", "Settings > System > Web interface");
      return;
    }
    logSD("Reboot: requested from web UI");
    srv.send(200, "application/json", "{\"ok\":true}");
    delay(400);            // let the response actually leave before the reset
    ESP.restart();
  });

  srv.on("/status.json", HTTP_GET, [&srv]() {
    srv.send(200, "application/json", statusJson());
  });
}
