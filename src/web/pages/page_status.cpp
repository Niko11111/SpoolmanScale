// The landing page. It used to be the firmware upload, which meant browsing
// the device address dropped the visitor straight into a file picker with no
// way to reach anything else.
#include "web/web_pages.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "app_config.h"
#include "hardware/i2c_scan.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/device_name.h"
#include "services/mdns_service.h"
#include "services/wifi_manager.h"
#include "ui/weight_format.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

static const char* label() { return T(STR_W_NAV_STATUS); }


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
    j += ",\"name\":\"" + jsonEsc(deviceFqdn()) + "\"";
    j += ",\"gw\":\"" + wifiManagerGatewayIP().toString() + "\"";
    j += ",\"dns\":\"" + wifiManagerDNSIP().toString() + "\"";
  }
  j += ",\"backend\":\"" + jsonEsc(backendName()) + "\"";
  j += ",\"backendUrl\":\"" + jsonEsc(backendBaseUrl()) + "\"";
  j += ",\"backendOk\":" + String(sm_reachable ? "true" : "false");
  j += ",\"scale\":" + String(scl_ok ? "true" : "false");
  j += ",\"scaleReady\":" + String(scale_ready ? "true" : "false");
  {
    // Read straight out of the loop task, which is also the task that
    // serves this request - handleOtaServerClient() runs from appLoop(),
    // so the value cannot be torn.
    char w[24];
    fmtG(w, sizeof(w), scale_weight_g);
    j += ",\"weight\":\"" + jsonEsc(w) + "\"";
  }
  j += ",\"nfc\":" + String(nfc_ok ? "true" : "false");
  j += ",\"i2c\":\"" + jsonEsc(i2cScanLast()) + "\"";
  j += ",\"sd\":" + String(sd_available ? "true" : "false");
  j += ",\"scans\":" + String(scan_count);
  j += ",\"config\":" + String(webConfigEnabled() ? "true" : "false");
  j += ",\"maint\":" + String(webMaintenanceEnabled() ? "true" : "false");
  j += ",\"creds\":" + String((backendIsFilaMan()||backendIsBamBuddy()) ? "true" : "false");
  j += ",\"filaman\":" + String(backendIsFilaMan() ? "true" : "false");
  j += ",\"fmKey\":" + String(filamanApiKey()[0] ? "true" : "false");
  j += ",\"fmToken\":" + String(filamanDeviceToken()[0] ? "true" : "false");
  j += "}";
  return j;
}

// A pill rather than the word on its own: state reads as a shape before it
// reads as text, which is what a status page is for.
static String pill(bool good, int good_id, int bad_id, bool warn_when_bad = false) {
  String s = F("<span class='pill ");
  s += good ? F("ok'>") : (warn_when_bad ? F("wr'>") : F("bd'>"));
  s += T(good ? good_id : bad_id);
  s += F("</span>");
  return s;
}

static String row(const String &k, const String &v, bool mono = false) {
  String s = F("<div class='row'><span class='k'>");
  s += k;
  s += mono ? F("</span><span class='v mono'>") : F("</span><span class='v'>");
  s += v;
  s += F("</span></div>");
  return s;
}

static String uptimeText() {
  uint32_t s = millis() / 1000UL;
  uint32_t d = s / 86400UL; s %= 86400UL;
  uint32_t h = s / 3600UL;  s %= 3600UL;
  uint32_t m = s / 60UL;
  char b[40];
  if (d)      snprintf(b, sizeof(b), "%lu d %lu h", (unsigned long)d, (unsigned long)h);
  else if (h) snprintf(b, sizeof(b), "%lu h %lu min", (unsigned long)h, (unsigned long)m);
  else        snprintf(b, sizeof(b), "%lu min", (unsigned long)m);
  return String(b);
}

// Four bars instead of a number nobody converts in their head. The number is
// still there, quietly, for whoever wants it.
static String signalBars() {
  const int r = wifiManagerRSSI();
  const int bars = (r >= -50) ? 4 : (r >= -65) ? 3 : (r >= -75) ? 2 : 1;
  String s = F("<span class='sig'>");
  for (int i = 1; i <= 4; i++) {
    s += F("<i style='background:");
    s += (i <= bars) ? (bars >= 3 ? F("var(--accent)") : F("var(--warn)")) : F("var(--ink-4)");
    s += F("'></i>");
  }
  s += F("</span><em>");
  s += String(r);
  s += F(" dBm</em>");
  return s;
}

static String body() {
  String h;
  h.reserve(6600);
  h += F("<div class='grid'>");

  // ---- network ----------------------------------------------------------
  h += F("<div class='card'><h2>");
  h += T(STR_W_C_NETWORK);
  h += F("</h2><div class='rows'>");
  if (wifi_ok) {
    h += row(T(STR_W_R_WIFI), String(cfg_wifi_ssid) + signalBars());
    h += row(T(STR_W_R_ADDRESS), wifiManagerLocalIP().toString(), true);
    // Both names when both apply: the DNS name is the one the network
    // serves, the mDNS name the one that works without it.
    if (deviceDomain()[0] || mdnsRunning()) h += row(T(STR_W_R_NAME), deviceFqdn(), true);
    if (deviceDomain()[0] && mdnsRunning()) {
      char m[DEVICE_FQDN_MAX + 1];
      deviceMdnsName(m, sizeof(m));
      h += row(T(STR_W_R_MDNS), m, true);
    }
    h += row(T(STR_W_R_GATEWAY), wifiManagerGatewayIP().toString(), true);
  } else {
    h += row(T(STR_W_R_WIFI), String(F("<span class='pill bd'>")) + T(STR_W_S_NOWIFI) + "</span>");
  }
  h += F("</div></div>");

  // ---- hardware ---------------------------------------------------------
  h += F("<div class='card'><h2>");
  h += T(STR_W_C_HARDWARE);
  h += F("</h2><div class='rows'>");
  h += row(T(STR_W_R_SCALE), pill(scl_ok, STR_W_S_READY, STR_W_S_MISSING));
  {
    // Server rendered once so the page is right before any script runs,
    // then kept current by the poll below.
    char w[24];
    if (scale_ready) fmtG(w, sizeof(w), scale_weight_g);
    else             strncpy(w, "---", sizeof(w));
    h += F("<div class='row'><span class='k'>");
    h += T(STR_W_R_WEIGHT);
    h += F("</span><span class='v' id='wt'>");
    h += w;
    h += F("</span></div>");
  }
  h += row(T(STR_W_R_NFC),   pill(nfc_ok, STR_W_S_READY, STR_W_S_MISSING));
  // What answers on the external bus, in the words the boot log uses. Both
  // rows above say "missing" for a chip that is broken, unpowered or wired to
  // the wrong pin; this one says whether anything is there at all.
  {
    h += F("<div class='row'><span class='k'>");
    h += T(STR_W_R_I2C);
    h += F("</span><span class='v mono' id='i2c'>");
    h += i2cScanLast();
    h += F("</span></div>");
  }
  h += row(T(STR_W_R_SD),    pill(sd_available, STR_W_S_READY, STR_W_S_MISSING, true));
  h += row(T(STR_W_R_UPTIME), uptimeText());
  h += F("<button class='quiet' id='i2cbtn'>");
  h += T(STR_W_RESCAN);
  h += F("</button>");
  h += F("</div></div>");

  // ---- inventory --------------------------------------------------------
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_C_INVENTORY);
  h += F("</h2><div class='rows'>");
  h += row(T(STR_W_R_BACKEND), backendName());
  h += row(T(STR_W_R_ADDRESS), backendBaseUrl(), true);
  h += row(T(STR_W_R_REACHABLE), pill(sm_reachable, STR_W_S_YES, STR_W_S_NO));
  h += row(T(STR_W_R_SCANS), String(scan_count));
  h += F("</div></div>");

  // ---- access -----------------------------------------------------------
  // Not a second navigation - the tabs already do that. This says which
  // sections are actually being served, which the tabs cannot show.
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_C_ACCESS);
  h += F("</h2><div class='rows'>");
  h += row(T(STR_W_NAV_SETTINGS), pill(webConfigEnabled(), STR_W_S_ON, STR_W_S_OFF, true));
  h += row(T(STR_W_C_DEVICE),     pill(webMaintenanceEnabled(), STR_W_S_ON, STR_W_S_OFF, true));
  h += F("</div><p class='note'>");
  h += T(STR_W_ACCESS_NOTE);
  h += F(" <b>");
  h += T(STR_W_OFF_PATH);
  h += F("</b>.</p></div>");

  // ---- device -----------------------------------------------------------
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_C_DEVICE);
  h += F("</h2><button class='quiet' onclick='doRestart()'>");
  h += T(STR_W_RESTART);
  h += F("</button><p class='note'>");
  h += T(STR_W_RESTART_NOTE);
  h += F("</p></div></div>");

  h += webShellRestartUi();

  // Two seconds, and only while the tab is in front. A status page left
  // open in a background tab would otherwise poll the scale all day for
  // nobody. Names are prefixed so nothing collides with the restart
  // overlay above - a duplicate const kills both blocks at parse time.
  h += F("<script>"
         "function wtTick(){if(document.hidden)return;"
         "fetch('/status.json',{cache:'no-store'}).then(r=>r.json()).then(d=>{"
         "const e=document.getElementById('wt');"
         "if(e)e.textContent=d.scaleReady?d.weight:'---';"
         "const q=document.getElementById('i2c');"
         "if(q&&d.i2c)q.textContent=d.i2c;"
         "}).catch(()=>{});}"
         "setInterval(wtTick,2000);"
         "document.addEventListener('visibilitychange',wtTick);"
         "const i2cB=document.getElementById('i2cbtn');"
         "if(i2cB)i2cB.addEventListener('click',()=>{"
         "i2cB.disabled=true;"
         "fetch('/api/i2cscan',{method:'POST',cache:'no-store'})"
         ".then(r=>r.json()).then(d=>{"
         "const e=document.getElementById('i2c');"
         "if(e)e.textContent=d.i2c;"
         "}).catch(()=>{}).then(()=>{i2cB.disabled=false;});"
         "});"
         "</script>");
  return h;
}

static void routes(WebServer &srv) {
  // Restarting is not destructive - settings live in NVS - but it is still a
  // remote action, so it sits behind a gate rather than being exposed
  // whenever the landing page is reachable.
  srv.on("/api/restart", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_C_DEVICE))) return;
    logSD("Reboot: requested from web UI");
    srv.send(200, "application/json", "{\"ok\":true}");
    delay(400);            // let the response actually leave before the reset
    ESP.restart();
  });

  // Probing 112 addresses costs about 10 ms of bus time that the reader and
  // the ADC have to wait through, so it happens when someone asks rather than
  // on every poll of the page. It runs in the loop task - the same task that
  // owns I2C_EXT - because handleOtaServerClient() is called from appLoop().
  srv.on("/api/i2cscan", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_OPEN, T(STR_W_NAV_STATUS))) return;
    i2cScanRefresh(I2C_EXT);
    logSDf("I2C_EXT rescan: %s", i2cScanLast());
    srv.send(200, "application/json",
             String("{\"i2c\":\"") + jsonEsc(i2cScanLast()) + "\"}");
  });

  // Polled by the restart overlay, which needs an answer the moment the
  // device is back. Kept as JSON rather than folded into the page.
  srv.on("/status.json", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_OPEN, T(STR_W_NAV_STATUS))) return;
    srv.send(200, "application/json", statusJson());
  });
}

extern const WebPage PAGE_STATUS;
const WebPage PAGE_STATUS = {
  "/", label, GATE_OPEN, nullptr,
  body, routes
};
