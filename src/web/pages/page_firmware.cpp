// Firmware upload. Used to live at "/", which meant browsing the device
// address dropped the visitor straight into a file picker.
#include "web/web_pages.h"

#include <Arduino.h>
#include <Update.h>
#include <WebServer.h>
#include <lvgl.h>

#include "app/app_state.h"
#include "app_config.h"
#include "hardware/sd_logger.h"
#include "services/github_release.h"
#include "services/ota_state.h"
#include "services/prefs_store.h"
#include "services/update_check.h"
#include "services/version_compare.h"
#include "ui/update_badges.h"
#include "web/web_access.h"
#include "web/web_server.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

// Set while an image is being received. The background update check reads
// this to stay out of the way: a second TLS connection during a flash is
// exactly the situation that must not happen.
static bool ota_upload_active = false;

// What the device screen needs to draw a bar while the browser pushes an
// image. Until now it said "Uploading..." once and then nothing for two
// minutes, so anyone standing at the scale could not tell a slow upload from
// a dead one.
static uint32_t ota_upload_total = 0;
static uint32_t ota_upload_done  = 0;
static unsigned long ota_last_paint = 0;

// A GitHub install asked for from this page, waiting for the loop. The route
// answers first and flashes afterwards: the download holds the loop for about
// a minute and then restarts the device, so a reply written after it would
// never leave.
static bool gh_web_flash_pending = false;
static char gh_web_flash_tag[40] = "";

bool otaWebUploadActive() { return ota_upload_active; }

static const char* label() { return T(STR_W_NAV_FIRMWARE); }

static String jsonEsc(const char *s) {
  String o;
  for (const char *p = s ? s : ""; *p; p++) {
    if (*p == '"' || *p == '\\') { o += '\\'; o += *p; }
    else if ((uint8_t)*p < 0x20)  { o += ' '; }
    else                          { o += *p; }
  }
  return o;
}

// Whatever else is holding a TLS connection or writing flash. Two handshakes
// want roughly 40 kB each and the device does not have that twice over.
static bool otaBusy() {
  return updateCheckBusy() || gh_flash_active || ota_upload_active ||
         gh_web_flash_pending;
}

static void webFlashProgress(uint32_t done, uint32_t total) {
  if (!lbl_ota_status) return;
  char line[48];
  otaProgressLine(line, sizeof(line), done, total);
  lv_label_set_text(lbl_ota_status, line);
  lv_refr_now(NULL);
}

void otaWebGithubTick() {
  if (!gh_web_flash_pending) return;
  gh_web_flash_pending = false;

  logSDf("OTA: installing %s from GitHub, asked from the web UI", gh_web_flash_tag);
  if (lbl_ota_status) lv_label_set_text(lbl_ota_status, T(STR_GH_OTA_FLASHING));

  char err[80] = "";
  if (githubFlashTag(gh_web_flash_tag, webFlashProgress, err, sizeof(err))) {
    logSD("Reboot: GitHub update written");
    if (lbl_ota_status) lv_label_set_text(lbl_ota_status, T(STR_OTA_SUCCESS));
    lv_timer_handler();
    delay(1500);
    ESP.restart();
  }
  logSDf("OTA: install failed - %s", err);
  if (lbl_ota_status) lv_label_set_text(lbl_ota_status, T(STR_OTA_FAIL));
}

static String body() {
  String h;
  h.reserve(5200);
  h += F("<div class='grid'><div class='card wide'><h2>");
  h += T(STR_W_C_FIRMWARE);
  h += F("</h2><div class='rows' style='margin-bottom:16px'>");
  h += F("<div class='row'><span class='k'>");
  h += T(STR_W_FW_INSTALLED);
  h += F("</span><span class='v mono'>");
  h += FW_VERSION;
  h += F("</span></div></div>"
         "<form method='POST' action='/update' enctype='multipart/form-data'>"
         "<div class='field'><label>");
  h += T(STR_W_FW_FILE);
  h += F("</label><div class='inrow'>"
         "<input type='file' name='firmware' accept='.bin' required>"
         "<button type='submit'>");
  h += T(STR_W_FW_FLASH);
  h += F("</button></div><span class='hint'>");
  h += T(STR_W_FW_HINT);
  h += F("</span></div></form></div>");

  // The same check the device screen offers, for anyone who is not standing
  // in front of the scale. The channel is the one setting behind both, so the
  // two screens cannot end up looking at different release lists.
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_C_FW_GITHUB);
  h += F("</h2><div class='rows' style='margin-bottom:16px'>"
         "<div class='row'><span class='k'>");
  h += T(STR_W_FW_CHANNEL);
  h += F("</span><span class='v'><select id='ghch' style='flex:0 0 auto'>"
         "<option value='0'");
  if (!gh_prerelease) h += F(" selected");
  h += F(">");
  h += T(STR_W_FW_CH_STABLE);
  h += F("</option><option value='1'");
  if (gh_prerelease) h += F(" selected");
  h += F(">");
  h += T(STR_W_FW_CH_PRE);
  h += F("</option></select></span></div>"
         "<div class='row'><span class='k'>");
  h += T(STR_W_FW_LATEST);
  h += F("</span><span class='v mono' id='ghlt'>");
  h += (gh_latest_version[0] ? gh_latest_version : "-");
  h += F("</span></div></div>"
         "<div class='inrow'><button class='quiet' id='ghck' onclick='ghCheck()'>");
  h += T(STR_W_FW_CHECK);
  // A check that already found something - the daily background one included
  // - leaves the button ready, rather than making the visitor repeat it.
  h += F("</button><button id='ghin' onclick='ghInstall()'");
  if (!(update_available && gh_latest_version[0])) h += F(" disabled");
  h += F(">");
  h += T(STR_W_FW_INSTALL);
  h += F("</button><span id='ghmsg' class='msg'></span></div><p class='note'>");
  h += T(STR_W_FW_GH_HINT);
  h += F("</p></div></div>");

  // Brings in the waiting overlay and its strings; the install below drives
  // the same box rather than growing a second one.
  h += webShellRestartUi();

  h += F("<script>const G={check:");
  h += jsStr(T(STR_W_FW_CHECK));
  h += F(",checking:");   h += jsStr(T(STR_W_FW_CHECKING));
  h += F(",uptodate:");   h += jsStr(T(STR_W_FW_UPTODATE));
  h += F(",avail:");      h += jsStr(T(STR_W_FW_AVAIL));
  h += F(",fail:");       h += jsStr(T(STR_W_FW_CHECK_FAIL));
  h += F(",nowifi:");     h += jsStr(T(STR_W_FW_NOWIFI));
  h += F(",busy:");       h += jsStr(T(STR_W_FW_BUSY));
  h += F(",installing:"); h += jsStr(T(STR_W_FW_INSTALLING));
  h += F(",keep:");       h += jsStr(T(STR_W_FW_HINT));
  h += F("};"
         "function ghSay(t,bad){var m=document.getElementById('ghmsg');"
         "m.className=bad?'msg bad':'msg';m.textContent=t;}"
         "function ghErr(d){return d.error==='nowifi'?G.nowifi:"
         "(d.error==='busy'?G.busy:G.fail+(d.error?': '+d.error:''));}"
         "function ghCheck(){"
         "var b=document.getElementById('ghck');"
         "b.disabled=true;b.textContent=G.checking;ghSay('');"
         "fetch('/api/ota/check?pre='+document.getElementById('ghch').value,"
         "{method:'POST'}).then(r=>r.json()).then(d=>{"
         "if(!d.ok){ghSay(ghErr(d),true);return;}"
         "document.getElementById('ghlt').textContent=d.tag;"
         "document.getElementById('ghin').disabled=!d.update;"
         "ghSay(d.update?G.avail:G.uptodate,false);"
         "}).catch(()=>ghSay(G.fail,true))"
         ".finally(()=>{b.disabled=false;b.textContent=G.check;});}"
         // The device is unreachable from the moment it starts downloading
         // until it has rebooted, so the first poll waits rather than
         // reporting a healthy install as a failure.
         "function ghInstall(){"
         "fetch('/api/ota/install',{method:'POST'}).then(r=>r.json()).then(d=>{"
         "if(!d.ok){ghSay(ghErr(d),true);return;}"
         "document.getElementById('rtitle').textContent=G.installing;"
         "var s=document.getElementById('rsec');"
         "document.getElementById('rbox').style.display='flex';"
         "var t=0;var iv=setInterval(function(){t++;"
         "s.textContent=G.keep+' - '+t+'s';"
         "if(t<20)return;"
         "if(t>300){clearInterval(iv);"
         "s.innerHTML=RT.gone+\" <a href='' style='color:var(--accent)'>\"+RT.reload+'</a>';"
         "return;}"
         "fetch('/status.json',{cache:'no-store'}).then(function(r){"
         "if(r.ok){clearInterval(iv);location.reload();}}).catch(function(){});"
         "},1000);"
         "}).catch(()=>ghSay(G.fail,true));}"
         "</script>");
  return h;
}

static void routes(WebServer &srv) {
  srv.on("/api/ota/check", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_FIRMWARE))) return;
    if (!wifi_ok) {
      srv.send(200, "application/json", "{\"ok\":false,\"error\":\"nowifi\"}");
      return;
    }
    if (otaBusy()) {
      srv.send(200, "application/json", "{\"ok\":false,\"error\":\"busy\"}");
      return;
    }
    if (srv.hasArg("pre")) {
      gh_prerelease = (srv.arg("pre") == "1");
      prefsPutBool("gh_prerelease", gh_prerelease);
    }

    char tag[40] = "", err[80] = "";
    if (!githubLatestTag(gh_prerelease, tag, sizeof(tag), err, sizeof(err))) {
      srv.send(200, "application/json",
               "{\"ok\":false,\"error\":\"" + jsonEsc(err) + "\"}");
      return;
    }

    strncpy(gh_latest_version, tag, sizeof(gh_latest_version) - 1);
    gh_latest_version[sizeof(gh_latest_version) - 1] = '\0';
    const bool newer = parseVersion(tag) > parseVersion(FW_VERSION);
    if (newer) {
      update_available = true;
      showUpdateBadges(true);
    }
    logSDf("OTA check: web asked, latest %s%s", tag, newer ? " (newer)" : "");
    srv.send(200, "application/json",
             "{\"ok\":true,\"tag\":\"" + jsonEsc(tag) +
             "\",\"installed\":\"" + jsonEsc(FW_VERSION) +
             "\",\"update\":" + (newer ? "true" : "false") + "}");
  });

  // Installs what the last check found. The tag is never taken from the
  // request: it goes straight into a download URL, and the only version this
  // page ever offers is the one it just showed.
  srv.on("/api/ota/install", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_FIRMWARE))) return;
    if (!wifi_ok) {
      srv.send(200, "application/json", "{\"ok\":false,\"error\":\"nowifi\"}");
      return;
    }
    if (otaBusy()) {
      srv.send(200, "application/json", "{\"ok\":false,\"error\":\"busy\"}");
      return;
    }
    if (gh_latest_version[0] == '\0') {
      srv.send(200, "application/json", "{\"ok\":false,\"error\":\"nocheck\"}");
      return;
    }
    strncpy(gh_web_flash_tag, gh_latest_version, sizeof(gh_web_flash_tag) - 1);
    gh_web_flash_tag[sizeof(gh_web_flash_tag) - 1] = '\0';
    gh_web_flash_pending = true;
    srv.send(200, "application/json", "{\"ok\":true}");
  });

  srv.on("/update", HTTP_POST,
    // Completion handler. Runs after the bytes are already written, which is
    // why the gate is checked in both callbacks: guarding only this one
    // refuses the reply and flashes the device anyway.
    [&srv]() {
      if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_FIRMWARE))) return;
      bool ok = !Update.hasError();
      String msg = ok
        ? "<!DOCTYPE html><html><head><meta charset='utf-8'>"
          "<meta http-equiv='refresh' content='5;url=/'>"
          "<style>body{background:#06080f;color:#28d49a;font-family:-apple-system,sans-serif;"
          "display:flex;flex-direction:column;align-items:center;justify-content:center;"
          "min-height:100vh;gap:12px}"
          "h1{font-size:28px}p{color:#4a6fa0;font-size:14px}</style></head>"
          "<body><h1>&#10003; " + String(T(STR_W_FW_OK)) + "</h1>"
          "<p>" + String(T(STR_W_FW_RESTARTING)) + "</p></body></html>"
        : "<!DOCTYPE html><html><head><meta charset='utf-8'>"
          "<style>body{background:#06080f;color:#ff8080;font-family:-apple-system,sans-serif;"
          "display:flex;flex-direction:column;align-items:center;justify-content:center;"
          "min-height:100vh;gap:12px}"
          "h1{font-size:28px}p{color:#4a6fa0;font-size:14px}"
          "a{color:#28d49a}</style></head>"
          "<body><h1>&#10007; " + String(T(STR_W_FW_FAIL)) + "</h1>"
          "<p>" + String(T(STR_W_FW_RETRY)) + "</p><a href='/'>&#8592; " + String(T(STR_W_BACK_STATUS)) + "</a></body></html>";
      srv.send(200, "text/html", msg);
      if (ok) {
        if (lbl_ota_status) lv_label_set_text(lbl_ota_status,
          T(STR_OTA_SUCCESS));
        lv_timer_handler();
        delay(1500);
        logSD("Reboot: OTA browser update success");
        ESP.restart();
      } else {
        if (lbl_ota_status) lv_label_set_text(lbl_ota_status,
          T(STR_OTA_FAIL));
      }
    },
    // Chunk handler.
    [&srv]() {
      if (!webGateOpen(GATE_MAINT)) return;
      HTTPUpload& upload = srv.upload();
      if (upload.status == UPLOAD_FILE_START) {
        Serial.printf("OTA start: %s\n", upload.filename.c_str());
        ota_upload_active = true;
        if (Update.isRunning()) Update.abort();  // clean up any previous failed upload
        if (!Update.begin(UPDATE_SIZE_UNKNOWN)) {
          Serial.println("OTA begin() error");
          ota_upload_active = false;
        }
        // The multipart envelope adds a few hundred bytes on top of the
        // image. On a 1.9 MB upload that is under 0.05 %, so it serves as the
        // denominator; otaProgressLine() clamps the last stretch at 100.
        ota_upload_total = (srv.clientContentLength() > 0)
                           ? (uint32_t)srv.clientContentLength() : 0;
        ota_upload_done  = 0;
        ota_last_paint   = 0;
        if (lbl_ota_status) lv_label_set_text(lbl_ota_status,
          T(STR_OTA_UPLOADING));
        lv_timer_handler();
      } else if (upload.status == UPLOAD_FILE_WRITE) {
        if (Update.write(upload.buf, upload.currentSize) != upload.currentSize) {
          Serial.println("OTA write() error");
        }
        ota_upload_done += upload.currentSize;
        // Same cadence as the GitHub path. Painting per chunk would cost more
        // than the write does.
        if (lbl_ota_status && millis() - ota_last_paint >= OTA_PROGRESS_MS) {
          ota_last_paint = millis();
          char line[48];
          otaProgressLine(line, sizeof(line), ota_upload_done, ota_upload_total);
          lv_label_set_text(lbl_ota_status, line);
          lv_refr_now(NULL);
        }
      } else if (upload.status == UPLOAD_FILE_END) {
        ota_upload_active = false;
        if (Update.end(true)) {
          Serial.printf("OTA end: %u bytes\n", upload.totalSize);
        } else {
          Serial.println("OTA end() error");
        }
      }
    }
  );
}

extern const WebPage PAGE_FIRMWARE;
const WebPage PAGE_FIRMWARE = {
  "/ota", label, GATE_MAINT, nullptr,
  body, routes
};
