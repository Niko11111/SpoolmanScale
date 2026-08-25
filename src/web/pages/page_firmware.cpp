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

// The last answer the network gave, and what it was asked. Opening the page
// checks by itself, so without this every visit - and every hop back to this
// tab - would spend a TLS handshake and a GitHub request to be told the same
// thing. Pressing the button always goes out; only the automatic check reuses
// this.
#define OTA_CHECK_CACHE_MS 600000UL
static unsigned long s_check_ms  = 0;     // 0 = no check yet this boot
static bool          s_check_pre = false; // the channel it was for
static bool          s_check_new = false;

bool otaWebUploadActive() { return ota_upload_active; }

static const char* label() { return T(STR_W_NAV_FIRMWARE); }

static String jsonEsc(const char *s) {
  String o;
  for (const char *p = s ? s : ""; *p; p++) {
    if (*p == '"' || *p == '\\') { o += '\\'; o += *p; }
    // Release notes are the only multi-line thing that comes through here,
    // and they arrive with CRLF. The CR is dropped rather than turned into a
    // space, which would end every line with one.
    else if (*p == '\n')          { o += "\\n"; }
    else if (*p == '\r')          { }
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
  h.reserve(7600);

  // What is running, and where it came from. The version alone was already at
  // the top of every page; which channel it belongs to and when it landed are
  // the parts nothing could answer.
  h += F("<div class='grid'><div class='card wide'><h2>");
  h += T(STR_W_C_FIRMWARE);
  h += F("</h2><div class='rows' style='margin-bottom:16px'>"
         "<div class='row'><span class='k'>");
  h += T(STR_W_FW_INSTALLED);
  h += F("</span><span class='v mono'>");
  h += FW_VERSION;
  h += F("</span></div>"
         "<div class='row'><span class='k'>");
  h += T(STR_W_FW_CHANNEL);
  h += F("</span><span class='v' id='fwch'>&hellip;</span></div>"
         "<div class='row'><span class='k'>");
  h += T(STR_W_FW_RELEASED);
  h += F("</span><span class='v' id='fwrel'>&hellip;</span></div>"
         "<div class='row'><span class='k'>");
  h += T(STR_W_FW_SINCE);
  // The epoch goes to the browser and is rendered there: the reader's own
  // clock and zone are the right ones for a page, and the device's are a
  // separate question.
  h += F("</span><span class='v' id='fwsince' data-t='");
  h += String((unsigned long)firmwareInstalledAt());
  h += F("'></span></div></div>"
         "<button class='quiet' id='fwnb' onclick='fwNotes()' disabled>");
  h += T(STR_W_FW_NOTES);
  h += F("</button>"
         "<pre id='fwn' class='notes'></pre>"
         "<form method='POST' action='/update' enctype='multipart/form-data'"
         " style='margin-top:18px'>"
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
  h += F("</span><span class='v'>"
         "<select id='ghch' style='flex:0 0 auto' onchange='ghCheck(false)'>"
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
  // - leaves the buttons ready, rather than making the visitor repeat it.
  const bool have_latest = (gh_latest_version[0] != '\0');
  h += F("</button><button id='ghin' onclick='ghInstall()'");
  if (!(update_available && have_latest)) h += F(" disabled");
  h += F(">");
  h += T(STR_W_FW_INSTALL);
  h += F("</button><button class='quiet' id='ghnb' onclick='ghNotes()'");
  if (!have_latest) h += F(" disabled");
  h += F(">");
  h += T(STR_W_FW_WHATSNEW);
  h += F("</button><span id='ghmsg' class='msg'></span></div>"
         "<pre id='ghn' class='notes'></pre><p class='note'>");
  h += T(STR_W_FW_GH_HINT);
  h += F("</p></div></div>");

  h += F("<style>.notes{display:none;max-height:340px;overflow:auto;"
         "background:var(--ground);border:1px solid var(--line);border-radius:8px;"
         "padding:12px 14px;margin-top:12px;font-size:12.5px;line-height:1.6;"
         "white-space:pre-wrap;word-break:break-word;color:var(--ink-2)}</style>");

  // Brings in the waiting overlay and its strings; the install below drives
  // the same box rather than growing a second one.
  h += webShellRestartUi();

  h += F("<script>const INSTALLED=");
  h += jsStr(FW_VERSION);
  h += F(",G={check:");
  h += jsStr(T(STR_W_FW_CHECK));
  h += F(",checking:");   h += jsStr(T(STR_W_FW_CHECKING));
  h += F(",uptodate:");   h += jsStr(T(STR_W_FW_UPTODATE));
  h += F(",avail:");      h += jsStr(T(STR_W_FW_AVAIL));
  h += F(",fail:");       h += jsStr(T(STR_W_FW_CHECK_FAIL));
  h += F(",nowifi:");     h += jsStr(T(STR_W_FW_NOWIFI));
  h += F(",busy:");       h += jsStr(T(STR_W_FW_BUSY));
  h += F(",installing:"); h += jsStr(T(STR_W_FW_INSTALLING));
  h += F(",keep:");       h += jsStr(T(STR_W_FW_HINT));
  h += F(",notes:");      h += jsStr(T(STR_W_FW_NOTES));
  h += F(",whatsnew:");   h += jsStr(T(STR_W_FW_WHATSNEW));
  h += F(",hide:");       h += jsStr(T(STR_W_FW_HIDE));
  h += F(",confirm:");    h += jsStr(T(STR_W_FW_CONFIRM));
  h += F(",cancel:");     h += jsStr(T(STR_CANCEL));
  h += F(",install:");    h += jsStr(T(STR_W_FW_INSTALL));
  h += F(",unpub:");      h += jsStr(T(STR_W_FW_UNPUBLISHED));
  h += F(",unknown:");    h += jsStr(T(STR_W_FW_UNKNOWN));
  h += F(",chrel:");      h += jsStr(T(STR_W_FW_CH_STABLE));
  h += F(",chpre:");      h += jsStr(T(STR_W_FW_CH_PRE));
  h += F("};"
         "function ghSay(t,bad){var m=document.getElementById('ghmsg');"
         "m.className=bad?'msg bad':'msg';m.textContent=t;}"
         "function ghErr(d){return d.error==='nowifi'?G.nowifi:"
         "(d.error==='busy'?G.busy:G.fail+(d.error?': '+d.error:''));}"
         "function fmtDate(s){if(!s)return G.unknown;"
         "var d=new Date(s);return isNaN(d)?s:d.toLocaleDateString();}"
         // One request on load fills the three rows and keeps the body, so
         // opening the notes afterwards costs nothing.
         "var INST=null;"
         // The overlay ships with a spinner and two lines of text. Installing
         // asks a question first, so it grows a button row - added here rather
         // than a second box, because the question and the wait that follows
         // it are one conversation.
         "function rModal(ask,title,text){"
         "var b=document.getElementById('rbox'),r=document.getElementById('rbtn');"
         "document.querySelector('#rbox .spin').style.display=ask?'none':'';"
         "document.getElementById('rtitle').textContent=title;"
         "document.getElementById('rsec').textContent=text;"
         "r.style.display=ask?'flex':'none';b.style.display='flex';}"
         "function rInit(){"
         "var rc=document.querySelector('#rbox .rc');if(!rc)return;"
         "var d=document.createElement('div');d.id='rbtn';"
         "d.style.cssText='display:none;gap:10px;justify-content:center;margin-top:20px';"
         "var no=document.createElement('button');no.className='quiet';"
         "no.textContent=G.cancel;"
         "no.onclick=function(){document.getElementById('rbox').style.display='none';};"
         "var yes=document.createElement('button');yes.textContent=G.install;"
         "yes.onclick=ghGo;"
         "d.appendChild(no);d.appendChild(yes);rc.appendChild(d);}"
         "function fwInit(){"
         "rInit();"
         "var e=document.getElementById('fwsince'),t=parseInt(e.dataset.t||'0');"
         "e.textContent=t?new Date(t*1000).toLocaleString():G.unknown;"
         "fetch('/api/ota/notes?tag='+encodeURIComponent(INSTALLED))"
         ".then(r=>r.json()).then(d=>{"
         "var c=document.getElementById('fwch'),r2=document.getElementById('fwrel');"
         "if(!d.ok){c.textContent=d.error==='notfound'?G.unpub:G.unknown;"
         "r2.textContent=G.unknown;return;}"
         "INST=d;c.textContent=d.prerelease?G.chpre:G.chrel;"
         "r2.textContent=fmtDate(d.published);"
         "document.getElementById('fwnb').disabled=!d.notes;"
         // Chained, not fired alongside: both calls are served from the same
         // loop as everything else the scale does, so two at once only means
         // the second one waits with a socket held open.
         "}).catch(()=>{}).finally(()=>ghCheck(true));}"
         "function toggle(pre,btn,shown,hidden,text){"
         "var e=document.getElementById(pre),b=document.getElementById(btn);"
         "if(e.style.display==='block'){e.style.display='none';b.textContent=shown;return;}"
         "e.textContent=text;e.style.display='block';b.textContent=hidden;}"
         "function fwNotes(){if(!INST)return;"
         "toggle('fwn','fwnb',G.notes,G.hide,INST.notes);}"
         // auto is the check the page runs by itself, on load and when the
         // channel changes. It may be answered from the device's last result,
         // and it stays quiet when it fails: a scale with no route out should
         // not greet every visitor with a red line.
         "function ghCheck(auto){"
         "var b=document.getElementById('ghck');"
         "b.disabled=true;b.textContent=G.checking;ghSay('');"
         "fetch('/api/ota/check?pre='+document.getElementById('ghch').value"
         "+(auto?'&auto=1':''),"
         "{method:'POST'}).then(r=>r.json()).then(d=>{"
         "if(!d.ok){if(!auto)ghSay(ghErr(d),true);return;}"
         "document.getElementById('ghlt').textContent=d.tag;"
         "document.getElementById('ghin').disabled=!d.update;"
         "var n=document.getElementById('ghnb');n.disabled=false;"
         // A different tag than whatever the notes pane last showed.
         "LATEST=null;document.getElementById('ghn').style.display='none';"
         "n.textContent=G.whatsnew;"
         "ghSay(d.update?G.avail:G.uptodate,false);"
         "}).catch(()=>{if(!auto)ghSay(G.fail,true);})"
         ".finally(()=>{b.disabled=false;b.textContent=G.check;});}"
         "var LATEST=null;"
         "function ghNotes(){"
         "var tag=document.getElementById('ghlt').textContent;"
         "if(!tag||tag==='-')return;"
         "if(LATEST){toggle('ghn','ghnb',G.whatsnew,G.hide,LATEST.notes);return;}"
         "var b=document.getElementById('ghnb');b.disabled=true;"
         "fetch('/api/ota/notes?tag='+encodeURIComponent(tag)).then(r=>r.json())"
         ".then(d=>{if(!d.ok){ghSay(ghErr(d),true);return;}"
         "LATEST=d;toggle('ghn','ghnb',G.whatsnew,G.hide,d.notes);})"
         ".catch(()=>ghSay(G.fail,true))"
         ".finally(()=>{b.disabled=false;});}"
         // The device is unreachable from the moment it starts downloading
         // until it has rebooted, so the first poll waits rather than
         // reporting a healthy install as a failure.
         "function ghInstall(){"
         "var tag=document.getElementById('ghlt').textContent;"
         "rModal(true,G.confirm.replace('{v}',tag),G.keep);}"
         "function ghGo(){"
         "rModal(false,G.installing,G.keep);"
         "fetch('/api/ota/install',{method:'POST'}).then(r=>r.json()).then(d=>{"
         // A refusal closes the box again and says why on the card, rather
         // than leaving a spinner over a device that is not doing anything.
         "if(!d.ok){document.getElementById('rbox').style.display='none';"
         "ghSay(ghErr(d),true);return;}"
         "var s=document.getElementById('rsec');"
         "var t=0;var iv=setInterval(function(){t++;"
         "s.textContent=G.keep+' - '+t+'s';"
         "if(t<20)return;"
         "if(t>300){clearInterval(iv);"
         "s.innerHTML=RT.gone+\" <a href='' style='color:var(--accent)'>\"+RT.reload+'</a>';"
         "return;}"
         "fetch('/status.json',{cache:'no-store'}).then(function(r){"
         "if(r.ok){clearInterval(iv);location.reload();}}).catch(function(){});"
         "},1000);"
         "}).catch(()=>{document.getElementById('rbox').style.display='none';"
         "ghSay(G.fail,true);});}"
         "fwInit();"
         "</script>");
  return h;
}

static void routes(WebServer &srv) {
  // What GitHub says about one tag: which channel it belongs to, when it was
  // published, and the release notes. The installed version and the one a
  // check found are both asked about through here.
  srv.on("/api/ota/notes", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_FIRMWARE))) return;
    if (!wifi_ok) {
      srv.send(200, "application/json", "{\"ok\":false,\"error\":\"nowifi\"}");
      return;
    }
    if (otaBusy()) {
      srv.send(200, "application/json", "{\"ok\":false,\"error\":\"busy\"}");
      return;
    }
    GithubRelease rel;
    char err[80] = "";
    if (!githubReleaseByTag(srv.arg("tag").c_str(), rel, err, sizeof(err))) {
      srv.send(200, "application/json",
               "{\"ok\":false,\"error\":\"" + jsonEsc(err) + "\"}");
      return;
    }
    srv.send(200, "application/json",
             "{\"ok\":true,\"tag\":\"" + jsonEsc(rel.tag) +
             "\",\"name\":\"" + jsonEsc(rel.name) +
             "\",\"published\":\"" + jsonEsc(rel.published) +
             "\",\"prerelease\":" + (rel.prerelease ? "true" : "false") +
             ",\"notes\":\"" + jsonEsc(rel.notes.c_str()) + "\"}");
  });

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
      const bool want = (srv.arg("pre") == "1");
      // Only on a real change. The page sends the channel with every check,
      // including the one it runs by itself on load, and NVS is flash.
      if (want != gh_prerelease) {
        gh_prerelease = want;
        prefsPutBool("gh_prerelease", gh_prerelease);
      }
    }

    // The page checked itself rather than being asked to. An answer from the
    // same channel, taken minutes ago, is the same answer.
    if (srv.arg("auto") == "1" && s_check_ms != 0 &&
        s_check_pre == gh_prerelease && gh_latest_version[0] &&
        millis() - s_check_ms < OTA_CHECK_CACHE_MS) {
      srv.send(200, "application/json",
               "{\"ok\":true,\"cached\":true,\"tag\":\"" + jsonEsc(gh_latest_version) +
               "\",\"installed\":\"" + jsonEsc(FW_VERSION) +
               "\",\"update\":" + (s_check_new ? "true" : "false") + "}");
      return;
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
    s_check_ms  = millis() ? millis() : 1;   // 0 is reserved for "never"
    s_check_pre = gh_prerelease;
    s_check_new = newer;
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
