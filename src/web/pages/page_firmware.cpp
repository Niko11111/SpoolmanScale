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
#include "services/partition_layout.h"
#include "services/ota_state.h"
#include "services/prefs_store.h"
#include "services/update_check.h"
#include "services/version_compare.h"
#include "ui/ota_github.h"
#include "ui/update_badges.h"
#include "web/web_access.h"
#include "web/web_jobs.h"
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
static bool          s_check_old = false;  // found something below the running build
static char          s_check_pub[24] = "";  // when that release was published
static bool          s_check_big = false;   // newer, but larger than this device's slot

// How far the GitHub download has got. Read by /api/ota/progress, which is the
// only route answered while an image is being written.
static uint32_t s_flash_done  = 0;
static uint32_t s_flash_total = 0;

// What the chunk handler found out, for the completion handler: whether the
// image went into flash whole. The completion handler used to ask
// Update.hasError(), which is also false when Update was never started - a
// refused or failed begin() ended in a "success" page and a restart into
// whatever was there before.
static bool s_upload_ok = false;

// What the multipart envelope adds on top of the image: boundary lines and
// the part header. A few hundred bytes; this is the slack the size check
// allows before an upload is called too big for the partition.
#define OTA_MULTIPART_SLACK  2048

bool otaWebUploadActive() { return ota_upload_active; }

static const char* label() { return T(STR_W_NAV_FIRMWARE); }


// Whatever else is holding a TLS connection or writing flash. Two handshakes
// want roughly 40 kB each and the device does not have that twice over.
static bool otaBusy() {
  return updateCheckBusy() || gh_flash_active || ota_upload_active ||
         gh_web_flash_pending;
}

static void webFlashProgress(uint32_t done, uint32_t total) {
  s_flash_done  = done;
  s_flash_total = total;
  // The browser that asked for this is watching a bar, and the loop that would
  // normally answer it is here, inside the download. Pumping the server from
  // the progress callback is what lets it answer at all - safely, because
  // webRequire() turns every other route away while a flash is running.
  handleOtaServerClient();
  // And the scale itself, which is writing the flash and about to restart.
  // Its own screen is the only thing a person standing in front of it can see.
  otaGithubOverlayProgress(done, total);
  if (!lbl_ota_status) return;
  char line[48];
  otaProgressLine(line, sizeof(line), done, total);
  lv_label_set_text(lbl_ota_status, line);
}

void otaWebGithubTick() {
  if (!gh_web_flash_pending) return;
  gh_web_flash_pending = false;

  logSDf("OTA: installing %s from GitHub, asked from the web UI", gh_web_flash_tag);
  if (lbl_ota_status) lv_label_set_text(lbl_ota_status, T(STR_GH_OTA_FLASHING));
  // Stale from whatever ran before. The browser only reads these while the
  // flash is active, but starting a second one from the first one's byte count
  // would make the bar jump.
  s_flash_done  = 0;
  s_flash_total = 0;
  // The same cover the device screen raises. Someone standing at the scale
  // gets told an image is being written, and the touch below it stops
  // reaching a screen that is about to be replaced.
  otaGithubOverlayShow();

  char err[80] = "";
  if (githubFlashTag(gh_web_flash_tag, otaExpectedSha(gh_web_flash_tag),
                     webFlashProgress, err, sizeof(err))) {
    logSD("Reboot: GitHub update written");
    if (lbl_ota_status) lv_label_set_text(lbl_ota_status, T(STR_OTA_SUCCESS));
    lv_timer_handler();
    delay(1500);
    ESP.restart();
  }
  otaGithubOverlayHide();
  logSDf("OTA: install failed - %s", err);
  if (lbl_ota_status) lv_label_set_text(lbl_ota_status, T(STR_OTA_FAIL));
}

static String body() {
  String h;
  h.reserve(10500);

  // What is running, and where it came from. The version alone was already at
  // the top of every page; which channel it belongs to and when it landed are
  // the parts nothing could answer.
  h += F("<div class='grid'>");
  // The old partition table: what it means and the way out, before anything
  // else on the page (Nikolai, 26.09.2026). Only once the public flasher
  // carries the current table - see FLASHER_HAS_CURRENT_LAYOUT.
  const PartitionLayout& pl = partitionLayout();
  if (!pl.current && FLASHER_HAS_CURRENT_LAYOUT) {
    char text[640];
    const char* too_big = partitionTooBigVersion();
    if (too_big[0]) snprintf(text, sizeof(text), T(STR_PART_HINT_BLOCKED), too_big);
    else            copyT(text, sizeof(text), STR_PART_HINT_TEXT);
    h += F("<div class='card wide' style='border-color:var(--warn)'><h2>");
    h += T(STR_PART_HINT_TITLE);
    h += F("</h2><p style='white-space:pre-line;line-height:1.6;color:var(--ink-2);margin:0 0 14px'>");
    h += htmlEsc(text);
    // Only here, where there is room: the display keeps the short version.
    h += F("</p><p class='hint' style='margin:0 0 14px'>");
    h += htmlEsc(T(STR_PART_HINT_ERASE));
    h += F("</p><a href='" FLASHER_URL "' target='_blank' rel='noopener' style='color:var(--accent);font-weight:600'>");
    h += T(STR_PART_HINT_QR);
    h += F(" &#8599;</a></div>");
  }
  h += F("<div class='card wide'><h2>");
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
         "<form id='fwform' method='POST' action='/update' enctype='multipart/form-data'"
         " style='margin-top:18px'>"
         "<div class='field'><label>");
  h += T(STR_W_FW_FILE);
  h += F("</label><div class='inrow'>"
         "<label class='filebtn'>");
  h += T(STR_W_FW_CHOOSE);
  // No `required` on the hidden input: the browser cannot point at a hidden
  // control to complain, so the form would just do nothing. The submit button
  // stays disabled until a file is picked instead.
  h += F("<input type='file' name='firmware' accept='.bin' onchange='fwPick(this)'></label>"
         "<span class='fname' id='fwname' data-none='");
  h += htmlEsc(T(STR_W_FW_NOFILE));
  h += F("'>");
  h += T(STR_W_FW_NOFILE);
  h += F("</span><button type='submit' id='fwgo' disabled>");
  h += T(STR_W_FW_FLASH);
  h += F("</button></div><span class='hint'>");
  h += T(STR_W_FW_HINT);
  h += F("</span><span class='msg' id='fwmsg'></span></div></form></div>");

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
  h += F("</span></div>"
         "<div class='row'><span class='k'>");
  h += T(STR_W_FW_RELEASED);
  h += F("</span><span class='v' id='ghrel'>-</span></div></div>"
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
  // The app slot, so a file that cannot fit is turned away before a byte of
  // it travels.
  h += F(",SLOT=");
  h += String((unsigned long)partitionLayout().app_slot_bytes);
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
  h += F(",reboots:");    h += jsStr(T(STR_W_FW_REBOOTS));
  h += F(",cancel:");     h += jsStr(T(STR_CANCEL));
  h += F(",install:");    h += jsStr(T(STR_W_FW_INSTALL));
  h += F(",unpub:");      h += jsStr(T(STR_W_FW_UNPUBLISHED));
  h += F(",unknown:");    h += jsStr(T(STR_W_FW_UNKNOWN));
  h += F(",chrel:");      h += jsStr(T(STR_W_FW_CH_STABLE));
  h += F(",chpre:");      h += jsStr(T(STR_W_FW_CH_PRE));
  h += F(",older:");      h += jsStr(T(STR_W_FW_OLDER));
  h += F(",downgrade:");  h += jsStr(T(STR_W_FW_DOWNGRADE));
  h += F(",downwarn:");   h += jsStr(T(STR_W_FW_DOWNWARN));
  h += F(",uploading:");  h += jsStr(T(STR_W_FW_UPLOADING));
  h += F(",restarting:"); h += jsStr(T(STR_W_FW_RESTARTING));
  h += F(",upfail:");     h += jsStr(T(STR_W_FW_FAIL));
  h += F(",toobig:");     h += jsStr(T(STR_W_FW_TOOBIG));
  h += F(",ghbig:");      h += jsStr(T(STR_GH_OTA_TOO_BIG));
  h += F("};"
         "function ghSay(t,bad){var m=document.getElementById('ghmsg');"
         "m.className=bad?'msg bad':'msg';m.textContent=t;}"
         "function ghErr(d){return d.error==='nowifi'?G.nowifi:"
         "(d.error==='busy'?G.busy:G.fail+(d.error?': '+d.error:''));}"
         "function fmtDate(s){if(!s)return G.unknown;"
         "var d=new Date(s);return isNaN(d)?s:d.toLocaleDateString();}"
         "function setLatest(tag,pub){"
         "document.getElementById('ghlt').textContent=tag;"
         "document.getElementById('ghrel').textContent=pub?fmtDate(pub):'-';}"
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
         "document.getElementById('rbar').style.display='none';"
         // The line under the bar outlives the counter above it, which is
         // overwritten every second and cannot carry this.
         "document.getElementById('rnote').style.display=ask?'none':'block';"
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
         "d.appendChild(no);d.appendChild(yes);rc.appendChild(d);"
         "var b=document.createElement('div');b.id='rbar';"
         "b.style.cssText='display:none;height:8px;border-radius:4px;margin-top:18px;"
         "background:var(--line);overflow:hidden';"
         "b.innerHTML=\"<i id='rbari' style='display:block;height:100%;width:0;"
         "background:var(--accent);transition:width .3s'></i>\";"
         "rc.appendChild(b);"
         "var n=document.createElement('div');n.id='rnote';"
         "n.style.cssText='display:none;margin-top:16px;font-size:12px;"
         "line-height:1.5;color:var(--ink-3)';"
         "n.textContent=G.reboots;rc.appendChild(n);}"
         "function mb(n){return n>=1048576?(n/1048576).toFixed(2)+' MB'"
         ":(n/1024).toFixed(0)+' KB';}"
         // The upload as a request of its own rather than a form post, so the
         // bytes can be counted on the way out, and then the same wait for the
         // device to come back that the GitHub install has (Nikolai, 26.09.2026).
         "function fwSay(t){var m=document.getElementById('fwmsg');m.className='msg bad';m.textContent=t;}"
         "function fwUpload(e){e.preventDefault();"
         "var inp=document.querySelector('#fwform input[type=file]'),f=inp&&inp.files[0];if(!f)return;"
         "if(SLOT&&f.size>SLOT){fwSay(G.toobig.replace('{s}',mb(SLOT)));return;}"
         "rModal(false,G.uploading,G.keep);"
         "var s=document.getElementById('rsec'),bar=document.getElementById('rbar'),"
         "bi=document.getElementById('rbari'),sent=false;bar.style.display='block';"
         "var fd=new FormData();fd.append('firmware',f,f.name);"
         "var x=new XMLHttpRequest();x.open('POST','/update');"
         "x.upload.onprogress=function(ev){if(!ev.lengthComputable)return;"
         "var p=Math.round(ev.loaded*100/ev.total);bi.style.width=p+'%';"
         "s.textContent=mb(ev.loaded)+' / '+mb(ev.total)+' - '+p+' %';if(p>=100)sent=true;};"
         "x.onload=function(){if(x.status===200&&x.responseText.indexOf('&#10003;')>=0)fwBack();"
         "else{document.getElementById('rbox').style.display='none';fwSay(G.upfail);}};"
         // A drop after the last byte is the restart overtaking the reply.
         "x.onerror=function(){if(sent)fwBack();"
         "else{document.getElementById('rbox').style.display='none';fwSay(G.upfail);}};"
         "x.send(fd);}"
         // Back once /status.json answers again - after it was seen gone, or
         // after long enough that a missed gap cannot reload the old build.
         "function fwBack(){document.getElementById('rtitle').textContent=G.restarting;"
         "var s=document.getElementById('rsec'),t=0,down=false;"
         "document.getElementById('rbari').style.width='100%';"
         "var iv=setInterval(function(){t++;s.textContent=G.restarting+' '+t+'s';"
         "if(t>180){clearInterval(iv);"
         "s.innerHTML=RT.gone+\" <a href='' style='color:var(--accent)'>\"+RT.reload+'</a>';return;}"
         "fetch('/status.json',{cache:'no-store'}).then(function(r){"
         "if(r.ok&&(down||t>20)){clearInterval(iv);location.reload();}})"
         ".catch(function(){down=true;});},1000);}"
         "function fwInit(){"
         "rInit();"
         "var ff=document.getElementById('fwform');if(ff)ff.addEventListener('submit',fwUpload);"
         "var e=document.getElementById('fwsince'),t=parseInt(e.dataset.t||'0');"
         "e.textContent=t?new Date(t*1000).toLocaleString():G.unknown;"
         "fwInst(0);}"
         // The installed release's notes come from the worker like every
         // other GitHub answer: 202 means "asked, not answered", so this asks
         // again a second later. The check is chained behind the final answer,
         // because the worker takes one job at a time.
         "function fwInst(n){"
         "fetch('/api/ota/notes?tag='+encodeURIComponent(INSTALLED),{cache:'no-store'})"
         ".then(r=>{if(r.status===202){if(n<60)setTimeout(()=>fwInst(n+1),1000);"
         "else ghCheck(true);return null;}return r.json();}).then(d=>{"
         "if(!d)return;"
         "var c=document.getElementById('fwch'),r2=document.getElementById('fwrel');"
         "if(!d.ok){c.textContent=d.error==='notfound'?G.unpub:G.unknown;"
         "r2.textContent=G.unknown;}else{"
         "INST=d;c.textContent=d.prerelease?G.chpre:G.chrel;"
         "r2.textContent=fmtDate(d.published);"
         "document.getElementById('fwnb').disabled=!d.notes;}"
         "ghCheck(true);}).catch(()=>ghCheck(true));}"
         "function toggle(pre,btn,shown,hidden,text){"
         "var e=document.getElementById(pre),b=document.getElementById(btn);"
         "if(e.style.display==='block'){e.style.display='none';b.textContent=shown;return;}"
         "e.textContent=text;e.style.display='block';b.textContent=hidden;}"
         "function fwPick(i){const f=i.files&&i.files[0];"
         "const s=document.getElementById('fwname');"
         "s.textContent=f?f.name:s.dataset.none;"
         "document.getElementById('fwgo').disabled=!f;}"
         "function fwNotes(){if(!INST)return;"
         "toggle('fwn','fwnb',G.notes,G.hide,INST.notes);}"
         // auto is the check the page runs by itself, on load and when the
         // channel changes. It may be answered from the device's last result,
         // and it stays quiet when it fails: a scale with no route out should
         // not greet every visitor with a red line.
         "function ghCheck(auto,n){"
         "var b=document.getElementById('ghck');"
         "b.disabled=true;b.textContent=G.checking;ghSay('');"
         "var again=false;n=n||0;"
         "fetch('/api/ota/check?pre='+document.getElementById('ghch').value"
         "+(auto?'&auto=1':''),"
         // 202: the device has asked GitHub and is not back yet. Asked again
         // in a second; the button stays "checking" meanwhile.
         "{method:'POST'}).then(r=>{if(r.status===202&&n<60){again=true;"
         "setTimeout(()=>ghCheck(auto,n+1),1000);return null;}return r.json();}).then(d=>{"
         "if(!d)return;"
         "if(!d.ok){if(!auto)ghSay(ghErr(d),true);return;}"
         "setLatest(d.tag,d.published);"
         // Either direction is something to act on. Older only ever gets
         // here through a check that answered, so a silent automatic failure
         // leaves the button as the server rendered it: off.
         "OLDER=!!d.older;"
         "document.getElementById('ghin').disabled=!(d.update||d.older);"
         "var n=document.getElementById('ghnb');n.disabled=false;"
         // A different tag than whatever the notes pane last showed.
         "LATEST=null;document.getElementById('ghn').style.display='none';"
         "n.textContent=G.whatsnew;"
         "if(d.toobig){ghSay(G.ghbig.replace('%s',d.tag),true);}"
         "else ghSay(d.update?G.avail:(d.older?G.older:G.uptodate),false);"
         "}).catch(()=>{if(!auto)ghSay(G.fail,true);})"
         ".finally(()=>{if(!again){b.disabled=false;b.textContent=G.check;}});}"
         "var LATEST=null,OLDER=false;"
         "function ghNotes(){"
         "var tag=document.getElementById('ghlt').textContent;"
         "if(!tag||tag==='-')return;"
         "if(LATEST){toggle('ghn','ghnb',G.whatsnew,G.hide,LATEST.notes);return;}"
         "var b=document.getElementById('ghnb');b.disabled=true;var again=false;"
         "fetch('/api/ota/notes?tag='+encodeURIComponent(tag)).then(r=>{"
         "if(r.status===202){again=true;setTimeout(ghNotes,1000);return null;}return r.json();})"
         ".then(d=>{if(!d)return;if(!d.ok){ghSay(ghErr(d),true);return;}"
         "LATEST=d;toggle('ghn','ghnb',G.whatsnew,G.hide,d.notes);})"
         ".catch(()=>ghSay(G.fail,true))"
         ".finally(()=>{if(!again)b.disabled=false;});}"
         // The device is unreachable from the moment it starts downloading
         // until it has rebooted, so the first poll waits rather than
         // reporting a healthy install as a failure.
         "function ghInstall(){"
         "var tag=document.getElementById('ghlt').textContent;"
         "if(OLDER){rModal(true,G.downgrade.replace('{v}',tag),"
         "G.downwarn.replace('{v}',tag).replace('{i}',INSTALLED)+' '+G.keep);return;}"
         "rModal(true,G.confirm.replace('{v}',tag),G.keep);}"
         "function ghGo(){"
         "rModal(false,G.installing,G.keep);"
         "fetch('/api/ota/install',{method:'POST'}).then(r=>r.json()).then(d=>{"
         // A refusal closes the box again and says why on the card, rather
         // than leaving a spinner over a device that is not doing anything.
         "if(!d.ok){document.getElementById('rbox').style.display='none';"
         "ghSay(ghErr(d),true);return;}"
         "var s=document.getElementById('rsec'),"
         "bar=document.getElementById('rbar'),bi=document.getElementById('rbari');"
         "var t=0,seen=false;"
         // Two questions, in order: how far is the download, and is the device
         // back. The first is answered until the write finishes, the second
         // only once it has rebooted - /status.json is refused while an image
         // is being written, so a reply from it means the new build is up.
         "var iv=setInterval(function(){t++;"
         "if(t>300){clearInterval(iv);"
         "s.innerHTML=RT.gone+\" <a href='' style='color:var(--accent)'>\"+RT.reload+'</a>';"
         "return;}"
         "fetch('/api/ota/progress',{cache:'no-store'}).then(r=>r.ok?r.json():null)"
         ".then(function(d){"
         "if(d&&d.active){seen=true;bar.style.display='block';"
         "if(d.total){var p=Math.min(100,Math.round(d.done*100/d.total));"
         "bi.style.width=p+'%';"
         "s.textContent=mb(d.done)+' / '+mb(d.total)+' - '+p+' %';}"
         "else{s.textContent=mb(d.done);}return;}"
         // Not writing yet, or no longer writing. Before the download starts
         // that is the queued request; after it, the device is rebooting.
         "if(!seen){s.textContent=G.keep;return;}"
         "s.textContent=G.keep+' - '+t+'s';bi.style.width='100%';"
         "fetch('/status.json',{cache:'no-store'}).then(function(r){"
         "if(r.ok){clearInterval(iv);location.reload();}}).catch(function(){});"
         "}).catch(function(){"
         "if(!seen){s.textContent=G.keep;return;}"
         "s.textContent=G.keep+' - '+t+'s';});"
         "},1000);"
         "}).catch(()=>{document.getElementById('rbox').style.display='none';"
         "ghSay(G.fail,true);});}"
         "fwInit();"
         "</script>");
  return h;
}

static void ghCheckFinish(WebServer &srv);
static void routesTail(WebServer &srv);

static void routes(WebServer &srv) {
  // What GitHub says about one tag: which channel it belongs to, when it was
  // published, and the release notes. The installed version and the one a
  // check found are both asked about through here.
  // Answered from inside the download loop. Deliberately the smallest reply
  // on the device: it is built while an image is being written.
  srv.on("/api/ota/progress", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_FIRMWARE))) return;
    char j[96];
    snprintf(j, sizeof(j), "{\"active\":%s,\"done\":%lu,\"total\":%lu}",
             gh_flash_active ? "true" : "false",
             (unsigned long)s_flash_done, (unsigned long)s_flash_total);
    srv.send(200, "application/json", j);
  });


  srv.on("/api/ota/check", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_FIRMWARE))) return;
    // A check that is in, or on its way, comes before every other answer:
    // the page is asking again for the one it started.
    if (webJobState() == WJS_DONE && webJobKind() == WJ_GH_CHECK) { ghCheckFinish(srv); return; }
    if (webJobState() == WJS_RUNNING) {
      // Ours, or somebody else's: either way the answer is "ask again". A
      // "busy" here is what the page showed for a whole minute whenever the
      // notes of the installed release were still on their way.
      srv.send(202, "application/json", "{\"ok\":true,\"pending\":true}");
      return;
    }
    // A finished job nobody collected - the page moved on - must not block
    // this one: the slot is taken back and used.
    if (webJobState() == WJS_DONE) webJobTake();
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
               "\",\"published\":\"" + jsonEsc(s_check_pub) +
               "\",\"update\":" + (s_check_new ? "true" : "false") +
               ",\"older\":" + (s_check_old ? "true" : "false") +
               ",\"toobig\":" + (s_check_big ? "true" : "false") + "}");
      return;
    }

    // The request itself runs on the web worker: a TLS handshake held the
    // loop task, and with it the display, for up to eight seconds when it was
    // made here. 202 says "asked, not answered"; the page asks again.
    if (!webJobStart(WJ_GH_CHECK, nullptr, gh_prerelease)) {
      srv.send(200, "application/json", "{\"ok\":false,\"error\":\"busy\"}");
      return;
    }
    srv.send(202, "application/json", "{\"ok\":true,\"pending\":true}");
  });
  srv.on("/api/ota/notes", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_FIRMWARE))) return;
    const String tag = srv.arg("tag");
    // Collect, if the notes for this tag are in.
    if (webJobState() == WJS_DONE && webJobKind() == WJ_GH_NOTES) {
      const WebJobResult& r = webJobResult();
      String reply = r.ok ? r.body
                          : "{\"ok\":false,\"error\":\"" + jsonEsc(r.err) + "\"}";
      const bool same = (tag == r.tag) || !r.ok;
      webJobTake();
      if (same) { srv.send(200, "application/json", reply); return; }
      // Notes for another tag were waiting; asked for this one, start over.
    }
    if (webJobState() == WJS_RUNNING) {
      // Ours or another job's: the page asks again either way.
      srv.send(202, "application/json", "{\"ok\":true,\"pending\":true}");
      return;
    }
    if (webJobState() == WJS_DONE) webJobTake();   // somebody else's leftover
    if (!wifi_ok) {
      srv.send(200, "application/json", "{\"ok\":false,\"error\":\"nowifi\"}");
      return;
    }
    if (otaBusy() || !webJobStart(WJ_GH_NOTES, tag.c_str(), false)) {
      srv.send(200, "application/json", "{\"ok\":false,\"error\":\"busy\"}");
      return;
    }
    srv.send(202, "application/json", "{\"ok\":true,\"pending\":true}");
  });
  routesTail(srv);
}

// The second half of /api/ota/check, once the worker has the tag: everything
// here touches the loop task's own things - the badge, NVS, the cached
// answer - and so it runs in the handler that collects, not in the worker.
static void ghCheckFinish(WebServer &srv) {
  const WebJobResult& r = webJobResult();
  if (!r.ok) {
    String reply = "{\"ok\":false,\"error\":\"" + jsonEsc(r.err) + "\"}";
    webJobTake();
    srv.send(200, "application/json", reply);
    return;
  }
  char tag[40], pub[24];
  strncpy(tag, r.tag, sizeof(tag) - 1); tag[sizeof(tag) - 1] = '\0';
  strncpy(pub, r.pub, sizeof(pub) - 1); pub[sizeof(pub) - 1] = '\0';
  const uint32_t image_size = r.image_size;
  webJobTake();

  {
    strncpy(gh_latest_version, tag, sizeof(gh_latest_version) - 1);
    gh_latest_version[sizeof(gh_latest_version) - 1] = '\0';
    const uint64_t remote = parseVersion(tag), running = parseVersion(FW_VERSION);
    // Newer but larger than this device's slot: not offered, the way to the
    // flasher instead - the same rule as the device's own check.
    const bool too_big = remote > running && !partitionImageFits(image_size);
    if (too_big) partitionNoteTooBig(tag, image_size);
    const bool newer = remote > running && !too_big;
    // Offered, not pushed. Someone who tested a pre-release and moved the
    // channel back is asking for the release below the running build, and the
    // page has to be able to say so rather than only "already up to date".
    const bool older = remote < running;
    // A check answers in both directions. Setting the badge but never clearing
    // it left it lit after a channel change that found something older, and
    // body() builds the Install button out of update_available - so the button
    // came back armed on a release below the running one.
    //
    // Not while the OTA screen is showing a result the user asked for, which
    // is the rule services/update_check.cpp states for the background check.
    if (newer || !otaGithubScreenVisible()) {
      update_available = newer;
      showUpdateBadges(newer);
    }
    s_check_ms  = millis() ? millis() : 1;   // 0 is reserved for "never"
    s_check_pre = gh_prerelease;
    s_check_new = newer;
    s_check_old = older;
    s_check_big = too_big;
    snprintf(s_check_pub, sizeof(s_check_pub), "%s", pub);
    logSDf("OTA check: web asked, latest %s%s", tag,
           newer ? " (newer)" : (older ? " (older)" : ""));
    srv.send(200, "application/json",
             "{\"ok\":true,\"tag\":\"" + jsonEsc(tag) +
             "\",\"installed\":\"" + jsonEsc(FW_VERSION) +
             "\",\"published\":\"" + jsonEsc(pub) +
             "\",\"update\":" + (newer ? "true" : "false") +
             ",\"older\":" + (older ? "true" : "false") +
             ",\"toobig\":" + (too_big ? "true" : "false") + "}");
  }
}

static void routesTail(WebServer &srv) {
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
    // A release a check found too large for the slot - this page's or the
    // device's - is refused here too, not only left without a button.
    if (s_check_big || partitionTagTooBig(gh_latest_version)) {
      srv.send(200, "application/json", "{\"ok\":false,\"error\":\"toobig\"}");
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
      const bool ok = s_upload_ok;
      s_upload_ok = false;
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
      // Decided at the first byte, not in the completion handler: by the time
      // that runs the image is already in flash. Everything webRequire() asks
      // - the gate, the host, the origin, the password, and no other flash in
      // progress - is asked here, and a refused upload is read and dropped so
      // the browser gets the proper answer from the completion handler.
      // refused: never started, the bytes are read and dropped. failed:
      // started and broken off - the same, but Update has been aborted.
      static bool refused = false;
      static bool failed  = false;
      HTTPUpload& upload = srv.upload();
      if (upload.status == UPLOAD_FILE_START) {
        s_upload_ok = false;
        failed  = false;
        refused = !webAllowed(srv, GATE_MAINT);
        if (refused) {
          logSD("OTA: upload refused before the first byte");
          return;
        }
        // Against the partition, before a byte is written. Update would find
        // out by itself, two megabytes later, with a write error.
        const size_t announced = srv.clientContentLength();
        const size_t room      = ESP.getFreeSketchSpace();
        if (announced > room + OTA_MULTIPART_SLACK) {
          refused = true;
          logSDf("OTA: upload of %u bytes refused, partition holds %u",
                 (unsigned)announced, (unsigned)room);
          return;
        }
        Serial.printf("OTA start: %s\n", upload.filename.c_str());
        ota_upload_active = true;
        if (Update.isRunning()) Update.abort();  // clean up any previous failed upload
        if (!Update.begin(UPDATE_SIZE_UNKNOWN)) {
          logSDf("OTA: begin() failed, error %u", (unsigned)Update.getError());
          ota_upload_active = false;
          failed = true;
          return;
        }
        // The multipart envelope adds a few hundred bytes on top of the
        // image. On a 1.9 MB upload that is under 0.05 %, so it serves as the
        // denominator; otaProgressLine() clamps the last stretch at 100.
        ota_upload_total = (srv.clientContentLength() > 0)
                           ? (uint32_t)srv.clientContentLength() : 0;
        ota_upload_done  = 0;
        ota_last_paint   = 0;
        // The whole screen says it, whatever screen was up: the upload holds
        // the loop, touch included, and a frozen home screen for two minutes
        // looked like a hung device (Nikolai, 26.09.2026).
        otaGithubOverlayShow();
        if (lbl_ota_status) lv_label_set_text(lbl_ota_status,
          T(STR_OTA_UPLOADING));
        lv_timer_handler();
      } else if (refused || failed) {
        if (upload.status == UPLOAD_FILE_END || upload.status == UPLOAD_FILE_ABORTED) {
          refused = false;
          failed  = false;
        }
      } else if (upload.status == UPLOAD_FILE_ABORTED) {
        // The browser tab closed, or the link dropped. The library reports
        // this and nothing here used to listen: ota_upload_active stayed set
        // for good, every OTA route answered "busy" and the daily check never
        // ran again until a reboot.
        Update.abort();
        ota_upload_active = false;
        ota_upload_done   = 0;
        ota_upload_total  = 0;
        otaGithubOverlayHide();
        logSD("OTA: upload aborted by the client");
        if (lbl_ota_status) lv_label_set_text(lbl_ota_status, T(STR_OTA_FAIL));
      } else if (upload.status == UPLOAD_FILE_WRITE) {
        if (Update.write(upload.buf, upload.currentSize) != upload.currentSize) {
          logSDf("OTA: write failed after %u bytes, error %u",
                 (unsigned)ota_upload_done, (unsigned)Update.getError());
          Update.abort();
          ota_upload_active = false;
          failed = true;
          otaGithubOverlayHide();
          if (lbl_ota_status) lv_label_set_text(lbl_ota_status, T(STR_OTA_FAIL));
          return;
        }
        ota_upload_done += upload.currentSize;
        // Same cadence as the GitHub path. Painting per chunk would cost more
        // than the write does.
        if (millis() - ota_last_paint >= OTA_PROGRESS_MS) {
          ota_last_paint = millis();
          otaGithubOverlayProgress(ota_upload_done, ota_upload_total);
          if (lbl_ota_status) {
            char line[48];
            otaProgressLine(line, sizeof(line), ota_upload_done, ota_upload_total);
            lv_label_set_text(lbl_ota_status, line);
            lv_refr_now(NULL);
          }
        }
      } else if (upload.status == UPLOAD_FILE_END) {
        ota_upload_active = false;
        // end(true), because the image size is only known now: the multipart
        // envelope hid it from begin(). The library still checks the image
        // header before it commits.
        s_upload_ok = Update.end(true) && !Update.hasError();
        if (s_upload_ok) {
          logSDf("OTA: browser upload complete, %u bytes", (unsigned)upload.totalSize);
        } else {
          otaGithubOverlayHide();
          logSDf("OTA: end() failed after %u bytes, error %u",
                 (unsigned)upload.totalSize, (unsigned)Update.getError());
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
