// The SD card log browser and the endpoints it polls.
#include "web/web_pages.h"

#include <Arduino.h>
#include <SD.h>
#include <WebServer.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

static const char* label() { return T(STR_W_NAV_LOGS); }

static String body() {
  String h;
  h.reserve(6500);
  h += F("<div class='grid'><div class='card wide'><h2>");
  h += T(STR_W_C_LOGS);
  h += F("</h2><div id='lg'></div>"
         "<div class='rows' style='margin-top:16px'><div class='row' id='vbrow'>"
         "<span class='k'>");
  h += T(STR_W_R_VERBOSE);
  h += F("</span><span class='v'>"
         "<button id='vb' class='quiet' onclick='toggleVerbose()'></button>"
         "</span></div><div class='row' id='darow'>"
         "<span class='k' id='dsum'></span>"
         "<span class='v'>"
         "<button id='da' class='danger' onclick='delAll()' disabled></button>"
         "</span></div></div><p class='note'>");
  h += T(STR_W_LOG_NOTE);
  h += F("</p></div>");

  // Kept separate from the card browser above: this one is always there,
  // with or without a card, and it is the only log most devices have.
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_C_SESSION);
  h += F("</h2><p class='note'>");
  h += T(STR_W_SESSION_NOTE);
  h += F("</p><pre id='sl' style='max-height:340px;overflow:auto;"
         "background:#06080f;border:1px solid #1a3060;border-radius:8px;"
         "padding:10px;font-size:12px;line-height:1.5;white-space:pre-wrap;"
         "word-break:break-word;margin:12px 0'></pre>"
         "<div style='display:flex;gap:12px;align-items:center'>"
         "<button id='slb' class='quiet' onclick='loadSession(true)'>");
  h += T(STR_W_SESSION_REFRESH);
  h += F("</button><button id='slc' class='quiet'>");
  h += T(STR_W_SESSION_COPY);
  h += F("</button><span id='sls' class='note' style='margin:0'></span>"
         "</div></div></div>");

  h += F("<script>const SESSION_EMPTY=");
  h += jsStr(T(STR_W_SESSION_EMPTY));
  h += F(",SESSION_BUSY=");    h += jsStr(T(STR_W_SESSION_BUSY));
  h += F(",SESSION_REFRESH="); h += jsStr(T(STR_W_SESSION_REFRESH));
  h += F(",SESSION_AT=");      h += jsStr(T(STR_W_SESSION_UPDATED));
  h += F(",SESSION_LINES=");   h += jsStr(T(STR_W_SESSION_LINES));
  h += F(",SESSION_PAUSED=");  h += jsStr(T(STR_W_SESSION_PAUSED));
  h += F(",SESSION_NEW=");     h += jsStr(T(STR_W_SESSION_NEW));
  h += F(",SESSION_COPY=");    h += jsStr(T(STR_W_SESSION_COPY));
  h += F(",SESSION_COPIED=");  h += jsStr(T(STR_W_SESSION_COPIED));
  h += F(",SESSION_COPYFAIL="); h += jsStr(T(STR_W_SESSION_COPYFAIL));
  h += F(";</script>");

  h += F("<script>const M={view:");
  h += jsStr(T(STR_W_LOG_VIEW));
  h += F(",del:");    h += jsStr(T(STR_W_LOG_DELETE));
  h += F(",ask:");    h += jsStr(T(STR_W_LOG_DELETE_ASK));
  h += F(",nosd:");   h += jsStr(T(STR_W_LOG_NOSD));
  h += F(",nosdh:");  h += jsStr(T(STR_W_LOG_NOSD_HINT));
  h += F(",empty:");  h += jsStr(T(STR_W_LOG_EMPTY));
  h += F(",on:");     h += jsStr(T(STR_W_S_ON));
  h += F(",off:");    h += jsStr(T(STR_W_S_OFF));
  h += F(",err:");    h += jsStr(T(STR_W_LOAD_FAIL));
  h += F(",all:");    h += jsStr(T(STR_W_LOG_DELETE_ALL));
  h += F(",allask:"); h += jsStr(T(STR_W_LOG_DELETE_ALL_ASK));
  h += F(",count:");  h += jsStr(T(STR_W_LOG_COUNT));
  h += F(",count1:"); h += jsStr(T(STR_W_LOG_COUNT_ONE));
  h += F(",allask1:");h += jsStr(T(STR_W_LOG_DELETE_ALL_ASK_ONE));
  h += F("};"
         "function kb(n){return n>=1048576?(n/1048576).toFixed(2)+' MB'"
         ":(n/1024).toFixed(0)+' KB';}"
         "function say(t){document.getElementById('lg').innerHTML="
         "'<div class=\"note\">'+t+'</div>';}"
         "var slSeq=0,slFollow=true,slPend=0,slAuto=false;"
         "function slNote(s,n){if(!s)return;"
         "s.textContent=slFollow?(SESSION_AT+' '+new Date().toLocaleTimeString()"
         "+' - '+n+' '+SESSION_LINES)"
         ":(SESSION_PAUSED+(slPend?' - '+slPend+' '+SESSION_NEW:''));}"
         "function loadSession(manual){"
         "var b=document.getElementById('slb'),s=document.getElementById('sls'),"
         "e=document.getElementById('sl');if(!e)return;"
         "if(manual){slFollow=true;slPend=0;}"
         "if(b&&manual){b.disabled=true;b.textContent=SESSION_BUSY;}"
         "var u='/api/log/session?since='+(manual?0:slSeq);"
         "fetch(u).then(r=>{slSeq=parseInt(r.headers.get('X-Log-Seq')||slSeq);"
         "var rst=r.headers.get('X-Log-Reset')==='1';"
         "return r.text().then(t=>({t:t,rst:rst}));}).then(d=>{"
         "var stick=slFollow;"
         "if(d.rst){e.textContent=d.t.trim()?d.t:SESSION_EMPTY;}"
         "else if(d.t){if(e.textContent===SESSION_EMPTY)e.textContent='';"
         "e.textContent+=d.t;if(!slFollow)slPend+=d.t.trim().split('\\n').length;}"
         "if(stick){slAuto=true;e.scrollTop=e.scrollHeight;}"
         "var all=e.textContent.trim();"
         "slNote(s,all&&all!==SESSION_EMPTY?all.split('\\n').length:0);"
         "}).catch(()=>{if(s)s.textContent='-';})"
         ".finally(()=>{if(b&&manual){b.disabled=false;b.textContent=SESSION_REFRESH;}});}"
         "function slCopy(){"
         "var e=document.getElementById('sl'),b=document.getElementById('slc');"
         "if(!e||!b)return;"
         "var txt=e.textContent||'';"
         "var done=function(ok){b.textContent=ok?SESSION_COPIED:SESSION_COPYFAIL;"
         "setTimeout(function(){b.textContent=SESSION_COPY;},1500);};"
         // navigator.clipboard only exists in a secure context. This page is
         // served over plain http on a LAN address, so it is undefined in
         // every current browser and the older path below is the one that
         // actually runs. The modern call stays first for the day the scale
         // is reached over https or through localhost.
         "if(navigator.clipboard&&window.isSecureContext){"
         "navigator.clipboard.writeText(txt).then(function(){done(true);},"
         "function(){done(false);});return;}"
         "var t=document.createElement('textarea');t.value=txt;"
         "t.setAttribute('readonly','');"
         "t.style.position='fixed';t.style.top='-1000px';"
         "document.body.appendChild(t);t.select();"
         "var ok=false;try{ok=document.execCommand('copy');}catch(err){ok=false;}"
         "document.body.removeChild(t);done(ok);}"
         "function slWatch(){var e=document.getElementById('sl');if(!e)return;"
         "var c=document.getElementById('slc');"
         "if(c)c.addEventListener('click',slCopy);"
         "e.addEventListener('scroll',function(){"
         "if(slAuto){slAuto=false;return;}"
         "if(slFollow){slFollow=false;"
         "slNote(document.getElementById('sls'),0);}});"
         "setInterval(function(){if(!document.hidden)loadSession(false);},3000);}"
         "function loadLogs(){fetch('/api/logs').then(r=>{"
         "if(!r.ok)throw 0;return r.json();}).then(d=>{"
         "const c=document.getElementById('lg');"
         "document.getElementById('vb').textContent=d.verbose?M.on:M.off;"
         "const da=document.getElementById('da');"
         "da.textContent=M.all;"
         // With nothing to delete the whole row goes, not just the button.
         // The rule that strips the border from the last row still counts a
         // display:none one, so hiding this one alone would leave the divider
         // under Verbose hanging into empty space.
         "const has=!!(d.files&&d.files.length);"
         "document.getElementById('darow').style.display=has?'':'none';"
         "document.getElementById('vbrow').style.borderBottom=has?'':'0';"
         "da.disabled=!has;"
         // Says what pressing it would free, which is the number someone
         // wants before pressing it rather than after.
         "const n=d.files?d.files.length:0;"
         "document.getElementById('dsum').textContent=n"
         "?(n===1?M.count1:M.count.replace('{n}',n))+' \u00b7 '"
         "+kb(d.files.reduce((s,f)=>s+f.size,0)):'';"
         // Sorted here rather than on the device: the browser already holds
         // the array. What arrives is FAT directory order, and the seven day
         // rotation frees entries that later files drop into, so it reads as
         // shuffled. Names are log_YYYY-MM-DD, which orders lexically the same
         // as chronologically.
         //
         // log_pre_ntp carries no date and is checked separately so it lands
         // at the bottom. The obvious shortcut - prefixing it with a low
         // character and letting one comparison handle both - does not work:
         // localeCompare ignores control characters and left it on top.
         "if(d.files)d.files.sort((a,b)=>{"
         "const A=a.name.startsWith('log_2'),B=b.name.startsWith('log_2');"
         "if(A!==B)return A?-1:1;"
         "return a.name<b.name?1:(a.name>b.name?-1:0);});"
         "if(!d.sd){c.innerHTML='<div class=\"note\"><b>'+M.nosd+'</b><br>'"
         "+M.nosdh+'</div>';return;}"
         "if(!d.files||!d.files.length){say(M.empty);return;}"
         "c.innerHTML=d.files.map(f=>"
         "'<div class=\"listrow\"><span class=\"nm\">'+f.name+'</span>'"
         "+'<span style=\"display:flex;align-items:center;gap:10px\">'"
         "+'<span class=\"sz\">'+kb(f.size)+'</span>'"
         "+'<a href=\"/api/log?file='+encodeURIComponent(f.name)+'\" target=\"_blank\">'"
         "+'<button class=\"quiet\">'+M.view+'</button></a>'"
         // The name rides in a data attribute and the handler is bound after
         // the rows exist. Threading it through an inline onclick quotes it
         // for C++, for a JS string, for an HTML attribute and for a JS call
         // in that order, and one backslash lost on the way took the entire
         // script block down without a word on the page.
         "+'<button class=\"danger\" data-del=\"'+f.name+'\">'+M.del+'</button>'"
         "+'</span></div>').join('');"
         "c.querySelectorAll('[data-del]').forEach(b=>"
         "b.onclick=()=>delLog(b.dataset.del));"
         "}).catch(()=>say(M.err));}"
         // Every fetch here ends in a catch. Without one a closed gate, a
         // dropped connection or a 403 arriving as text/plain died as a silent
         // rejection, and the card just stayed empty.
         "function delLog(n){if(!confirm(M.ask))return;"
         "fetch('/api/deletelog?file='+encodeURIComponent(n),{method:'POST'})"
         ".then(()=>loadLogs()).catch(()=>say(M.err));}"
         "function delAll(){"
         "const n=document.querySelectorAll('.listrow').length;"
         "if(!n||!confirm(n===1?M.allask1:M.allask.replace('{n}',n)))return;"
         "fetch('/api/deletelogs',{method:'POST'})"
         ".then(()=>loadLogs()).catch(()=>say(M.err));}"
         "function toggleVerbose(){fetch('/api/verbose',{method:'POST'})"
         ".then(r=>r.json()).then(d=>{"
         "document.getElementById('vb').textContent=d.verbose?M.on:M.off;})"
         ".catch(()=>say(M.err));}"
"loadLogs();loadSession(true);slWatch();"
         // Was in the page until beta.33 and fell out of the 720px rebuild
         // without anyone noticing. Back, but idle while the tab sits in the
         // background - a forgotten tab should not poll the scale all day.
         "setInterval(()=>{if(!document.hidden)loadLogs();},30000);"
         "document.addEventListener('visibilitychange',()=>"
         "{if(!document.hidden)loadLogs();});"
         "</script>");
  return h;
}

static void routes(WebServer &srv) {
  // ── SD-Card Log endpoints ─────────────────────────────────
  // GET /logs -> JSON list of available log files
  srv.on("/api/logs", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    if (!sd_available) {
      srv.send(200, "application/json", "{\"sd\":false,\"verbose\":false,\"files\":[]}");
      return;
    }
    String json = "{\"sd\":true,\"verbose\":";
    json += sd_verbose ? "true" : "false";
    json += ",\"files\":[";
    File root = SD.open("/");
    bool first = true;
    if (root && root.isDirectory()) {
      File entry = root.openNextFile();
      while (entry) {
        if (!entry.isDirectory()) {
          String name = entry.name();
          if (name.startsWith("/")) name = name.substring(1);
          if (name.startsWith("log_") && name.endsWith(".txt")) {
            if (!first) json += ",";
            json += "{\"name\":\"";
            json += name;
            json += "\",\"size\":";
            json += String((unsigned long)entry.size());
            json += "}";
            first = false;
          }
        }
        entry = root.openNextFile();
      }
      root.close();
    }
    json += "]}";
    srv.send(200, "application/json", json);
  });

  // GET /log?file=<filename> -> serve log file content
  srv.on("/api/log", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    if (!sd_available) { srv.send(404, "text/plain", "No SD card"); return; }
    if (!srv.hasArg("file")) {
      srv.send(400, "text/plain", "Missing file param");
      return;
    }
    String fname = srv.arg("file");
    // basic sanitization: only allow log_*.txt names
    if (!fname.startsWith("log_") || !fname.endsWith(".txt") || fname.indexOf("..") >= 0) {
      srv.send(400, "text/plain", "Invalid filename");
      return;
    }
    String path = "/" + fname;
    if (!SD.exists(path.c_str())) {
      srv.send(404, "text/plain", "Not found");
      return;
    }
    File f = SD.open(path.c_str(), FILE_READ);
    if (!f) { srv.send(500, "text/plain", "Open failed"); return; }
    srv.streamFile(f, "text/plain");
    f.close();
  });

  // POST /deletelog?file=<name> -> delete a log file
  srv.on("/api/deletelog", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    if (!sd_available) { srv.send(404, "text/plain", "No SD card"); return; }
    if (!srv.hasArg("file")) {
      srv.send(400, "text/plain", "Missing file param");
      return;
    }
    String fname = srv.arg("file");
    if (!fname.startsWith("log_") || !fname.endsWith(".txt") || fname.indexOf("..") >= 0) {
      srv.send(400, "text/plain", "Invalid filename");
      return;
    }
    String path = "/" + fname;
    if (SD.remove(path.c_str())) {
      // Deleting today's own log leaves the cap standing over a file that is
      // gone, so the count is dropped here too and not only in the delete-all.
      sdLogResetSize();
      logSDf("Log file deleted via web: %s", fname.c_str());
      srv.send(200, "text/plain", "OK");
    } else {
      srv.send(500, "text/plain", "Delete failed");
    }
  });

  // POST /deletelogs -> remove every log file at once
  srv.on("/api/deletelogs", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    if (!sd_available) { srv.send(404, "text/plain", "No SD card"); return; }

    // Same walk-and-remove as cleanOldLogs(): close the entry, remove it, then
    // ask for the next one. That pattern has been running in the rotation for
    // a long time, so it is not reinvented here.
    int deleted = 0;
    File root = SD.open("/");
    if (root && root.isDirectory()) {
      File entry = root.openNextFile();
      while (entry) {
        if (!entry.isDirectory()) {
          String name = entry.name();
          if (name.startsWith("/")) name = name.substring(1);
          if (name.startsWith("log_") && name.endsWith(".txt")) {
            entry.close();
            if (SD.remove(("/" + name).c_str())) deleted++;
            entry = root.openNextFile();
            continue;
          }
        }
        entry = root.openNextFile();
      }
      root.close();
    }

    // The cap counts bytes since boot, so without this the card is empty and
    // the writer stays mute until the next restart.
    sdLogResetSize();

    // Serial only, deliberately. logSDf() here would recreate today's file on
    // the spot, and a list that is supposed to be empty would come back
    // holding a fresh log with one line in it - which reads as a failure.
    Serial.printf("All logs deleted via web: %d file(s)\n", deleted);

    srv.send(200, "application/json", String("{\"deleted\":") + deleted + "}");
  });

  // The ring buffer, oldest line first. Streamed rather than built into one
  // String: 240 lines is 38 kB, and this handler runs on the internal heap.
  srv.on("/api/log/session", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    // A reader that says where it got to is sent only what came after, which
    // is almost always nothing. Without that, following the log would push the
    // whole ring through the loop every few seconds to say the same thing.
    const uint32_t seq    = logRingSeq();
    const uint32_t oldest = seq - (uint32_t)logRingCount();
    uint32_t since = 0;
    bool have_since = srv.hasArg("since");
    if (have_since) since = (uint32_t)strtoul(srv.arg("since").c_str(), nullptr, 10);
    // A cursor older than the ring means lines were missed. Say so, and send
    // everything: the alternative is a gap the reader cannot see.
    const bool stale = have_since && since < oldest;
    if (!have_since || stale) since = oldest;

    srv.sendHeader("X-Log-Seq", String(seq));
    srv.sendHeader("X-Log-Reset", (!have_since || stale) ? "1" : "0");
    srv.setContentLength(CONTENT_LENGTH_UNKNOWN);
    srv.send(200, "text/plain", "");
    char line[176], out[200];
    for (uint32_t q = since; q < seq; q++) {
      time_t when = 0;
      uint32_t up = 0;
      if (!logRingGetSeq(q, line, sizeof(line), &when, &up)) continue;
      char stamp[16];
      if (when) {
        // The device already runs in the owner's zone, so localtime_r is the
        // whole of it: no borrowing the C library's zone per line, and no
        // second setting that can disagree with the clock.
        struct tm t;
        localtime_r(&when, &t);
        snprintf(stamp, sizeof(stamp), "%02d:%02d:%02d",
                 t.tm_hour, t.tm_min, t.tm_sec);
      } else {
        // Written before the clock was set. Uptime beats a wrong wall time.
        snprintf(stamp, sizeof(stamp), "+%lus", (unsigned long)up);
      }
      snprintf(out, sizeof(out), "[%s] %s\n", stamp, line);
      srv.sendContent(out);
    }
    srv.sendContent("");
  });

  // POST /verbose -> toggle verbose.txt on SD root
  srv.on("/api/verbose", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    if (!sd_available) {
      srv.send(404, "application/json", "{\"error\":\"No SD card\"}");
      return;
    }
    if (sd_verbose) {
      // currently ON -> remove file
      if (SD.remove("/verbose.txt")) {
        sd_verbose = false;
        logSD("Verbose logging: DISABLED via web");
        srv.send(200, "application/json", "{\"verbose\":false}");
      } else {
        srv.send(500, "application/json", "{\"error\":\"Failed to remove verbose.txt\"}");
      }
    } else {
      // currently OFF -> create file
      File f = SD.open("/verbose.txt", FILE_WRITE);
      if (f) {
        f.println("Verbose logging marker. Delete this file to disable verbose mode.");
        f.close();
        sd_verbose = true;
        logSD("Verbose logging: ENABLED via web");
        srv.send(200, "application/json", "{\"verbose\":true}");
      } else {
        srv.send(500, "application/json", "{\"error\":\"Failed to create verbose.txt\"}");
      }
    }
  });
}

extern const WebPage PAGE_LOGS;
const WebPage PAGE_LOGS = {
  "/logs", label, GATE_MAINT, nullptr,
  body, routes
};
