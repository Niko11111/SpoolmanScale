// The log browser - the files on the card and the ring in flash - and the
// endpoints it polls.
#include "web/web_pages.h"

#include <Arduino.h>
#include <SD.h>
#include <WebServer.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "hardware/flash_log.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

static const char* label() { return T(STR_W_NAV_LOGS); }

// Lines leave the ring in chunks rather than one String: two megabytes of log
// would not fit on the internal heap this handler runs on.
#define RING_OUT_CHUNK 1024
struct RingOut { WebServer *srv; String buf; };
static void ringOutLine(const char *line, void *ctx) {
  RingOut *out = (RingOut *)ctx;
  out->buf += line;
  out->buf += '\n';
  if (out->buf.length() >= RING_OUT_CHUNK) {
    out->srv->sendContent(out->buf);
    out->buf = "";
  }
}

static String body() {
  String h;
  h.reserve(7000);
  h += F("<div class='grid'><div class='card wide'><h2>");
  h += T(STR_W_C_LOGS);
  h += F("</h2>");
  // The two settings first, then what came out of them. Both are a strip of
  // buttons rather than a switch: the destination has three states now, and
  // two controls that look the same read better than one switch beside one
  // strip.
  h += F("<div class='k' style='margin-bottom:6px'>");
  h += T(STR_W_R_LOGDEST);
  h += F("</div><div class='btabs' id='dst' style='margin-bottom:16px'>"
         "<button class='btab' data-d='0'>");
  h += T(STR_W_S_DEST_OFF);
  h += F("</button><button class='btab' data-d='1'>");
  h += T(STR_W_S_DEST_SD);
  h += F("</button><button class='btab' data-d='2'>");
  h += T(STR_W_S_DEST_INT);
  h += F("</button></div><div class='k' style='margin-bottom:6px'>");
  h += T(STR_W_R_LOGLVL);
  h += F("</div><div class='btabs' id='lvl' style='margin-bottom:6px'>"
         "<button class='btab' data-l='0'>");
  h += T(STR_W_S_LVL_MIN);
  h += F("</button><button class='btab' data-l='1'>");
  h += T(STR_W_S_LVL_NORM);
  h += F("</button><button class='btab' data-l='2'>");
  h += T(STR_W_S_LVL_VERB);
  h += F("</button></div><p class='note'>");
  h += T(STR_W_LOG_INT_NOTE);
  h += F("</p><div class='btabs' id='flt' style='margin:16px 0 12px'>"
         "<button class='btab on' data-f='all'>");
  h += T(STR_W_LOG_SRC_ALL);
  h += F("</button><button class='btab' data-f='int'>");
  h += T(STR_W_S_DEST_INT);
  h += F("</button><button class='btab' data-f='sd'>");
  h += T(STR_W_S_DEST_SD);
  h += F("</button></div><div id='lg'></div>"
         "<div class='rows' style='margin-top:16px'><div class='row' id='darow'>"
         "<span class='k' id='dsum'></span>"
         "<span class='v'>"
         "<button id='da' class='danger' disabled></button>"
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
  h += F(",dl:");      h += jsStr(T(STR_W_LOG_DOWNLOAD));
  h += F(",del:");     h += jsStr(T(STR_W_LOG_DELETE));
  h += F(",ask:");     h += jsStr(T(STR_W_LOG_DELETE_ASK));
  h += F(",nosd:");    h += jsStr(T(STR_W_LOG_NOSD));
  h += F(",nosdh:");   h += jsStr(T(STR_W_LOG_NOSD_HINT));
  h += F(",empty:");   h += jsStr(T(STR_W_LOG_EMPTY));
  h += F(",err:");     h += jsStr(T(STR_W_LOAD_FAIL));
  h += F(",all:");     h += jsStr(T(STR_W_LOG_DELETE_ALL));
  h += F(",allask:");  h += jsStr(T(STR_W_LOG_DELETE_ALL_ASK));
  h += F(",count:");   h += jsStr(T(STR_W_LOG_COUNT));
  h += F(",count1:");  h += jsStr(T(STR_W_LOG_COUNT_ONE));
  h += F(",allask1:"); h += jsStr(T(STR_W_LOG_DELETE_ALL_ASK_ONE));
  h += F(",intname:"); h += jsStr(T(STR_W_LOG_INTERNAL));
  h += F(",linesof:"); h += jsStr(T(STR_W_LOG_LINES_OF));
  h += F(",intnone:"); h += jsStr(T(STR_W_LOG_INT_NONE));
  h += F("};"
         "function kb(n){return n>=1048576?(n/1048576).toFixed(2)+' MB'"
         ":(n/1024).toFixed(0)+' KB';}"
         "function say(t){document.getElementById('lg').innerHTML="
         "'<div class=\"note\">'+t+'</div>';}"
         "var slSeq=0,slFollow=true,slPend=0,slAuto=false,flt='all',last=null;"
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
         // The active choice is the one that is disabled, the way the backend
         // page marks its tabs. A destination the device cannot reach - no
         // card in, or no data partition - is dimmed and refuses the press
         // rather than being hidden: it says the option exists.
         "function paint(d){"
         "document.querySelectorAll('#dst .btab').forEach(function(b){"
         "var v=+b.dataset.d,na=(v===1&&!d.sd)||(v===2&&!d.int_ready);"
         "b.classList.toggle('on',v===d.dest);"
         "b.disabled=na||v===d.dest;b.style.opacity=na?'0.45':'';});"
         "document.querySelectorAll('#lvl .btab').forEach(function(b){"
         "var v=+b.dataset.l;b.classList.toggle('on',v===d.lvl);"
         "b.disabled=v===d.lvl;});"
         "document.querySelectorAll('#flt .btab').forEach(function(b){"
         "b.classList.toggle('on',b.dataset.f===flt);"
         "b.disabled=b.dataset.f===flt;});}"
         // One row for the ring in flash, then the files on the card. The
         // ring has no name and no date, so it carries its fill instead.
         "function intRow(d){"
         "return '<div class=\"listrow\"><span class=\"nm\">'+M.intname+'</span>'"
         "+'<span style=\"display:flex;align-items:center;gap:10px\">'"
         "+'<span class=\"sz\">'+M.linesof.replace('{a}',d.int_lines)"
         ".replace('{b}',d.int_max)+'</span>'"
         "+'<a href=\"/api/log?src=int\" target=\"_blank\">'"
         "+'<button class=\"quiet\">'+M.view+'</button></a>'"
         "+'<a href=\"/api/log?src=int&dl=1\" download=\"spoolmanscale-internal.txt\">'"
         "+'<button class=\"quiet\">'+M.dl+'</button></a>'"
         "+'<button class=\"danger\" data-cint=\"1\">'+M.del+'</button>'"
         "+'</span></div>';}"
         "function fileRow(f){"
         "return '<div class=\"listrow\"><span class=\"nm\">'+f.name+'</span>'"
         "+'<span style=\"display:flex;align-items:center;gap:10px\">'"
         "+'<span class=\"sz\">'+kb(f.size)+'</span>'"
         "+'<a href=\"/api/log?file='+encodeURIComponent(f.name)+'\" target=\"_blank\">'"
         "+'<button class=\"quiet\">'+M.view+'</button></a>'"
         // No target=_blank on this one: a new tab suppresses the download
         // hint in some browsers. The download attribute and the header the
         // route sends say the same thing twice, on purpose.
         "+'<a href=\"/api/log?dl=1&file='+encodeURIComponent(f.name)"
         "+'\" download=\"'+f.name+'\">'"
         "+'<button class=\"quiet\">'+M.dl+'</button></a>'"
         // The name rides in a data attribute and the handler is bound after
         // the rows exist. Threading it through an inline onclick quotes it
         // for C++, for a JS string, for an HTML attribute and for a JS call
         // in that order, and one backslash lost on the way took the entire
         // script block down without a word on the page.
         "+'<button class=\"danger\" data-del=\"'+f.name+'\">'+M.del+'</button>'"
         "+'</span></div>';}"
         "function render(){var d=last;if(!d)return;"
         "const c=document.getElementById('lg');"
         "paint(d);"
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
         "var fs=(d.files||[]).slice().sort((a,b)=>{"
         "const A=a.name.startsWith('log_2'),B=b.name.startsWith('log_2');"
         "if(A!==B)return A?-1:1;"
         "return a.name<b.name?1:(a.name>b.name?-1:0);});"
         "var html='';"
         "if(flt!=='sd'&&d.int_ready)html+=intRow(d);"
         "if(flt!=='int')html+=fs.map(fileRow).join('');"
         "var da=document.getElementById('da');da.textContent=M.all;"
         // With nothing to delete the whole row goes, not just the button.
         "var n=(flt==='int')?0:fs.length;"
         "document.getElementById('darow').style.display=n?'':'none';"
         "da.disabled=!n;"
         // Says what pressing it would free, which is the number someone
         // wants before pressing it rather than after.
         "document.getElementById('dsum').textContent=n"
         "?(n===1?M.count1:M.count.replace('{n}',n))+' · '"
         "+kb(fs.reduce((s,f)=>s+f.size,0)):'';"
         "if(!html){"
         "c.innerHTML=(!d.sd&&!d.int_ready)"
         "?'<div class=\"note\"><b>'+M.nosd+'</b><br>'+M.nosdh+'</div>'"
         ":'<div class=\"note\">'+M.empty+'</div>';return;}"
         "c.innerHTML=html;"
         "c.querySelectorAll('[data-del]').forEach(b=>"
         "b.onclick=()=>delLog(b.dataset.del));"
         "c.querySelectorAll('[data-cint]').forEach(b=>b.onclick=clearInt);}"
         // getJson resolves with null instead of rejecting, which is how a
         // closed gate answering 403 as text/plain is handled here.
         "function loadLogs(){return getJson('/api/logs').then(d=>{"
         "if(!d){say(M.err);return;}last=d;render();});}"
         "function delLog(n){if(!confirm(M.ask))return;"
         "post('/api/deletelog?file='+encodeURIComponent(n),'').then(loadLogs);}"
         "function clearInt(){if(!confirm(M.ask))return;"
         "post('/api/deletelogs?src=int','').then(loadLogs);}"
         "function delAll(){"
         "var n=document.querySelectorAll('[data-del]').length;"
         "if(!n||!confirm(n===1?M.allask1:M.allask.replace('{n}',n)))return;"
         "post('/api/deletelogs?src=sd','').then(loadLogs);}"
         // Reloads rather than trusting its own answer: a destination can
         // fall back on the device, and the strip has to show where the lines
         // really go, not where they were asked to go.
         "function setDest(v){post('/api/logdest?d='+v,'').then(loadLogs);}"
         "function setLvl(v){post('/api/loglevel?l='+v,'').then(loadLogs);}"
         "function bind(){"
         "document.querySelectorAll('#dst .btab').forEach(function(b){"
         "b.addEventListener('click',function(){setDest(+b.dataset.d);});});"
         "document.querySelectorAll('#lvl .btab').forEach(function(b){"
         "b.addEventListener('click',function(){setLvl(+b.dataset.l);});});"
         "document.querySelectorAll('#flt .btab').forEach(function(b){"
         "b.addEventListener('click',function(){flt=b.dataset.f;render();});});"
         "var da=document.getElementById('da');"
         "if(da)da.addEventListener('click',delAll);}"
         "bind();loadLogs();loadSession(true);slWatch();"
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
    // Both stores in one answer: the page draws one list and one set of
    // switches, so asking twice would only let the two disagree.
    String json = "{\"sd\":";
    json += sd_available ? "true" : "false";
    json += ",\"dest\":";     json += String((int)logDestStored());
    json += ",\"dest_eff\":"; json += String((int)logDestEffective());
    json += ",\"lvl\":";      json += String((int)logLevel());
    json += ",\"int_ready\":";
    json += flashLogAvailable() ? "true" : "false";
    json += ",\"int_lines\":"; json += String((unsigned long)flashLogLines());
    json += ",\"int_max\":";   json += String((unsigned long)FLASH_LOG_LINE_CAPACITY);
    json += ",\"int_used\":";  json += String((unsigned long)flashLogUsedBytes());
    json += ",\"files\":[";
    bool first = true;
    if (sd_available) {
      File root = SD.open("/");
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
    }
    json += "]}";
    srv.send(200, "application/json", json);
  });

  // GET /log?file=<filename> -> serve log file content
  srv.on("/api/log", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    // The ring in flash has no file name, so it is asked for by source alone
    // and streamed the way the session log is: it can be two megabytes, and
    // this handler runs on the internal heap.
    if (srv.arg("src") == "int") {
      if (!flashLogAvailable()) { srv.send(404, "text/plain", "No internal storage"); return; }
      if (srv.hasArg("dl")) {
        srv.sendHeader("Content-Disposition",
                       "attachment; filename=\"spoolmanscale-internal.txt\"");
      }
      srv.setContentLength(CONTENT_LENGTH_UNKNOWN);
      srv.send(200, "text/plain", "");
      RingOut out{&srv, String()};
      out.buf.reserve(RING_OUT_CHUNK + 256);
      flashLogEmit(ringOutLine, &out);
      if (out.buf.length()) srv.sendContent(out.buf);
      srv.sendContent("");
      return;
    }
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
    // Same file either way; the header is the whole difference between reading
    // it in the browser and saving it. text/plain renders inline everywhere,
    // so without this there is no way to get the file out of the device - the
    // download used to be a `download` attribute on the link and fell out with
    // the 720px rebuild. sendHeader() before streamFile() is honoured, the
    // same order the session route uses for X-Log-Seq below.
    if (srv.hasArg("dl")) {
      srv.sendHeader("Content-Disposition",
                     "attachment; filename=\"" + fname + "\"");
    }
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
    // Clearing the ring answers at once and erases in the background, a
    // sector per loop pass: erasing all 512 of them here would hold the
    // request, and the loop with it, for half a minute.
    if (srv.arg("src") == "int") {
      if (!flashLogAvailable()) { srv.send(404, "text/plain", "No internal storage"); return; }
      flashLogClear();
      Serial.println("Internal log cleared via web");
      srv.send(200, "application/json", "{\"deleted\":1}");
      return;
    }
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

  // POST /api/logdest?d=0|1|2 -> off, SD card, internal
  srv.on("/api/logdest", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    const int d = srv.arg("d").toInt();
    if (d < LOG_DEST_OFF || d > LOG_DEST_INTERNAL) {
      srv.send(400, "application/json", "{\"error\":\"Unknown destination\"}");
      return;
    }
    if (!logDestSet((LogDest)d)) {
      srv.send(500, "application/json", "{\"error\":\"Failed to store the setting\"}");
      return;
    }
    srv.send(200, "application/json",
             String("{\"dest\":") + (int)logDestStored() +
             ",\"dest_eff\":" + (int)logDestEffective() + "}");
  });

  // POST /api/loglevel?l=0|1|2 -> minimal, normal, verbose
  srv.on("/api/loglevel", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    const int l = srv.arg("l").toInt();
    if (l < LOG_LVL_MIN || l > LOG_LVL_VERBOSE) {
      srv.send(400, "application/json", "{\"error\":\"Unknown scope\"}");
      return;
    }
    if (!logLevelSet((LogLevel)l)) {
      srv.send(500, "application/json", "{\"error\":\"Failed to store the setting\"}");
      return;
    }
    srv.send(200, "application/json", String("{\"lvl\":") + (int)logLevel() + "}");
  });
}

extern const WebPage PAGE_LOGS;
const WebPage PAGE_LOGS = {
  "/logs", label, GATE_MAINT, nullptr,
  body, routes
};
