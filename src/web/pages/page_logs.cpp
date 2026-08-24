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
  h.reserve(3800);
  h += F("<div class='grid'><div class='card wide'><h2>");
  h += T(STR_W_C_LOGS);
  h += F("</h2><div id='lg'></div>"
         "<div class='rows' style='margin-top:16px'><div class='row'>"
         "<span class='k'>");
  h += T(STR_W_R_VERBOSE);
  h += F("</span><span class='v'>"
         "<button id='vb' class='quiet' onclick='toggleVerbose()'></button>"
         "</span></div></div><p class='note'>");
  h += T(STR_W_LOG_NOTE);
  h += F("</p></div></div>");

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
  h += F("};"
         "function kb(n){return n>=1048576?(n/1048576).toFixed(2)+' MB'"
         ":(n/1024).toFixed(0)+' KB';}"
         "function say(t){document.getElementById('lg').innerHTML="
         "'<div class=\"note\">'+t+'</div>';}"
         "function loadLogs(){fetch('/api/logs').then(r=>{"
         "if(!r.ok)throw 0;return r.json();}).then(d=>{"
         "const c=document.getElementById('lg');"
         "document.getElementById('vb').textContent=d.verbose?M.on:M.off;"
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
         "function toggleVerbose(){fetch('/api/verbose',{method:'POST'})"
         ".then(r=>r.json()).then(d=>{"
         "document.getElementById('vb').textContent=d.verbose?M.on:M.off;})"
         ".catch(()=>say(M.err));}"
         "loadLogs();"
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
      logSDf("Log file deleted via web: %s", fname.c_str());
      srv.send(200, "text/plain", "OK");
    } else {
      srv.send(500, "text/plain", "Delete failed");
    }
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
