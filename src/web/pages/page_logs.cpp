// SD card log browser, and the endpoints it polls.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>
#include <SD.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "web/web_access.h"

static String body() {
  String html;
  html +=
      "<div class='card'>"
      "<h2>SD Card Logs</h2>"
      "<div id='log-list'><div class='no-sd'><div class='no-sd-hint'>Loading...</div></div></div>"
      "</div>"
      "<style>#log-entries{max-height:184px;overflow-y:auto}</style>"
      "<script>"
      "function loadLogs(){"
      "fetch('/api/logs').then(r=>r.json()).then(d=>{"
      "var c=document.getElementById('log-list');"
      "if(!d.sd){c.innerHTML="
      "\"<div class='no-sd'>\"+"
      "\"<div class='no-sd-title'>No SD card detected</div>\"+"
      "\"<div class='no-sd-hint'>Insert a FAT32-formatted SD card<br>\"+"
      "\"to enable diagnostic logging.<br>\"+"
      "\"<span style='font-size:11px;color:#2a5a40'>* Booting with SD card increases startup time by ~20 seconds.</span></div>\"+"
      "\"</div>\";return;}"
      "var h=\"<div class='sd-info-box'>\"+"
      "\"&#9432; SD card increases boot time by ~20 seconds. Use without SD for normal operation, insert only for debugging.</div>\"+"
      "\"<div class='verbose-row'>\"+"
      "\"<div><span class='verbose-label'>Verbose Logging</span>\"+"
      "\"<span class='verbose-state \"+(d.verbose?'verbose-on':'verbose-off')+\"'>\"+"
      "(d.verbose?'ON':'OFF')+\"</span></div>\"+"
      "\"<button class='btn-toggle' onclick='toggleVerbose()'>Toggle</button>\"+"
      "\"</div>\";"
      "if(d.files.length===0){"
      "h+=\"<div class='no-sd'>\"+"
      "\"<div class='no-sd-title'>No log files yet</div>\"+"
      "\"<div class='no-sd-hint'>Logs will appear here as you use the device.</div>\"+"
      "\"</div>\";"
      "}else{h+=\"<div class='section-divider'></div><div id='log-entries'>\";"
      "d.files.forEach(f=>{"
      "h+=\"<div class='log-row'><span class='log-name'>\"+f.name+\"</span>\"+"
      "\"<div class='log-actions'>\"+"
      "\"<a class='log-btn' href='/api/log?file=\"+encodeURIComponent(f.name)+\"' download='\"+f.name+\"'>Download</a>\"+"
      "\"<a class='log-btn log-btn-del' href='#' onclick=\\\"delLog('\"+f.name+\"');return false;\\\">Delete</a>\"+"
      "\"</div></div>\";});h+=\"</div>\";}"
      "c.innerHTML=h;});}"
      "function delLog(n){if(!confirm('Delete '+n+'?'))return;"
      "fetch('/deletelog?file='+encodeURIComponent(n),{method:'POST'}).then(()=>loadLogs());}"
      "function toggleVerbose(){"
      "fetch('/api/verbose',{method:'POST'}).then(r=>r.json()).then(d=>{"
      "loadLogs();"
      "if(d.verbose)alert('Verbose logging ENABLED. Reboot device for full effect.');"
      "else alert('Verbose logging DISABLED.');"
      "});}"
      "loadLogs();setInterval(loadLogs,30000);"
      "</script>";
  return html;
}

static void routes(WebServer &srv) {
  // ── SD-Card Log endpoints ─────────────────────────────────
  // GET /logs -> JSON list of available log files
  srv.on("/api/logs", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, "Logs")) return;
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
    if (!webRequire(srv, GATE_MAINT, "Logs")) return;
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
    if (!webRequire(srv, GATE_MAINT, "Logs")) return;
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
    if (!webRequire(srv, GATE_MAINT, "Logs")) return;
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
  "/logs", "Logs", nullptr, GATE_MAINT, nullptr,
  body, routes
};
