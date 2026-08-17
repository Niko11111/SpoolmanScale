#include "ota_web_server.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <SD.h>
#include <Update.h>
#include <WebServer.h>
#include <lvgl.h>
#include <string.h>
#include <strings.h>

#include "app_config.h"
#include "drying_config.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/filaman_api.h"
#include "lang.h"
#include "list_limits.h"
#include "prefs_store.h"
#include "wifi_manager.h"


static WebServer ota_server(80);
static bool ota_server_running = false;
static bool ota_upload_active = false;

void stopOtaServer() {
  if (ota_server_running) {
    ota_server.stop();
    ota_server_running = false;
    Serial.println("OTA server stopped");
  }
}

void startOtaServer() {
  if (!wifi_ok) return;

  // Route: Startseite mit Upload-Formular
  ota_server.on("/", HTTP_GET, []() {
    char ver_buf[20];
    strncpy(ver_buf, FW_VERSION, sizeof(ver_buf)-1);
    String version = String(ver_buf);
    String html =
      "<!DOCTYPE html><html><head>"
      "<meta charset='utf-8'>"
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<title>SpoolmanScale - Firmware Update</title>"
      "<style>"
      "*{box-sizing:border-box;margin:0;padding:0}"
      "body{background:#06080f;color:#e8f0ff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
      "min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:32px 16px}"
      ".logo{font-size:32px;font-weight:700;color:#28d49a;letter-spacing:-0.5px;margin-bottom:4px}"
      ".logo span{color:#e8f0ff}"
      ".version{font-size:13px;color:#2a4060;margin-bottom:32px}"
      ".card{background:#0c1828;border:1px solid #1a3060;border-radius:14px;padding:28px;"
      "width:100%;max-width:480px;margin-bottom:20px}"
      ".card h2{color:#28d49a;font-size:16px;font-weight:600;margin-bottom:16px;"
      "display:flex;align-items:center;gap:8px}"
      ".card h2::before{content:'';display:inline-block;width:3px;height:16px;"
      "background:#28d49a;border-radius:2px}"
      "input[type=file]{width:100%;padding:12px;background:#06080f;border:1px dashed #1a3060;"
      "border-radius:8px;color:#4a6fa0;font-size:14px;margin-bottom:16px;cursor:pointer}"
      "input[type=file]:hover{border-color:#28d49a}"
      ".btn-flash{width:100%;padding:14px;background:#1a3020;color:#40c080;"
      "border:1px solid #2a5030;border-radius:8px;font-size:16px;font-weight:600;"
      "cursor:pointer;transition:background .2s}"
      ".btn-flash:hover{background:#2a5030}"
      ".hint{font-size:12px;color:#2a4060;margin-top:10px;text-align:center}"
      ".log-row{display:flex;align-items:center;justify-content:space-between;"
      "padding:10px 12px;background:#06080f;border:1px solid #1a3060;border-radius:8px;"
      "margin-bottom:8px}"
      ".log-name{color:#c8d8f0;font-size:14px;font-family:monospace}"
      ".log-actions{display:flex;gap:6px}"
      ".log-btn{padding:6px 14px;background:#0a1828;color:#28d49a;border:1px solid #1a3060;"
      "border-radius:6px;font-size:13px;text-decoration:none;cursor:pointer}"
      ".log-btn:hover{background:#1a3060}"
      ".log-btn-del{color:#ff8080;border-color:#3a1010}"
      ".log-btn-del:hover{background:#3a1010}"
      ".sd-info-box{background:#090c0a;border-left:2px solid #1a3020;border-radius:0 4px 4px 0;"
      "padding:5px 10px;margin-bottom:10px;font-size:11px;color:#2a5040;line-height:1.5}"
      ".verbose-row{display:flex;align-items:center;justify-content:space-between;"
      "padding:10px 12px;background:#06080f;border:1px solid #1a3060;border-radius:8px;"
      "margin-bottom:12px}"
      ".verbose-label{color:#c8d8f0;font-size:14px}"
      ".verbose-state{display:inline-block;padding:3px 10px;border-radius:4px;"
      "font-size:12px;font-weight:600;margin-left:8px}"
      ".verbose-on{background:#1a3020;color:#40c080;border:1px solid #2a5030}"
      ".verbose-off{background:#1a1828;color:#4a6fa0;border:1px solid #2a3050}"
      ".btn-toggle{padding:6px 14px;background:#0a1828;color:#28d49a;border:1px solid #1a3060;"
      "border-radius:6px;font-size:13px;cursor:pointer;font-family:inherit}"
      ".btn-toggle:hover{background:#1a3060}"
      ".section-divider{height:1px;background:#1a3060;margin:12px 0}"
      ".no-sd{text-align:center;padding:24px 16px}"
      ".no-sd-title{color:#c8d8f0;font-size:15px;font-weight:600;margin-bottom:6px}"
      ".no-sd-hint{color:#4a6fa0;font-size:13px;line-height:1.5}"
      ".links{display:grid;grid-template-columns:1fr 1fr;gap:10px;width:100%;max-width:480px}"
      ".link-btn{display:flex;align-items:center;justify-content:center;gap:8px;"
      "padding:12px 16px;border-radius:10px;text-decoration:none;"
      "font-size:14px;font-weight:500;transition:opacity .2s;border:1px solid}"
      ".link-btn:hover{opacity:0.8}"
      ".link-kofi{background:#1a2800;color:#a0d840;border-color:#2a4010}"
      ".link-github{background:#0a1828;color:#28d49a;border-color:#1a3060}"
      ".link-discord{background:#12103a;color:#8090ff;border-color:#2a2860}"
      ".link-maker{background:#1a0a18;color:#c060e0;border-color:#2a1a38}"
      ".footer{margin-top:24px;font-size:11px;color:#1a3060;text-align:center}"
      "</style></head><body>"

      // Logo
      "<img src='data:image/jpeg;base64,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' style='width:120px;height:120px;border-radius:12px;margin-bottom:8px'>"
      "<div class='version'>" + version + " &nbsp;|&nbsp; Firmware Update</div>"

      "<div class='links' style='margin-bottom:20px'>"
      "<a class='link-btn link-kofi' href='https://ko-fi.com/formfollowsfunction' target='_blank'>"
      "&#9749; Ko-fi</a>"
      "<a class='link-btn link-github' href='https://github.com/Niko11111/SpoolmanScale' target='_blank'>"
      "&#9873; GitHub</a>"
      "<a class='link-btn link-discord' href='https://discord.gg/GzQzGa5pBG' target='_blank'>"
      "&#128172; Discord</a>"
      "<a class='link-btn link-maker' href='https://makerworld.com/de/@FormFollowsF/upload' target='_blank'>"
      "&#11088; MakerWorld</a>"
      "</div>"

      // Upload-Card
      "<div class='card'>"
      "<h2>Upload Firmware</h2>"
      "<form method='POST' action='/update' enctype='multipart/form-data'>"
      "<input type='file' name='firmware' accept='.bin' required>"
      "<button class='btn-flash' type='submit'>&#x2191;&nbsp; Flash Firmware</button>"
      "</form>"
      "<p class='hint'>Select SpoolmanScale vX.Y.Z.bin - device restarts automatically</p>"
      "</div>"

      // SD-Logs Card
      "<div class='card'>"
      "<h2>SD Card Logs</h2>"
      "<div id='log-list'><div class='no-sd'><div class='no-sd-hint'>Loading...</div></div></div>"
      "</div>"
      "<style>#log-entries{max-height:184px;overflow-y:auto}</style>"
      "<script>"
      "function loadLogs(){"
      "fetch('/logs').then(r=>r.json()).then(d=>{"
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
      "\"<a class='log-btn' href='/log?file=\"+encodeURIComponent(f.name)+\"' download='\"+f.name+\"'>Download</a>\"+"
      "\"<a class='log-btn log-btn-del' href='#' onclick=\\\"delLog('\"+f.name+\"');return false;\\\">Delete</a>\"+"
      "\"</div></div>\";});h+=\"</div>\";}"
      "c.innerHTML=h;});}"
      "function delLog(n){if(!confirm('Delete '+n+'?'))return;"
      "fetch('/deletelog?file='+encodeURIComponent(n),{method:'POST'}).then(()=>loadLogs());}"
      "function toggleVerbose(){"
      "fetch('/verbose',{method:'POST'}).then(r=>r.json()).then(d=>{"
      "loadLogs();"
      "if(d.verbose)alert('Verbose logging ENABLED. Reboot device for full effect.');"
      "else alert('Verbose logging DISABLED.');"
      "});}"
      "loadLogs();setInterval(loadLogs,30000);"
      "</script>"

      // List limits - combined, moved to end via JS or just keep at end
      // Drying Reminder card
      "<div class='card'>"
      "<h2>Drying Reminder - Material Thresholds</h2>"
      "<p style='font-size:12px;color:#4a6fa0;margin-bottom:6px'>Days until Yellow / Red warning per material. Sealed multiplier applies when storage is airtight.</p>"
      "<table id='dry-tbl' style='width:100%;border-collapse:collapse;font-size:14px;margin-bottom:14px'>"
      "<tr style='color:#4a6fa0;font-size:12px'><th style='text-align:left;padding:4px 6px'>Material</th>"
      "<th style='text-align:center;padding:4px 6px'>Yellow</th><th style='text-align:center;padding:4px 6px'>Red</th>"
      "<th style='text-align:center;padding:4px 6px'>Storage</th></tr>"
      // PLA
      "<tr><td style='padding:4px 6px;color:#e8f0ff'>PLA</td>"
      "<td><input class='dry-in' name='y_PLA' type='number' min='1' value='"+String(g_dry_mat_yellow[0])+"'></td>"
      "<td><input class='dry-in' name='r_PLA' type='number' min='1' value='"+String(g_dry_mat_red[0])+"'></td>"
      "<td style='text-align:center;white-space:nowrap'>"
      "<label style='font-size:11px;color:#4a6fa0;cursor:pointer;margin-right:8px'>"
      "<input type='radio' name='s_PLA' value='open' "+String(g_dry_mat_sealed[0]?"":"checked")+"> Open</label>"
      "<label style='font-size:11px;color:#28d49a;cursor:pointer'>"
      "<input type='radio' name='s_PLA' value='sealed' "+String(g_dry_mat_sealed[0]?"checked":"")+"> Sealed</label>"
      "</td></tr>"
      "<tr><td style='padding:4px 6px;color:#e8f0ff'>PETG</td>"
      "<td><input class='dry-in' name='y_PETG' type='number' min='1' value='"+String(g_dry_mat_yellow[1])+"'></td>"
      "<td><input class='dry-in' name='r_PETG' type='number' min='1' value='"+String(g_dry_mat_red[1])+"'></td>"
      "<td style='text-align:center;white-space:nowrap'>"
      "<label style='font-size:11px;color:#4a6fa0;cursor:pointer;margin-right:8px'>"
      "<input type='radio' name='s_PETG' value='open' "+String(g_dry_mat_sealed[1]?"":"checked")+"> Open</label>"
      "<label style='font-size:11px;color:#28d49a;cursor:pointer'>"
      "<input type='radio' name='s_PETG' value='sealed' "+String(g_dry_mat_sealed[1]?"checked":"")+"> Sealed</label>"
      "</td></tr>"
      "<tr><td style='padding:4px 6px;color:#e8f0ff'>ABS</td>"
      "<td><input class='dry-in' name='y_ABS' type='number' min='1' value='"+String(g_dry_mat_yellow[2])+"'></td>"
      "<td><input class='dry-in' name='r_ABS' type='number' min='1' value='"+String(g_dry_mat_red[2])+"'></td>"
      "<td style='text-align:center;white-space:nowrap'>"
      "<label style='font-size:11px;color:#4a6fa0;cursor:pointer;margin-right:8px'>"
      "<input type='radio' name='s_ABS' value='open' "+String(g_dry_mat_sealed[2]?"":"checked")+"> Open</label>"
      "<label style='font-size:11px;color:#28d49a;cursor:pointer'>"
      "<input type='radio' name='s_ABS' value='sealed' "+String(g_dry_mat_sealed[2]?"checked":"")+"> Sealed</label>"
      "</td></tr>"
      "<tr><td style='padding:4px 6px;color:#e8f0ff'>ASA</td>"
      "<td><input class='dry-in' name='y_ASA' type='number' min='1' value='"+String(g_dry_mat_yellow[3])+"'></td>"
      "<td><input class='dry-in' name='r_ASA' type='number' min='1' value='"+String(g_dry_mat_red[3])+"'></td>"
      "<td style='text-align:center;white-space:nowrap'>"
      "<label style='font-size:11px;color:#4a6fa0;cursor:pointer;margin-right:8px'>"
      "<input type='radio' name='s_ASA' value='open' "+String(g_dry_mat_sealed[3]?"":"checked")+"> Open</label>"
      "<label style='font-size:11px;color:#28d49a;cursor:pointer'>"
      "<input type='radio' name='s_ASA' value='sealed' "+String(g_dry_mat_sealed[3]?"checked":"")+"> Sealed</label>"
      "</td></tr>"
      "<tr><td style='padding:4px 6px;color:#e8f0ff'>TPU</td>"
      "<td><input class='dry-in' name='y_TPU' type='number' min='1' value='"+String(g_dry_mat_yellow[4])+"'></td>"
      "<td><input class='dry-in' name='r_TPU' type='number' min='1' value='"+String(g_dry_mat_red[4])+"'></td>"
      "<td style='text-align:center;white-space:nowrap'>"
      "<label style='font-size:11px;color:#4a6fa0;cursor:pointer;margin-right:8px'>"
      "<input type='radio' name='s_TPU' value='open' "+String(g_dry_mat_sealed[4]?"":"checked")+"> Open</label>"
      "<label style='font-size:11px;color:#28d49a;cursor:pointer'>"
      "<input type='radio' name='s_TPU' value='sealed' "+String(g_dry_mat_sealed[4]?"checked":"")+"> Sealed</label>"
      "</td></tr>"
      "<tr><td style='padding:4px 6px;color:#e8f0ff'>PA</td>"
      "<td><input class='dry-in' name='y_PA' type='number' min='1' value='"+String(g_dry_mat_yellow[5])+"'></td>"
      "<td><input class='dry-in' name='r_PA' type='number' min='1' value='"+String(g_dry_mat_red[5])+"'></td>"
      "<td style='text-align:center;white-space:nowrap'>"
      "<label style='font-size:11px;color:#4a6fa0;cursor:pointer;margin-right:8px'>"
      "<input type='radio' name='s_PA' value='open' "+String(g_dry_mat_sealed[5]?"":"checked")+"> Open</label>"
      "<label style='font-size:11px;color:#28d49a;cursor:pointer'>"
      "<input type='radio' name='s_PA' value='sealed' "+String(g_dry_mat_sealed[5]?"checked":"")+"> Sealed</label>"
      "</td></tr>"
      "<tr><td style='padding:4px 6px;color:#e8f0ff'>PC</td>"
      "<td><input class='dry-in' name='y_PC' type='number' min='1' value='"+String(g_dry_mat_yellow[6])+"'></td>"
      "<td><input class='dry-in' name='r_PC' type='number' min='1' value='"+String(g_dry_mat_red[6])+"'></td>"
      "<td style='text-align:center;white-space:nowrap'>"
      "<label style='font-size:11px;color:#4a6fa0;cursor:pointer;margin-right:8px'>"
      "<input type='radio' name='s_PC' value='open' "+String(g_dry_mat_sealed[6]?"":"checked")+"> Open</label>"
      "<label style='font-size:11px;color:#28d49a;cursor:pointer'>"
      "<input type='radio' name='s_PC' value='sealed' "+String(g_dry_mat_sealed[6]?"checked":"")+"> Sealed</label>"
      "</td></tr>"
      "</table>"
      "<div style='display:flex;gap:10px;align-items:center;margin-bottom:10px'>"
      "<label style='font-size:13px;color:#c8d8f0'>Sealed multiplier:</label>"
      "<input id='dry-mult' type='number' min='1' max='10' step='0.1' value='"+String(g_dry_mult_sealed,1)+"'"
      " style='width:72px;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;"
      "border-radius:8px;padding:6px 10px;font-size:15px'>"
      "<span style='font-size:12px;color:#4a6fa0'>x (airtight storage)</span>"
      "</div>"
      "<div style='display:flex;gap:10px'>"
      "<button class='btn-toggle' onclick='saveDry()'>Save</button>"
      "<button class='btn-toggle' style='background:#1a0a0a;border-color:#402020;color:#e04040' onclick='resetDry()'>Reset to Defaults</button>"
      "<span id='dry-s' style='font-size:12px;color:#28d49a;line-height:36px;display:inline-block'></span>"
      "</div></div>"
      "<style>.dry-in{width:64px;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;"
      "border-radius:6px;padding:4px 8px;font-size:14px;text-align:center}</style>"
      "<script>"
      "function setLocL(){""var v=parseInt(document.getElementById('locl-in').value);""if(v<5)v=5;if(v>100)v=100;""fetch('/loclimit',{method:'POST',body:String(v)})"".then(r=>r.json()).then(d=>{""document.getElementById('locl-s').textContent='Saved: '+d.limit;""setTimeout(()=>{document.getElementById('locl-s').textContent='';},3000);""});}""function setLL(){"
      "var v=parseInt(document.getElementById('ll-in').value);"
      "if(v<5)v=5;if(v>100)v=100;"
      "fetch('/listlimit',{method:'POST',body:String(v)})"
      ".then(r=>r.json()).then(d=>{"
      "document.getElementById('ll-s').textContent='Saved: '+d.limit;"
      "setTimeout(()=>{document.getElementById('ll-s').textContent='';},3000);"
      "});}"
      "function saveDry(){"
      "var mats=['PLA','PETG','ABS','ASA','TPU','PA','PC'];"
      "var arr=mats.map(function(m){"
      "var sr=document.querySelector('[name=s_'+m+'][value=sealed]');"
      "return{name:m,"
      "yellow:parseInt(document.querySelector('[name=y_'+m+']').value)||1,"
      "red:parseInt(document.querySelector('[name=r_'+m+']').value)||1,"
      "sealed:sr?sr.checked:false};"
      "});"
      "var mult=parseFloat(document.getElementById('dry-mult').value)||1;"
      "fetch('/drying',{method:'POST',"
      "headers:{'Content-Type':'application/json'},"
      "body:JSON.stringify({mult_sealed:mult,materials:arr})})"
      ".then(r=>r.json()).then(d=>{"
      "document.getElementById('dry-s').textContent=d.ok?'Saved!':'Error';"
      "setTimeout(()=>{document.getElementById('dry-s').textContent='';},3000);"
      "});}"
      "function resetDry(){"
      "fetch('/drying/reset',{method:'POST'})"
      ".then(r=>r.json()).then(d=>{"
      "document.getElementById('dry-s').textContent='Reset!';"
      "setTimeout(()=>location.reload(),1500);"
      "});}"
      "</script>"
      // FilaMan credentials. Only emitted in FilaMan mode, so the block is
      // not merely hidden but never built and never sent. Saves heap on the
      // ESP32 and keeps the page free of options that do not apply.
      + (backendIsFilaMan() ? String(
      "<div class='card'>"
      "<h2>FilaMan</h2>"
      "<p style='font-size:12px;color:#4a6fa0;margin-bottom:14px'>"
      "The scale needs two credentials. The <b>device token</b> identifies it when "
      "reporting weights, the <b>API key</b> is used for everything else. "
      "<span onclick=\"h('p')\" style='cursor:pointer;color:#28d49a;border:1px solid #28d49a;"
      "border-radius:50%;padding:0 6px;font-size:11px'>?</span> "
      "Tip for a tighter setup.</p>"
      "<div id='h-p' style='display:none;font-size:12px;color:#8ab0d8;background:#06080f;"
      "border-left:2px solid #28d49a;border-radius:4px;padding:10px 12px;margin-bottom:14px'>"
      "An API key has no permissions of its own. It inherits them from the user who "
      "created it, so a key made from an admin account can do everything that account "
      "can. If you would rather keep that narrow:<br><br>"
      "1. Create a new FilaMan user without admin rights.<br>"
      "2. Create a role and give it at least these permissions:<br>"
      "&nbsp;&nbsp;<b>Read</b> spools:read, spool_events:read, locations:read, "
      "filaments:read, manufacturers:read<br>"
      "&nbsp;&nbsp;<b>Write</b> spools:update, spools:create, spools:archive, "
      "spools:move_location, filaments:update, manufacturers:update<br>"
      "3. Assign the role to that user.<br>"
      "4. Sign in <i>as that user</i> and create the API key there. A role has no "
      "effect on a key created by somebody else.<br><br>"
      "SpoolmanScale never deletes anything and never calls an admin endpoint. "
      "Weight reports go through the device token, not the key.<br><br>"
      "<i>The list is derived from the endpoints the firmware calls. It has not been "
      "verified against a restricted account yet, so if something stops working, "
      "widen the role and please report it.</i></div>"
      "<div style='margin-bottom:12px'>"
      "<label style='font-size:13px;color:#c8d8f0;display:block;margin-bottom:6px'>"
      "API key - create it in FilaMan under API keys "
      "<span onclick=\"h('k')\" style='cursor:pointer;color:#28d49a;border:1px solid #28d49a;"
      "border-radius:50%;padding:0 6px;font-size:11px;margin-left:4px'>?</span></label>"
      "<div id='h-k' style='display:none;font-size:12px;color:#8ab0d8;background:#06080f;"
      "border-left:2px solid #28d49a;border-radius:4px;padding:8px 10px;margin-bottom:8px'>"
      "Open FilaMan in another tab. At the bottom of the left sidebar there is a gear icon. "
      "Click it, choose <b>API keys</b>, and create a new key. Copy the value it shows you "
      "right away, FilaMan will not display it a second time.</div>"
      "<div style='display:flex;gap:10px;align-items:center'>"
      "<input id='fm-key' type='password' placeholder='uak.1....' value='"
      + String(filamanApiKey()[0] ? "________________" : "") + "'"
      " style='flex:1;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;"
      "border-radius:8px;padding:8px 10px;font-size:14px'>"
      "<button class='btn-toggle' onclick='setKey()'>Save</button>"
      "</div>"
      "<span id='fm-key-s' style='font-size:12px;color:#28d49a'></span>"
      "</div>"
      "<div>"
      "<label style='font-size:13px;color:#c8d8f0;display:block;margin-bottom:6px'>"
      "Device code - 6 characters from FilaMan admin. Current token: "
      + String(filamanDeviceToken()[0] ? "set" : "missing")
      + "<span onclick=\"h('d')\" style='cursor:pointer;color:#28d49a;border:1px solid #28d49a;"
      "border-radius:50%;padding:0 6px;font-size:11px;margin-left:4px'>?</span></label>"
      "<div id='h-d' style='display:none;font-size:12px;color:#8ab0d8;background:#06080f;"
      "border-left:2px solid #28d49a;border-radius:4px;padding:8px 10px;margin-bottom:8px'>"
      "In FilaMan go to the <b>Admin</b> area and open <b>Devices</b>. Add a new device there. "
      "FilaMan then shows a 6 character code. Enter it below and press Register device. "
      "Each code can only be used once, so if it is refused, have FilaMan issue a fresh one."
      "</div>"
      "<div style='display:flex;gap:10px;align-items:center'>"
      "<input id='fm-code' type='text' maxlength='6' placeholder='AA5354'"
      " style='width:110px;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;"
      "border-radius:8px;padding:8px 10px;font-size:16px;letter-spacing:2px'>"
      "<button class='btn-toggle' onclick='reg()'>Register device</button>"
      "</div>"
      "<span id='fm-reg-s' style='font-size:12px;color:#28d49a'></span>"
      "</div></div>"
      "<script>"
      // Both credentials sit in places of FilaMan that are easy to miss, so
      // each has a question mark that folds a short pointer open.
      "function h(i){var e=document.getElementById('h-'+i);"
      "e.style.display=(e.style.display==='none'?'block':'none');}"
      "function setKey(){var v=document.getElementById('fm-key').value;"
      "if(v.indexOf('_')===0){return;}"
      "fetch('/filaman/key',{method:'POST',body:v})"
      ".then(r=>r.text()).then(t=>{document.getElementById('fm-key-s').textContent=t;});}"
      "function reg(){var c=document.getElementById('fm-code').value;"
      "document.getElementById('fm-reg-s').textContent='Registering...';"
      "fetch('/filaman/register',{method:'POST',body:c})"
      ".then(r=>r.text()).then(t=>{document.getElementById('fm-reg-s').textContent=t;});}"
      "</script>") : String("")) +
      // List Limits combined card - at bottom
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
      "</div></div></div>"
      // Both are named regardless of the active mode. This device is called
      // SpoolmanScale, so in FilaMan mode a disclaimer that mentions only
      // FilaMan would leave out the very name that could suggest an
      // affiliation. Not a place to be clever with backendName().
      "<div class='footer'>Not affiliated with Spoolman or FilaMan - Open Source Project</div>"
      "</body></html>";
    ota_server.send(200, "text/html", html);
  });

  // Route: Upload verarbeiten
  ota_server.on("/update", HTTP_POST,
    // Abschluss-Handler
    []() {
      bool ok = !Update.hasError();
      String msg = ok
        ? "<!DOCTYPE html><html><head><meta charset='utf-8'>"
          "<meta http-equiv='refresh' content='5;url=/'>"
          "<style>body{background:#06080f;color:#28d49a;font-family:-apple-system,sans-serif;"
          "display:flex;flex-direction:column;align-items:center;justify-content:center;"
          "min-height:100vh;gap:12px}"
          "h1{font-size:28px}p{color:#4a6fa0;font-size:14px}</style></head>"
          "<body><h1>&#10003; Update successful!</h1>"
          "<p>Device is restarting...</p><p style='color:#1a3060'>Redirecting in 5s</p></body></html>"
        : "<!DOCTYPE html><html><head><meta charset='utf-8'>"
          "<style>body{background:#06080f;color:#ff8080;font-family:-apple-system,sans-serif;"
          "display:flex;flex-direction:column;align-items:center;justify-content:center;"
          "min-height:100vh;gap:12px}"
          "h1{font-size:28px}p{color:#4a6fa0;font-size:14px}"
          "a{color:#28d49a}</style></head>"
          "<body><h1>&#10007; Update failed</h1>"
          "<p>Please try again.</p><a href='/'>&#8592; Back</a></body></html>";
      ota_server.send(200, "text/html", msg);
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
    // Upload-Handler (chunk-weise)
    []() {
      HTTPUpload& upload = ota_server.upload();
      if (upload.status == UPLOAD_FILE_START) {
        Serial.printf("OTA start: %s\n", upload.filename.c_str());
        ota_upload_active = true;
        if (Update.isRunning()) Update.abort();  // clean up any previous failed upload
        if (!Update.begin(UPDATE_SIZE_UNKNOWN)) {
          Serial.println("OTA begin() error");
          ota_upload_active = false;
        }
        if (lbl_ota_status) lv_label_set_text(lbl_ota_status,
          T(STR_OTA_UPLOADING));
        lv_timer_handler();
      } else if (upload.status == UPLOAD_FILE_WRITE) {
        if (Update.write(upload.buf, upload.currentSize) != upload.currentSize) {
          Serial.println("OTA write() error");
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

  // ── SD-Card Log endpoints ─────────────────────────────────
  // GET /logs -> JSON list of available log files
  ota_server.on("/logs", HTTP_GET, []() {
    if (!sd_available) {
      ota_server.send(200, "application/json", "{\"sd\":false,\"verbose\":false,\"files\":[]}");
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
    ota_server.send(200, "application/json", json);
  });

  // GET /log?file=<filename> -> serve log file content
  ota_server.on("/log", HTTP_GET, []() {
    if (!sd_available) { ota_server.send(404, "text/plain", "No SD card"); return; }
    if (!ota_server.hasArg("file")) {
      ota_server.send(400, "text/plain", "Missing file param");
      return;
    }
    String fname = ota_server.arg("file");
    // basic sanitization: only allow log_*.txt names
    if (!fname.startsWith("log_") || !fname.endsWith(".txt") || fname.indexOf("..") >= 0) {
      ota_server.send(400, "text/plain", "Invalid filename");
      return;
    }
    String path = "/" + fname;
    if (!SD.exists(path.c_str())) {
      ota_server.send(404, "text/plain", "Not found");
      return;
    }
    File f = SD.open(path.c_str(), FILE_READ);
    if (!f) { ota_server.send(500, "text/plain", "Open failed"); return; }
    ota_server.streamFile(f, "text/plain");
    f.close();
  });

  // POST /deletelog?file=<name> -> delete a log file
  ota_server.on("/deletelog", HTTP_POST, []() {
    if (!sd_available) { ota_server.send(404, "text/plain", "No SD card"); return; }
    if (!ota_server.hasArg("file")) {
      ota_server.send(400, "text/plain", "Missing file param");
      return;
    }
    String fname = ota_server.arg("file");
    if (!fname.startsWith("log_") || !fname.endsWith(".txt") || fname.indexOf("..") >= 0) {
      ota_server.send(400, "text/plain", "Invalid filename");
      return;
    }
    String path = "/" + fname;
    if (SD.remove(path.c_str())) {
      logSDf("Log file deleted via web: %s", fname.c_str());
      ota_server.send(200, "text/plain", "OK");
    } else {
      ota_server.send(500, "text/plain", "Delete failed");
    }
  });

  // POST /verbose -> toggle verbose.txt on SD root
  ota_server.on("/verbose", HTTP_POST, []() {
    if (!sd_available) {
      ota_server.send(404, "application/json", "{\"error\":\"No SD card\"}");
      return;
    }
    if (sd_verbose) {
      // currently ON -> remove file
      if (SD.remove("/verbose.txt")) {
        sd_verbose = false;
        logSD("Verbose logging: DISABLED via web");
        ota_server.send(200, "application/json", "{\"verbose\":false}");
      } else {
        ota_server.send(500, "application/json", "{\"error\":\"Failed to remove verbose.txt\"}");
      }
    } else {
      // currently OFF -> create file
      File f = SD.open("/verbose.txt", FILE_WRITE);
      if (f) {
        f.println("Verbose logging marker. Delete this file to disable verbose mode.");
        f.close();
        sd_verbose = true;
        logSD("Verbose logging: ENABLED via web");
        ota_server.send(200, "application/json", "{\"verbose\":true}");
      } else {
        ota_server.send(500, "application/json", "{\"error\":\"Failed to create verbose.txt\"}");
      }
    }
  });

  // List limit: GET returns current value, POST sets new value
  // FilaMan: store the API key. The value is never echoed back to the page,
  // the input shows a placeholder when one is already stored.
  ota_server.on("/filaman/key", HTTP_POST, []() {
    String key = ota_server.arg("plain");
    key.trim();
    if (key.length() < 8) { ota_server.send(400, "text/plain", "Key too short"); return; }
    filamanSetApiKey(key.c_str());
    ota_server.send(200, "text/plain", "Saved");
  });

  // FilaMan: exchange the 6 character device code for a device token.
  ota_server.on("/filaman/register", HTTP_POST, []() {
    String code = ota_server.arg("plain");
    code.trim();
    code.toUpperCase();   // codes are shown uppercase in the FilaMan admin
    if (code.length() < 4) { ota_server.send(400, "text/plain", "Code too short"); return; }
    if (strlen(backendBaseUrl()) <= 7) {
      ota_server.send(200, "text/plain", "Set the FilaMan address on the device first");
      return;
    }

    char token[80] = "";
    char errmsg[96] = "";
    int rc = filamanRegisterDevice(backendBaseUrl(), code.c_str(),
                                   token, sizeof(token), errmsg, sizeof(errmsg));
    if (rc != 200 || !token[0]) {
      // Always name the URL that was actually contacted. A missing port
      // silently sends the request to whatever runs on port 80, and the
      // answer then looks like a FilaMan problem when it is not.
      String msg = String("Failed (HTTP ") + rc + ") calling "
                 + backendBaseUrl() + "/api/v1/devices/register";
      if (errmsg[0]) msg += String(" - ") + errmsg;
      if (!strchr(backendHost(), ':')) {
        msg += " - the address has no port, FilaMan usually runs on :8002";
      } else if (rc == 404) {
        msg += " - codes are single use, create a new device or rotate the token in FilaMan";
      } else if (rc == 403) {
        msg += " - this device already has a token, rotate it in FilaMan to get a fresh code";
      }
      ota_server.send(200, "text/plain", msg);
      return;
    }
    filamanSetDeviceToken(token);
    ota_server.send(200, "text/plain", "Device registered");
  });

  ota_server.on("/listlimit", HTTP_GET, []() {
    char json[32];
    snprintf(json, sizeof(json), "{\"limit\":%d}", spool_list_limit);
    ota_server.send(200, "application/json", json);
  });
  ota_server.on("/listlimit", HTTP_POST, []() {
    if (!ota_server.hasArg("plain")) { ota_server.send(400, "application/json", "{\"error\":\"no body\"}"); return; }
    int val = ota_server.arg("plain").toInt();
    if (val < 5) val = 5;
    if (val > 100) val = 100;
    spool_list_limit = val;
    prefsPutUChar("list_limit", (uint8_t)val);
    char json[32]; snprintf(json, sizeof(json), "{\"limit\":%d}", spool_list_limit);
    logSDf("Webserver: list_limit set to %d", spool_list_limit);
    ota_server.send(200, "application/json", json);
  });

  ota_server.on("/loclimit", HTTP_GET, []() {
    char json[32];
    snprintf(json, sizeof(json), "{\"limit\":%d}", location_list_limit);
    ota_server.send(200, "application/json", json);
  });
  ota_server.on("/loclimit", HTTP_POST, []() {
    if (!ota_server.hasArg("plain")) { ota_server.send(400, "application/json", "{\"error\":\"no body\"}"); return; }
    int val = ota_server.arg("plain").toInt();
    if (val < 5) val = 5;
    if (val > 100) val = 100;
    location_list_limit = val;
    prefsPutUChar("loc_limit", (uint8_t)val);
    char json[32]; snprintf(json, sizeof(json), "{\"limit\":%d}", location_list_limit);
    logSDf("Webserver: loc_limit set to %d", location_list_limit);
    ota_server.send(200, "application/json", json);
  });

  // ── Drying Reminder: Material-Schwellwerte lesen ──────────
  ota_server.on("/drying", HTTP_GET, []() {
    String json = "{";
    json += "\"mode\":" + String(g_dry_mode) + ",";
    json += "\"man_yellow\":" + String(g_dry_man_yellow) + ",";
    json += "\"man_red\":" + String(g_dry_man_red) + ",";
    json += "\"mult_sealed\":" + String(g_dry_mult_sealed, 1) + ",";
    json += "\"materials\":[";
    for (int i = 0; i < DRY_MAT_COUNT; i++) {
      if (i > 0) json += ",";
      json += "{\"name\":\"" + String(DRY_MAT_NAMES[i]) + "\",";
      json += "\"yellow\":" + String(g_dry_mat_yellow[i]) + ",";
      json += "\"red\":" + String(g_dry_mat_red[i]) + ",";
      json += "\"sealed\":" + String(g_dry_mat_sealed[i] ? "true" : "false") + "}";
    }
    json += "]}";
    ota_server.send(200, "application/json", json);
  });

  // ── Drying Reminder: Material-Schwellwerte speichern ──────
  // Body: JSON {"mult_sealed":3.0,"materials":[{"name":"PLA","yellow":180,"red":365},...]}
  ota_server.on("/drying", HTTP_POST, []() {
    if (!ota_server.hasArg("plain")) {
      ota_server.send(400, "application/json", "{\"error\":\"no body\"}"); return;
    }
    StaticJsonDocument<1024> doc;
    DeserializationError err = deserializeJson(doc, ota_server.arg("plain"));
    if (err) {
      ota_server.send(400, "application/json", "{\"error\":\"json parse\"}"); return;
    }
    if (doc.containsKey("mult_sealed")) {
      g_dry_mult_sealed = doc["mult_sealed"].as<float>();
      if (g_dry_mult_sealed < 1.0f) g_dry_mult_sealed = 1.0f;
      if (g_dry_mult_sealed > 10.0f) g_dry_mult_sealed = 10.0f;
      prefsPutFloat("dry_mult_s", g_dry_mult_sealed);
    }
    if (doc.containsKey("materials")) {
      JsonArray arr = doc["materials"].as<JsonArray>();
      for (JsonObject obj : arr) {
        const char* nm = obj["name"] | "";
        for (int i = 0; i < DRY_MAT_COUNT; i++) {
          if (strcasecmp(nm, DRY_MAT_NAMES[i]) == 0) {
            char key[16];
            if (obj.containsKey("yellow")) {
              g_dry_mat_yellow[i] = max(1, (int)obj["yellow"]);
              snprintf(key, sizeof(key), "dry_y_%s", DRY_MAT_NAMES[i]);
              prefsPutInt(key, g_dry_mat_yellow[i]);
            }
            if (obj.containsKey("red")) {
              g_dry_mat_red[i] = max(1, (int)obj["red"]);
              snprintf(key, sizeof(key), "dry_r_%s", DRY_MAT_NAMES[i]);
              prefsPutInt(key, g_dry_mat_red[i]);
            }
            if (obj["sealed"].is<bool>()) {
              g_dry_mat_sealed[i] = obj["sealed"].as<bool>();
              snprintf(key, sizeof(key), "dry_s_%s", DRY_MAT_NAMES[i]);
              prefsPutBool(key, g_dry_mat_sealed[i]);
            }
            break;
          }
        }
      }
    }
    logSD("Webserver: drying thresholds updated");
    ota_server.send(200, "application/json", "{\"ok\":true}");
  });

  // ── Drying Reminder: Reset auf Defaults ───────────────────
  ota_server.on("/drying/reset", HTTP_POST, []() {
    g_dry_mult_sealed = 2.0f;
    g_dry_man_yellow  = 30;
    g_dry_man_red     = 90;
    prefsPutFloat("dry_mult_s", g_dry_mult_sealed);
    prefsPutInt("dry_man_y",  g_dry_man_yellow);
    prefsPutInt("dry_man_r",  g_dry_man_red);
    char key[16];
    for (int i = 0; i < DRY_MAT_COUNT; i++) {
      g_dry_mat_yellow[i] = DRY_MAT_DEF_YELLOW[i];
      g_dry_mat_red[i]    = DRY_MAT_DEF_RED[i];
      g_dry_mat_sealed[i] = false;
      snprintf(key, sizeof(key), "dry_y_%s", DRY_MAT_NAMES[i]);
      prefsPutInt(key, g_dry_mat_yellow[i]);
      snprintf(key, sizeof(key), "dry_r_%s", DRY_MAT_NAMES[i]);
      prefsPutInt(key, g_dry_mat_red[i]);
      snprintf(key, sizeof(key), "dry_s_%s", DRY_MAT_NAMES[i]);
      prefsPutBool(key, false);
    }
    logSD("Webserver: drying thresholds reset to defaults");
    ota_server.send(200, "application/json", "{\"ok\":true,\"reset\":true}");
  });

  ota_server.begin();
  ota_server_running = true;
  Serial.printf("OTA server started: http://%s/\n", wifiManagerLocalIP().toString().c_str());
}


void handleOtaServerClient() {
  if (ota_server_running) ota_server.handleClient();
}

bool otaWebUploadActive() {
  return ota_upload_active;
}
