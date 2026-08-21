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
#include "services/remote_link.h"
#include "lang.h"
#include "list_limits.h"
#include "web_access.h"
#include "web_shell.h"
#include "hardware/display.h"
#include "backend_api.h"
#include "tag_write.h"
#include "hardware/nfc.h"
#include "web_home.h"
#include "prefs_store.h"
#include "wifi_manager.h"


static WebServer ota_server(80);
static bool ota_server_running  = false;
static bool ota_upload_active   = false;
static bool ota_routes_enabled  = false;
static bool routes_registered   = false;

// The OTA, log and settings routes answer only while the web screen is open.
// The socket itself can outlive that screen, because FilaMan triggers the
// remote link on port 80 and expects a listener at any time. So the routes
// are gated rather than removed: WebServer has no way to unregister a
// handler once it is added.
static bool otaRoutesOpen() { return ota_routes_enabled; }

// True while the scale has to stay reachable for FilaMan's write-tag
// trigger. In Spoolman mode this is never true and nothing changes.
static bool remoteLinkNeedsServer() {
  return wifi_ok && backendIsFilaMan() && filamanDeviceToken()[0];
}

static void registerRoutes();

static void serverEnsureRunning() {
  if (ota_server_running) return;
  registerRoutes();
  ota_server.begin();
  ota_server_running = true;
  Serial.printf("Web server listening: http://%s/\n",
                wifiManagerLocalIP().toString().c_str());
}

static void serverEnsureStopped() {
  if (!ota_server_running) return;
  ota_server.stop();
  ota_server_running = false;
  Serial.println("Web server stopped");
}

  // One shell, five pages. This used to be a single page at "/" carrying the
  // firmware upload, the log browser, the drying thresholds, the FilaMan
  // credentials and the list limits all at once, while the clean URLs were
  // taken by its JSON backend. Each section now has its own address and only
  // that section is built and sent.
  static const char *SEC_TITLE[] = { "Firmware", "Logs", "Drying", "FilaMan", "Limits", "Tags" };
  static const char *SEC_PATH[]  = { "/ota", "/logs", "/drying", "/filaman", "/config", "/tags" };

  static String maintNav(int sec) {
    String n = "<div class='nav'>";
    n += "<a href='/'>Status</a>";
    for (int i = 0; i < 6; i++) {
      if (i == 3 && !backendIsFilaMan()) continue;   // not applicable on Spoolman
      n += String("<a class='") + (i == sec ? "on" : "") + "' href='" + SEC_PATH[i] + "'>"
           + SEC_TITLE[i] + "</a>";
    }
    n += "</div>";
    return n;
  }

  static String maintPage(int sec) {
    String html;
    html += webShellHead(SEC_TITLE[sec]);
    html += webShellPageCss();
    html += "<style>.nav{display:flex;flex-wrap:wrap;gap:8px;width:100%;max-width:480px;"
            "margin-bottom:18px}.nav a{padding:8px 14px;background:#0a1828;border:1px solid "
            "#1a3060;border-radius:8px;color:#4a6fa0;text-decoration:none;font-size:13px}"
            ".nav a:hover{border-color:#28d49a;color:#e8f0ff}"
            ".nav a.on{background:#1a3060;color:#e8f0ff;border-color:#28d49a}</style>";
    html += maintNav(sec);
    html += webShellLinks();
    if (sec == 0) html +=       "<div class='card'>"
      "<h2>Upload Firmware</h2>"
      "<form method='POST' action='/update' enctype='multipart/form-data'>"
      "<input type='file' name='firmware' accept='.bin' required>"
      "<button class='btn-flash' type='submit'>&#x2191;&nbsp; Flash Firmware</button>"
      "</form>"
      "<p class='hint'>Select SpoolmanScale vX.Y.Z.bin - device restarts automatically</p>"
      "</div>";
    if (sec == 1) html +=       "<div class='card'>"
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
    if (sec == 2) html +=       "<div class='card'>"
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
      "border-radius:6px;padding:4px 8px;font-size:14px;text-align:center}</style>";

    html +=       "<script>"
      "function setLocL(){""var v=parseInt(document.getElementById('locl-in').value);""if(v<5)v=5;if(v>100)v=100;""fetch('/api/loclimit',{method:'POST',body:String(v)})"".then(r=>r.json()).then(d=>{""document.getElementById('locl-s').textContent='Saved: '+d.limit;""setTimeout(()=>{document.getElementById('locl-s').textContent='';},3000);""});}""var tgCur='',tgNew='',tgLinked='',tgUid='';""function tgSync(){var b=document.getElementById('tg-btn');if(!b)return;""var n=document.getElementById('tg-new');""if(!tgNew){b.disabled=true;b.textContent='Pick a spool';if(n)n.textContent='';return;}""if(n){var w='Will write: '+tgNew;""if(tgLinked&&tgUid&&tgLinked!=tgUid)""w+=' | note: spool is linked to '+tgLinked+', linking replaces it';""n.textContent=w;}""if(tgCur===tgNew){b.disabled=true;b.textContent='Tag already matches';}""else{b.disabled=false;b.textContent=tgCur&&tgCur!='blank'?'Overwrite tag':'Write tag';}}""function loadPreview(){var v=parseInt(document.getElementById('tg-id').value);""var f=document.getElementById('tg-fmt').value;""if(!v){tgNew='';tgSync();return;}""fetch('/api/tag/preview?id='+v+'&fmt='+f).then(r=>r.json()).then(d=>{""tgNew=d.ok?d.preview:'';tgLinked=d.ok?(d.linked||''):'';""if(!d.ok){var n=document.getElementById('tg-new');""if(n)n.textContent='Spool '+v+' not found on the backend.';}""tgSync();});}""function setOpt(p,t){p.innerHTML='';var o=document.createElement('option');""o.value='';o.textContent=t;p.appendChild(o);}""function pickSpool(){var p=document.getElementById('tg-pick');""if(p.value)document.getElementById('tg-id').value=p.value;loadPreview();}""function loadSpools(){var p=document.getElementById('tg-pick');if(!p)return;""fetch('/api/spools').then(r=>r.json()).then(d=>{""if(d.error){setOpt(p,d.error);return;}""setOpt(p,'-- pick a spool --');""d.forEach(s=>{var o=document.createElement('option');o.value=s.id;""o.textContent='#'+s.id+'  '+s.label;p.appendChild(o);});""}).catch(e=>{setOpt(p,'spool list unavailable');});}""function tgPoll(){fetch('/api/tag').then(r=>r.json()).then(d=>{""document.getElementById('tg-uid').textContent=d.uid?('Tag on reader: '+d.uid+' ('+d.kind+')'):'No tag on the reader.';""var c=document.getElementById('tg-cur');""tgUid=d.uid||'';""if(c)c.textContent=d.content?('Currently on tag: '+d.content):'';""if(d.content!==tgCur){tgCur=d.content||'';tgSync();}""var s=document.getElementById('tg-s');""if(d.state!='idle'){s.textContent=d.message;""s.style.color=(d.state=='error')?'#ff8080':'#28d49a';}""});}""function writeTag(){""var v=parseInt(document.getElementById('tg-id').value);""if(!v){document.getElementById('tg-s').textContent='Enter a spool ID.';return;}""var f=document.getElementById('tg-fmt').value;""var l=document.getElementById('tg-link').checked?1:0;""fetch('/api/tag/write',{method:'POST',body:v+','+f+','+l})"".then(r=>r.json()).then(d=>{document.getElementById('tg-s').textContent=d.message||'Queued.';});""setTimeout(tgPoll,1500);setTimeout(tgPoll,4000);}""document.addEventListener('DOMContentLoaded',function(){""if(document.getElementById('tg-uid')){tgPoll();setInterval(tgPoll,3000);}""if(document.getElementById('tg-pick'))loadSpools();""});""function setGain(){"
      "var v=parseInt(document.getElementById('gain-in').value);"
      "fetch('/api/gain',{method:'POST',body:String(v)})"
      ".then(r=>r.json()).then(d=>{"
      "document.getElementById('gain-s').textContent='Saved: '+d.gain;"
      "setTimeout(()=>{document.getElementById('gain-s').textContent='';},3000);"
      "});}"
      "function setLL(){"
      "var v=parseInt(document.getElementById('ll-in').value);"
      "if(v<5)v=5;if(v>100)v=100;"
      "fetch('/api/listlimit',{method:'POST',body:String(v)})"
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
      "fetch('/api/drying',{method:'POST',"
      "headers:{'Content-Type':'application/json'},"
      "body:JSON.stringify({mult_sealed:mult,materials:arr})})"
      ".then(r=>r.json()).then(d=>{"
      "document.getElementById('dry-s').textContent=d.ok?'Saved!':'Error';"
      "setTimeout(()=>{document.getElementById('dry-s').textContent='';},3000);"
      "});}"
      "function resetDry(){"
      "fetch('/api/drying/reset',{method:'POST'})"
      ".then(r=>r.json()).then(d=>{"
      "document.getElementById('dry-s').textContent='Reset!';"
      "setTimeout(()=>location.reload(),1500);"
      "});}"
      "</script>";
    if (sec == 3 && backendIsFilaMan()) html +=       "<div class='card'>"
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
      "fetch('/api/filaman/key',{method:'POST',body:v})"
      ".then(r=>r.text()).then(t=>{document.getElementById('fm-key-s').textContent=t;});}"
      "function reg(){var c=document.getElementById('fm-code').value;"
      "document.getElementById('fm-reg-s').textContent='Registering...';"
      "fetch('/api/filaman/register',{method:'POST',body:c})"
      ".then(r=>r.text()).then(t=>{document.getElementById('fm-reg-s').textContent=t;});}"
      "</script>";
    if (sec == 3 && backendIsBamBuddy()) html += 
      "</script>";
    if (sec == 4) html +=       "<div class='card'>"
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
      "</div></div></div>";

    if (sec == 4) html +=       "<div class='card'>"
      "<h2>Display</h2>"
      "<p style='font-size:12px;color:#4a6fa0;margin-bottom:14px'>Gamma lift applied to every pixel. 100 is off; higher raises shadows and midtones without touching white, which brightens the whole UI at once. Independent of the backlight.</p>"
      "<div style='display:flex;gap:10px;align-items:center'>"
      "<input id='gain-in' type='range' min='100' max='300' step='5' value='"+String(displayGetUiGain())+"'"
      " oninput=\"document.getElementById('gain-v').textContent=this.value\" style='flex:1'>"
      "<span id='gain-v' style='font-size:14px;color:#e8f0ff;width:38px;text-align:right'>"+String(displayGetUiGain())+"</span>"
      "<button class='btn-toggle' onclick='setGain()'>Save</button>"
      "<span id='gain-s' style='font-size:12px;color:#28d49a;line-height:36px'></span>"
      "</div></div>";
    if (sec == 5) html +=
      "<div class='card'>"
      "<h2>Write a tag</h2>"
      "<p style='font-size:12px;color:#4a6fa0;margin-bottom:14px'>Place a writable NTAG on the reader, pick a spool, and write it. Whatever is already on the tag is replaced. Factory tags are usually MIFARE Classic or locked, and can only be read.</p>"
      "<div id='tg-uid' style='font-size:13px;color:#c8d8f0;margin-bottom:12px'>Checking reader...</div>"
      "<div id='tg-cur' style='font-size:12px;color:#4a6fa0;margin-bottom:12px'></div>"
      "<div id='tg-new' style='font-size:12px;color:#4a6fa0;margin-bottom:12px'></div>"
      "<div style='display:flex;gap:10px;align-items:center;flex-wrap:wrap'>"
      "<label style='font-size:13px;color:#c8d8f0'>Spool ID</label>"
      "<input id='tg-id' type='number' min='1' oninput='loadPreview()' style='width:88px;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;border-radius:8px;padding:8px 10px;font-size:16px'>"
      "<select id='tg-pick' onchange='pickSpool()' style='flex:1;min-width:200px;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;border-radius:8px;padding:8px 10px;font-size:14px'><option value=''>Loading spools...</option></select>"
      "<select id='tg-fmt' onchange='loadPreview()' style='background:#06080f;color:#e8f0ff;border:1px solid #1a3060;border-radius:8px;padding:8px 10px;font-size:14px'>"
      "<option value='0'>Anycubic ACE</option>"
      "<option value='1'>OpenSpool (FilaMan)</option>"
      "<option value='2'>Erase the tag</option>"
      "</select>"
      "<button id='tg-btn' class='btn-toggle' onclick='writeTag()' disabled>Pick a spool</button>"
      "</div>"
      "<label style='display:flex;align-items:center;gap:8px;font-size:13px;color:#c8d8f0;margin-top:12px'>"
      "<input id='tg-link' type='checkbox' checked style='width:16px;height:16px'>"
      "Also link this tag to the spool, so presenting it selects that spool"
      "</label>"
      "<div id='tg-s' style='font-size:13px;color:#28d49a;margin-top:12px'></div>"
      "</div>";

    html += webShellFoot();
    return html;
  }

void stopOtaServer() {
  ota_routes_enabled = false;
  // Keep the socket up when the remote link still needs it. The routes are
  // closed either way, so nothing becomes reachable that was not before.
  if (!remoteLinkNeedsServer()) serverEnsureStopped();
}

void startOtaServer() {
  if (!wifi_ok) return;
  ota_routes_enabled = true;
  serverEnsureRunning();
}

// Idempotent, called once a second from appLoop(). Picking the state up from
// the conditions rather than from events means a backend switch, a freshly
// entered device token and a returning WiFi connection all take effect
// without anyone having to remember to call something.
void webServerSyncState() {
  if (remoteLinkNeedsServer())      serverEnsureRunning();
  else if (!ota_routes_enabled)     serverEnsureStopped();
}

// Registered exactly once. This used to run on every visit to the web
// screen, which appended another 15 handlers to WebServer's list each time
// and never freed the previous ones.
static void registerRoutes() {
  if (routes_registered) return;
  routes_registered = true;

  // The status landing page owns its own routes. Registered here so
  // everything lands in the one-shot registration.
  registerHomeRoutes(ota_server);

  // FilaMan remote link trigger. Deliberately not behind otaRoutesOpen():
  // this one has to answer whenever the scale is awake, that is the whole
  // point of keeping the socket up.
  //
  // FilaMan sends this fire and forget and waits five seconds, so nothing
  // here may block. The request is only parked, appLoop() picks it up.
  // Nothing is ever written to the tag, the trigger is read as "the spool on
  // the scale belongs to this id".
  ota_server.on("/api/v1/rfid/write", HTTP_POST, []() {
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, ota_server.arg("plain"));
    if (err) {
      ota_server.send(400, "application/json", "{\"status\":\"error\"}");
      return;
    }

    const int spool_id    = doc["spool_id"]    | 0;
    const int location_id = doc["location_id"] | 0;

    if (spool_id > 0) {
      remoteLinkSetPending(spool_id);
      ota_server.send(200, "application/json", "{\"status\":\"ok\"}");
      return;
    }
    if (location_id > 0) {
      // Locations are a FilaMan concept the scale does not handle yet.
      // Turning the request down beats ignoring it: the web UI would
      // otherwise poll for a full minute before its own timeout.
      remote_link_reject_pending = true;
      ota_server.send(200, "application/json", "{\"status\":\"ok\"}");
      return;
    }
    ota_server.send(400, "application/json", "{\"status\":\"error\"}");
  });

  // Route: Startseite mit Upload-Formular
  ota_server.on("/ota", HTTP_GET, []() {
    if (!webMaintenanceEnabled()) { webSendDisabled(ota_server, "Setup and firmware", "Settings > System > Web interface"); return; }
    ota_server.send(200, "text/html", maintPage(0));
  });
  ota_server.on("/logs", HTTP_GET, []() {
    if (!webMaintenanceEnabled()) { webSendDisabled(ota_server, "Logs", "Settings > System > Web interface"); return; }
    ota_server.send(200, "text/html", maintPage(1));
  });
  ota_server.on("/drying", HTTP_GET, []() {
    if (!webMaintenanceEnabled()) { webSendDisabled(ota_server, "Drying thresholds", "Settings > System > Web interface"); return; }
    ota_server.send(200, "text/html", maintPage(2));
  });
  ota_server.on("/filaman", HTTP_GET, []() {
    if (!webMaintenanceEnabled()) { webSendDisabled(ota_server, "FilaMan setup", "Settings > System > Web interface"); return; }
    ota_server.send(200, "text/html", maintPage(3));
  });
  ota_server.on("/config", HTTP_GET, []() {
    if (!webMaintenanceEnabled()) { webSendDisabled(ota_server, "List limits", "Settings > System > Web interface"); return; }
    ota_server.send(200, "text/html", maintPage(4));
  });
  ota_server.on("/tags", HTTP_GET, []() {
    if (!webMaintenanceEnabled()) { webSendDisabled(ota_server, "Tag writing", "Settings > System > Web interface"); return; }
    ota_server.send(200, "text/html", maintPage(5));
  });


  // Route: Upload verarbeiten
  ota_server.on("/update", HTTP_POST,
    // Abschluss-Handler
    []() {
      if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
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
      if (!otaRoutesOpen()) return;
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
  ota_server.on("/api/logs", HTTP_GET, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
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
  ota_server.on("/api/log", HTTP_GET, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
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
  ota_server.on("/api/deletelog", HTTP_POST, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
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
  ota_server.on("/api/verbose", HTTP_POST, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
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
  ota_server.on("/api/filaman/key", HTTP_POST, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
    String key = ota_server.arg("plain");
    key.trim();
    if (key.length() < 8) { ota_server.send(400, "text/plain", "Key too short"); return; }
    filamanSetApiKey(key.c_str());
    ota_server.send(200, "text/plain", "Saved");
  });

  // BamBuddy: store the API key. An empty value is accepted and clears it,
  // because an instance without authentication needs none - unlike FilaMan,
  // where a missing credential is always a mistake.
  ota_server.on("/bambuddy/key", HTTP_POST, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
    String key = ota_server.arg("plain");
    key.trim();
    if (key.length() > 0 && key.length() < 8) {
      ota_server.send(400, "text/plain", "Key too short");
      return;
    }
    bambuddySetApiKey(key.c_str());
    ota_server.send(200, "text/plain", key.length() ? "Saved" : "Cleared");
  });

  // FilaMan: exchange the 6 character device code for a device token.
  ota_server.on("/api/filaman/register", HTTP_POST, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
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

  ota_server.on("/api/tag/preview", HTTP_GET, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
    int id  = ota_server.arg("id").toInt();
    int fmt = ota_server.arg("fmt").toInt();
    char prev[128] = "", linked[40] = "";
    bool ok = tagPreview(id, fmt == 2 ? TAG_FMT_ERASE : fmt == 1 ? TAG_FMT_OPENSPOOL : TAG_FMT_ACE,
                         prev, sizeof(prev), linked, sizeof(linked));
    ota_server.send(200, "application/json",
      String("{\"ok\":") + (ok ? "true" : "false") + ",\"preview\":\"" + prev +
      "\",\"linked\":\"" + linked + "\"}");
  });

  ota_server.on("/api/spools", HTTP_GET, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
    JsonDocument doc;
    int code = backendGetSpoolListJson(backendBaseUrl(), false, doc);
    if (code != 200) {
      ota_server.send(200, "application/json",
                      String("{\"error\":\"backend HTTP ") + code + "\"}");
      return;
    }
    String out = "[";
    bool first = true;
    for (JsonObjectConst sp : doc.as<JsonArrayConst>()) {
      int id = sp["id"] | 0;
      if (!id) continue;
      String label = String(sp["filament"]["vendor"]["name"] | "");
      String name  = String(sp["filament"]["name"] | "");
      String mat   = String(sp["filament"]["material"] | "");
      if (label.length() && name.length()) label += " ";
      label += name;
      if (mat.length()) label += " (" + mat + ")";
      label.replace("\\", "");
      label.replace("\"", "'");
      if (!first) out += ",";
      first = false;
      out += "{\"id\":" + String(id) + ",\"label\":\"" + label + "\"}";
    }
    out += "]";
    ota_server.send(200, "application/json", out);
  });

  ota_server.on("/api/tag", HTTP_GET, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
    // Reader state comes from the loop task; touching the reader here would
    // race the main NFC poll.
    String j = String("{\"uid\":\"") + tagCachedUid() + "\",\"kind\":\"" + tagCachedKind() +
               "\",\"state\":\"" + tagWriteState() +
               "\",\"message\":\"" + tagWriteMessage() +
               "\",\"content\":\"" + tagCachedContent() + "\"}";
    ota_server.send(200, "application/json", j);
  });

  ota_server.on("/api/tag/write", HTTP_POST, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
    if (!ota_server.hasArg("plain")) { ota_server.send(400, "application/json", "{\"error\":\"no body\"}"); return; }
    String body = ota_server.arg("plain");
    int c1 = body.indexOf(',');
    int c2 = c1 < 0 ? -1 : body.indexOf(',', c1 + 1);
    int id  = body.substring(0, c1 < 0 ? body.length() : c1).toInt();
    int fmt = c1 < 0 ? 0 : body.substring(c1 + 1, c2 < 0 ? body.length() : c2).toInt();
    bool link = c2 >= 0 && body.substring(c2 + 1).toInt() == 1;
    bool ok = tagWriteRequest(id, fmt == 2 ? TAG_FMT_ERASE : fmt == 1 ? TAG_FMT_OPENSPOOL : TAG_FMT_ACE, link);
    ota_server.send(200, "application/json",
      ok ? "{\"message\":\"Queued, keep the tag on the reader.\"}"
         : "{\"message\":\"Busy or invalid spool ID.\"}");
  });

  ota_server.on("/api/gain", HTTP_POST, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
    if (!ota_server.hasArg("plain")) { ota_server.send(400, "application/json", "{\"error\":\"no body\"}"); return; }
    int val = ota_server.arg("plain").toInt();
    if (val < 100) val = 100;
    if (val > 300) val = 300;
    displaySetUiGain((uint16_t)val);
    prefsPutUInt("ui_gain", (uint32_t)val);
    char json[32]; snprintf(json, sizeof(json), "{\"gain\":%d}", val);
    logSDf("Webserver: ui_gain set to %d", val);
    ota_server.send(200, "application/json", json);
  });

  ota_server.on("/api/listlimit", HTTP_GET, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
    char json[32];
    snprintf(json, sizeof(json), "{\"limit\":%d}", spool_list_limit);
    ota_server.send(200, "application/json", json);
  });
  ota_server.on("/api/listlimit", HTTP_POST, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
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

  ota_server.on("/api/loclimit", HTTP_GET, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
    char json[32];
    snprintf(json, sizeof(json), "{\"limit\":%d}", location_list_limit);
    ota_server.send(200, "application/json", json);
  });
  ota_server.on("/api/loclimit", HTTP_POST, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
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
  ota_server.on("/api/drying", HTTP_GET, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
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
  ota_server.on("/api/drying", HTTP_POST, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
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
  ota_server.on("/api/drying/reset", HTTP_POST, []() {
    if (!otaRoutesOpen()) { ota_server.send(403, "text/plain", "Closed"); return; }
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

}


void handleOtaServerClient() {
  if (ota_server_running) ota_server.handleClient();
}

bool otaWebUploadActive() {
  return ota_upload_active;
}
