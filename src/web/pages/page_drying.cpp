// Drying thresholds and reminder settings.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>
#include <ArduinoJson.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/drying_config.h"
#include "services/prefs_store.h"
#include "web/web_access.h"

static String body() {
  String html;
  html +=
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
      "border-radius:6px;padding:4px 8px;font-size:14px;text-align:center}</style>";

    html +=       "<script>"
      "function setLocL(){""var v=parseInt(document.getElementById('locl-in').value);""if(v<5)v=5;if(v>100)v=100;""fetch('/api/loclimit',{method:'POST',body:String(v)})"".then(r=>r.json()).then(d=>{""document.getElementById('locl-s').textContent='Saved: '+d.limit;""setTimeout(()=>{document.getElementById('locl-s').textContent='';},3000);""});}""var tgCur='',tgNew='',tgLinked='',tgUid='',tgCurI=null,tgNewI=null;""function esc(t){return String(t).replace(/[<>&]/g,function(c){""return {'<':'&lt;','>':'&gt;','&':'&amp;'}[c];});}""function row(k,a,b){if(a===undefined&&b===undefined)return '';""var d=(a!==undefined&&b!==undefined&&a!==b)?' class=\"diff\"':'';""return '<tr'+d+'><td>'+k+'</td><td>'+esc(a===undefined?'-':a)+'</td></tr>';}""function plain(el,t,x){el.innerHTML='<h3>'+t+'</h3>'""+'<div style=\"font-size:13px;color:#4a6fa0\">'+x+'</div>';}""function swatch(el,i,o,t,empty){if(!el)return;""if(!i||!i.fmt){plain(el,t,empty);return;}""if(i.fmt=='blank'){plain(el,t,'Blank tag');return;}""if(i.fmt=='unknown'){plain(el,t,'Data this firmware cannot read');return;}""o=o||{};""var h='<h3>'+t+'</h3>'""+'<div style=\"display:flex;gap:12px;align-items:center\">'""+'<div class=\"chip\" style=\"background:'+(i.color||'#101828')+'\"></div>'""+'<div><div class=\"name\">'+esc(i.brand||'')+' '+esc(i.material||'')+'</div>'""+'<div class=\"fmt\">'+esc(i.fmt)+(i.color?' - '+esc(i.color):'')+'</div></div></div>'""+'<table>'""+row('SKU',i.sku,o.sku)""+row('Nozzle',i.nozzle?i.nozzle+' C':undefined,o.nozzle?o.nozzle+' C':undefined)""+row('Bed',i.bed?i.bed+' C':undefined,o.bed?o.bed+' C':undefined)""+row('Weight',i.weight?i.weight+' g':undefined,o.weight?o.weight+' g':undefined)""+row('Diameter',i.dia?i.dia+' mm':undefined,o.dia?o.dia+' mm':undefined)""+row('Length',i.len?i.len+' m':undefined,o.len?o.len+' m':undefined)""+'</table>';el.innerHTML=h;}""function tgDraw(){""swatch(document.getElementById('tg-cur'),tgCurI,tgNewI,'On the tag','No tag on the reader.');""swatch(document.getElementById('tg-new'),tgNewI,tgCurI,'Will be written','Pick a spool.');}""function tgSync(){tgDraw();var b=document.getElementById('tg-btn');if(!b)return;""var n=document.getElementById('tg-note');""if(n)n.textContent=(tgLinked&&tgUid&&tgLinked!=tgUid)""?('This spool is linked to '+tgLinked+', which becomes its previous tag.'):'';""var er=document.getElementById('tg-erase');""if(er)er.disabled=!tgUid||tgCur=='blank';""if(!tgNew){b.disabled=true;b.textContent='Pick a spool';return;}""if(tgCur===tgNew){b.disabled=true;b.textContent='Tag already matches';}""else{b.disabled=false;b.textContent=tgCur&&tgCur!='blank'?'Overwrite tag':'Write tag';}}""function loadPreview(){var v=parseInt(document.getElementById('tg-id').value);""var f=document.getElementById('tg-fmt').value;""if(!v){tgNew='';tgNewI=null;tgSync();return;}""fetch('/api/tag/preview?id='+v+'&fmt='+f).then(r=>r.json()).then(d=>{""tgNew=d.ok?d.preview:'';tgLinked=d.ok?(d.linked||''):'';""tgNewI=d.ok?d.info:null;tgSync();});}""function setOpt(p,t){p.innerHTML='';var o=document.createElement('option');""o.value='';o.textContent=t;p.appendChild(o);}""function pickSpool(){var p=document.getElementById('tg-pick');""if(p.value)document.getElementById('tg-id').value=p.value;loadPreview();}""function loadSpools(){var p=document.getElementById('tg-pick');if(!p)return;""fetch('/api/spools').then(r=>r.json()).then(d=>{""if(d.error){setOpt(p,d.error);return;}""setOpt(p,'-- pick a spool --');""d.forEach(s=>{var o=document.createElement('option');o.value=s.id;""o.textContent='#'+s.id+'  '+s.label;p.appendChild(o);});""}).catch(e=>{setOpt(p,'spool list unavailable');});}""function tgPoll(){fetch('/api/tag').then(r=>r.json()).then(d=>{""document.getElementById('tg-uid').textContent=d.uid?('Tag on reader: '+d.uid+' ('+d.kind+')'):'No tag on the reader.';""tgUid=d.uid||'';tgCurI=d.uid?d.info:null;""tgCur=d.content||'';tgSync();""var s=document.getElementById('tg-s');""if(d.state!='idle'){s.textContent=d.message;""s.style.color=(d.state=='error')?'#ff8080':'#28d49a';}""});}""function eraseTag(){""if(!confirm('Erase everything on this tag?'))return;""fetch('/api/tag/write',{method:'POST',body:'0,2,0'})"".then(r=>r.json()).then(d=>{document.getElementById('tg-s').textContent=d.message||'Queued.';});""setTimeout(tgPoll,1500);setTimeout(tgPoll,4000);}""function writeTag(){""var v=parseInt(document.getElementById('tg-id').value);""if(!v){document.getElementById('tg-s').textContent='Enter a spool ID.';return;}""var f=document.getElementById('tg-fmt').value;""var l=document.getElementById('tg-link').checked?1:0;""fetch('/api/tag/write',{method:'POST',body:v+','+f+','+l})"".then(r=>r.json()).then(d=>{document.getElementById('tg-s').textContent=d.message||'Queued.';});""setTimeout(tgPoll,1500);setTimeout(tgPoll,4000);}""document.addEventListener('DOMContentLoaded',function(){""if(document.getElementById('tg-uid')){tgPoll();setInterval(tgPoll,3000);}""if(document.getElementById('tg-pick'))loadSpools();""});""function setGain(){"
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
  return html;
}

static void routes(WebServer &srv) {
  // ── Drying Reminder: Material-Schwellwerte lesen ──────────
  srv.on("/api/drying", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "Drying thresholds")) return;
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
    srv.send(200, "application/json", json);
  });

  // ── Drying Reminder: Material-Schwellwerte speichern ──────
  // Body: JSON {"mult_sealed":3.0,"materials":[{"name":"PLA","yellow":180,"red":365},...]}
  srv.on("/api/drying", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "Drying thresholds")) return;
    if (!srv.hasArg("plain")) {
      srv.send(400, "application/json", "{\"error\":\"no body\"}"); return;
    }
    StaticJsonDocument<1024> doc;
    DeserializationError err = deserializeJson(doc, srv.arg("plain"));
    if (err) {
      srv.send(400, "application/json", "{\"error\":\"json parse\"}"); return;
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
    srv.send(200, "application/json", "{\"ok\":true}");
  });

  // ── Drying Reminder: Reset auf Defaults ───────────────────
  srv.on("/api/drying/reset", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, "Drying thresholds")) return;
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
    srv.send(200, "application/json", "{\"ok\":true,\"reset\":true}");
  });
}

extern const WebPage PAGE_DRYING;
const WebPage PAGE_DRYING = {
  "/drying", "Drying", nullptr, GATE_CONFIG, nullptr,
  body, routes
};
