#include "web/web_screenshot.h"

#include "app/screenshot.h"
#include "app_config.h"
#include "web/web_access.h"
#include "web/web_shell.h"

// Last: T() is a macro, and ArduinoJson uses T as a template parameter.
#include "lang.h"

static constexpr uint32_t MS_PER_S = 1000;
// Between two downloads of "save all": browsers drop clicks that come in one
// burst, and ask once whether the page may save several files.
static constexpr int SAVE_ALL_GAP_MS = 400;

static void cardHtml(String& h) {
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_C_SHOT);
  h += F("</h2><p class='note'>");
  h += T(STR_W_SHOT_NOTE);
  h += F("</p><div style='display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:12px 0'>"
         "<button id='shb'>");
  h += T(STR_W_SHOT_TAKE);
  h += F("</button><button id='sha' class='quiet' disabled>");
  h += T(STR_W_SHOT_SAVE_ALL);
  h += F("</button><button id='shx' class='danger' disabled>");
  h += T(STR_W_SHOT_DROP_ALL);
  h += F("</button><span id='sht' class='note' style='margin:0'></span></div>"
         "<div id='shl' style='display:grid;gap:16px;"
         "grid-template-columns:repeat(auto-fill,minmax(240px,1fr))'></div></div>");
}

static void cardStrings(String& h) {
  h += F("<script>const SH={take:");
  h += jsStr(T(STR_W_SHOT_TAKE));
  h += F(",busy:");  h += jsStr(T(STR_W_SHOT_BUSY));
  h += F(",web:");   h += jsStr(T(STR_W_SHOT_AT_WEB));
  h += F(",panel:"); h += jsStr(T(STR_W_SHOT_AT_PANEL));
  h += F(",fail:");  h += jsStr(T(STR_W_SHOT_FAIL));
  h += F(",empty:"); h += jsStr(T(STR_W_SHOT_EMPTY));
  h += F(",save:");  h += jsStr(T(STR_W_LOG_DOWNLOAD));
  h += F(",del:");   h += jsStr(T(STR_W_LOG_DELETE));
  h += F(",fw:");    h += jsStr(FW_VERSION);
  h += F(",gap:");   h += String(SAVE_ALL_GAP_MS);
  h += F("};");
}

String screenshotCard() {
  String h;
  h.reserve(5200);
  cardHtml(h);
  cardStrings(h);
  h += F("var shPng={},shIds=[];"
         "function shEl(i){return document.getElementById(i);}"
         "function p2(n){return String(n).padStart(2,'0');}"
         "function shSay(t){shEl('sht').textContent=t;}"
         // The device sends a BMP because it needs no encoder for it; GitHub
         // takes PNG, so the browser redraws it on a canvas and saves that.
         "function shToPng(blob){return createImageBitmap(blob).then(function(bm){"
         "var c=document.createElement('canvas');c.width=bm.width;c.height=bm.height;"
         "c.getContext('2d').drawImage(bm,0,0);"
         "return new Promise(function(res,rej){c.toBlob(function(b){b?res(b):rej(0);},"
         "'image/png');});});}"
         // Each picture is fetched once and kept as a PNG: a BMP is 450 KB.
         "function shFetch(s){if(shPng[s.id])return Promise.resolve();"
         "return fetch('/api/screenshot.bmp?id='+s.id,{cache:'no-store'}).then(function(r){"
         "if(!r.ok)throw 0;return r.blob();}).then(shToPng).then(function(png){"
         "var at=new Date(Date.now()-s.age_s*1000);"
         "shPng[s.id]={url:URL.createObjectURL(png),"
         "name:'spoolmanscale-'+SH.fw+'-'+at.getFullYear()+p2(at.getMonth()+1)"
         "+p2(at.getDate())+'-'+p2(at.getHours())+p2(at.getMinutes())+p2(at.getSeconds())+'.png',"
         "label:(s.src==='panel'?SH.panel:SH.web).replace('{t}',at.toLocaleTimeString())};});}"
         "function shItem(id){var p=shPng[id];if(!p)return '';"
         "return '<div><img src=\"'+p.url+'\" alt=\"\" style=\"width:100%;display:block;"
         "border:1px solid var(--line);border-radius:8px\">'"
         "+'<div class=\"note\" style=\"margin:6px 0\">'+p.label+'</div>'"
         "+'<div style=\"display:flex;gap:8px\">'"
         "+'<button class=\"quiet\" data-sv=\"'+id+'\">'+SH.save+'</button>'"
         "+'<button class=\"danger\" data-rm=\"'+id+'\">'+SH.del+'</button></div></div>';}"
         // Newest first. Pictures the device no longer holds lose their PNG.
         "function shRender(){var c=shEl('shl');"
         "Object.keys(shPng).forEach(function(k){if(shIds.indexOf(+k)<0){"
         "URL.revokeObjectURL(shPng[k].url);delete shPng[k];}});"
         "c.innerHTML=shIds.length?shIds.slice().reverse().map(shItem).join('')"
         ":'<div class=\"note\">'+SH.empty+'</div>';"
         "c.querySelectorAll('[data-sv]').forEach(function(b){"
         "b.addEventListener('click',function(){shSave(+b.dataset.sv);});});"
         "c.querySelectorAll('[data-rm]').forEach(function(b){"
         "b.addEventListener('click',function(){shDrop('id='+b.dataset.rm);});});"
         "shEl('sha').disabled=shEl('shx').disabled=!shIds.length;}"
         // One at a time: the device answers one request after the other anyway.
         "function shLoad(){return getJson('/api/screenshot/list').then(function(d){"
         "if(!d)return;var l=d.shots||[];shIds=l.map(function(s){return s.id;});"
         "return l.reduce(function(p,s){return p.then(function(){return shFetch(s);});},"
         "Promise.resolve()).then(shRender);}).catch(function(){shSay(SH.fail);});}"
         "function shTake(){var b=shEl('shb');b.disabled=true;b.textContent=SH.busy;shSay('');"
         "post('/api/screenshot','').then(function(r){"
         "if(!r.ok){shSay(SH.fail);return;}return shLoad();})"
         ".finally(function(){b.disabled=false;b.textContent=SH.take;});}"
         "function shSave(id){var p=shPng[id];if(!p)return;var a=document.createElement('a');"
         "a.href=p.url;a.download=p.name;document.body.appendChild(a);a.click();a.remove();}"
         "function shSaveAll(){shIds.forEach(function(id,i){"
         "setTimeout(function(){shSave(id);},i*SH.gap);});}"
         "function shDrop(q){post('/api/screenshot/drop?'+q,'').then(shLoad);}"
         "shEl('shb').addEventListener('click',shTake);"
         "shEl('sha').addEventListener('click',shSaveAll);"
         "shEl('shx').addEventListener('click',function(){shDrop('all=1');});"
         // A picture taken on the panel shows up once the tab is looked at.
         "document.addEventListener('visibilitychange',function(){"
         "if(!document.hidden)shLoad();});"
         "shLoad();"
         "</script>");
  return h;
}

static void sendBmp(WebServer& srv) {
  const uint32_t id = (uint32_t)srv.arg("id").toInt();
  // Rows leave one at a time, decoded on the way: 1440 bytes, about one TCP
  // segment, where the whole file would be 450 KB the internal heap lacks.
  static uint8_t row[SCREENSHOT_BMP_ROW_BYTES];
  if (!screenshotBmpRow(id, 0, row)) {
    srv.send(404, "text/plain", "No such screenshot");
    return;
  }
  uint8_t header[SCREENSHOT_BMP_HEADER_BYTES];
  screenshotBmpHeader(header);
  srv.sendHeader("Cache-Control", "no-store");
  srv.setContentLength(SCREENSHOT_BMP_FILE_BYTES);
  srv.send(200, "image/bmp", "");
  srv.sendContent((const char*)header, sizeof(header));
  srv.sendContent((const char*)row, sizeof(row));
  for (int r = 1; r < DISPLAY_H_PX; r++) {
    if (!screenshotBmpRow(id, r, row)) break;
    srv.sendContent((const char*)row, sizeof(row));
  }
}

static void sendList(WebServer& srv) {
  String json = "{\"max\":";
  json += String(SCREENSHOT_MAX);
  json += ",\"shots\":[";
  ScreenshotInfo info;
  for (int i = 0; screenshotInfoAt(i, info); i++) {
    if (i) json += ',';
    json += "{\"id\":";     json += String(info.id);
    json += ",\"age_s\":";  json += String(info.age_ms / MS_PER_S);
    json += ",\"bytes\":";  json += String(info.bytes);
    json += ",\"src\":\"";
    json += info.source == SCREENSHOT_FROM_PANEL ? "panel" : "web";
    json += "\"}";
  }
  json += "]}";
  srv.send(200, "application/json", json);
}

void screenshotRoutes(WebServer& srv) {
  // POST /api/screenshot -> takes a picture of the display now
  srv.on("/api/screenshot", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    const uint32_t id = screenshotTake(SCREENSHOT_FROM_WEB);
    if (!id) {
      srv.send(503, "application/json", "{\"error\":\"Screenshot failed, no memory\"}");
      return;
    }
    srv.send(200, "application/json", String("{\"id\":") + id + "}");
  });

  // GET /api/screenshot/list -> the held pictures, oldest first
  srv.on("/api/screenshot/list", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    sendList(srv);
  });

  // GET /api/screenshot.bmp?id=N -> one picture, 404 when it is not held
  srv.on("/api/screenshot.bmp", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    sendBmp(srv);
  });

  // POST /api/screenshot/drop?id=N or ?all=1 -> frees the PSRAM they hold
  srv.on("/api/screenshot/drop", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    if (srv.hasArg("all")) {
      screenshotDropAll();
    } else {
      screenshotDrop((uint32_t)srv.arg("id").toInt());
    }
    srv.send(200, "application/json", "{\"ok\":true}");
  });
}
