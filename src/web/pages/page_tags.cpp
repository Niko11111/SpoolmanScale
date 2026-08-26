// Writing NFC tags from the browser. GATE_MAINT rather than GATE_CONFIG: a
// mistake here is written to a physical tag and cannot be taken back from the
// device.
//
// The two swatches show what is on the tag and what would replace it, both
// produced by the same formatter so they compare character for character.
#include "web/web_pages.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <WebServer.h>
#include <esp_heap_caps.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/tag_write.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

// Defined locally in every .cpp that needs it, as everywhere else in this
// project: ArduinoJson's allocator interface is a template detail and there
// is no shared header for it.
namespace {
struct SpiRamAllocator : ArduinoJson::Allocator {
  void* allocate(size_t size) override {
    void* ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
    if (!ptr) ptr = malloc(size);
    return ptr;
  }
  void deallocate(void* pointer) override { heap_caps_free(pointer); }
  void* reallocate(void* ptr, size_t new_size) override {
    void* p = heap_caps_realloc(ptr, new_size, MALLOC_CAP_SPIRAM);
    if (!p) p = realloc(ptr, new_size);
    return p;
  }
};
}

static const char* label() { return T(STR_W_NAV_TAGS); }


static String body() {
  String h;
  h.reserve(7600);

  h += F("<div class='grid'><div class='card wide'><h2>");
  h += T(STR_W_C_WRITETAG);
  h += F("</h2>"
         "<div id='tg-uid' class='hint' style='margin-bottom:14px'></div>"
         "<div class='grid' style='gap:12px'>"
         "<div class='card' style='background:var(--surface-2);padding:14px' id='tg-cur'></div>"
         "<div class='card' style='background:var(--surface-2);padding:14px' id='tg-new'></div>"
         "</div>"
         "<div class='field' style='margin-top:14px'><label>");
  h += T(STR_W_TAG_SPOOL);
  h += F("</label><div class='inrow'>"
         "<input id='tg-id' type='number' min='1' oninput='loadPreview()'>"
         "<select id='tg-pick' onchange='pickSpool()' style='min-width:210px'></select>"
         // OpenSpool first and preselected: it is the format the scale's own
         // backends read back, where ACE only ever talks to the printer.
         "<select id='tg-fmt' onchange='loadPreview()' style='flex:0 0 auto'>"
         "<option value='1' selected>OpenSpool</option>"
         "<option value='3'>FilaMan</option>"
         "<option value='0'>Anycubic ACE</option>"
         "</select></div></div>"
         "<label class='inrow' style='margin-top:14px;gap:8px;font-size:13px;color:var(--ink-2)'>"
         "<input id='tg-link' type='checkbox' checked style='flex:0 0 16px;width:16px;height:16px'> ");
  h += T(STR_W_TAG_LINK);
  h += F("</label>"
         "<div class='inrow' style='margin-top:16px'>"
         "<button id='tg-btn' onclick='writeTag()' disabled></button>"
         "<button id='tg-erase' class='danger' onclick='eraseTag()' disabled>");
  h += T(STR_W_TAG_ERASE);
  h += F("</button><span class='msg' id='tg-s'></span></div>"
         // Right under the buttons rather than above the fields: it is about
         // whether the write can happen at all, so it belongs where the write
         // is started.
         "<div id='tg-note' class='msg' style='color:var(--warn);margin-top:10px'></div>"
         "<p class='note'>");
  h += T(STR_W_TAG_NOTE);
  h += F("</p><p class='note' style='margin-top:8px'>");
  h += T(STR_W_TAG_SIZES);
  h += F("</p><p class='hint' style='margin-top:8px'>");
  h += T(STR_W_TAG_COMPARE);
  h += F("</p></div></div>");

  // Its own script. When the pages were split the shared block stayed behind
  // on the drying page, so every function this page calls was missing and the
  // whole page did nothing at all.
  h += F("<style>#tg-cur h3,#tg-new h3{font-size:10.5px;font-weight:650;letter-spacing:.1em;"
         "text-transform:uppercase;color:var(--ink-soft);margin-bottom:10px}"
         ".tgline{display:flex;align-items:center;gap:9px;margin-bottom:8px}"
         ".chip{width:26px;height:26px;border-radius:7px;border:1px solid #ffffff22;flex:none}"
         ".tgname{font-size:13.5px;color:var(--ink);line-height:1.3}"
         "#tg-cur table td,#tg-new table td{font-size:11.5px;font-family:var(--mono);"
         "color:var(--ink-3);padding:3px 8px 3px 0;border:0}"
         "tr.diff td{color:var(--warn)}</style>");

  h += F("<script>const M={cur:");
  h += jsStr(T(STR_W_TAG_ONTAG));
  h += F(",will:");    h += jsStr(T(STR_W_TAG_WILLBE));
  h += F(",notag:");   h += jsStr(T(STR_W_TAG_NOTAG));
  h += F(",onread:");  h += jsStr(T(STR_W_TAG_ONREADER));
  h += F(",pick:");    h += jsStr(T(STR_W_TAG_PICK));
  h += F(",pickf:");   h += jsStr(T(STR_W_TAG_PICKFIRST));
  h += F(",blank:");   h += jsStr(T(STR_W_TAG_BLANK));
  h += F(",unk:");     h += jsStr(T(STR_W_TAG_UNKNOWN));
  h += F(",write:");   h += jsStr(T(STR_W_TAG_WRITE));
  h += F(",over:");    h += jsStr(T(STR_W_TAG_OVERWRITE));
  h += F(",match:");   h += jsStr(T(STR_W_TAG_MATCHES));
  h += F(",eraseq:");  h += jsStr(T(STR_W_TAG_ERASE_ASK));
  h += F(",relink:");  h += jsStr(T(STR_W_TAG_RELINK));
  h += F(",queued:");  h += jsStr(T(STR_W_TAG_QUEUED));
  h += F(",nolist:");  h += jsStr(T(STR_W_TAG_NOLIST));
  h += F(",sku:");     h += jsStr(T(STR_W_TAG_SKU));
  h += F(",nozzle:");  h += jsStr(T(STR_W_TAG_NOZZLE));
  h += F(",bed:");     h += jsStr(T(STR_W_TAG_BED));
  h += F(",weight:");  h += jsStr(T(STR_W_TAG_WEIGHT));
  h += F(",dia:");     h += jsStr(T(STR_W_TAG_DIA));
  h += F(",len:");     h += jsStr(T(STR_W_TAG_LENGTH));
  h += F(",toosmall:"); h += jsStr(T(STR_W_TAG_TOOSMALL));
  h += F("};"
         "let tgCur='',tgNew='',tgLinked='',tgUid='',tgCurI=null,tgNewI=null,"
         "tgBytes=0,tgNeed=0;"
         "function esc(t){return String(t).replace(/[<>&]/g,c=>"
         "({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));}"
         // A row is only drawn when the side it belongs to has the field, and
         // it is highlighted when the two sides disagree - that difference is
         // the whole reason both are shown.
         "function row(k,a,b){if(a===undefined&&b===undefined)return '';"
         "const d=(a!==undefined&&b!==undefined&&a!==b)?' class=\"diff\"':'';"
         "return '<tr'+d+'><td>'+k+'</td><td>'+esc(a===undefined?'-':a)+'</td></tr>';}"
         "function plain(el,t,x){el.innerHTML='<h3>'+t+'</h3>'"
         "+'<div class=\"hint\">'+x+'</div>';}"
         "function swatch(el,i,o,t,empty){if(!el)return;"
         "if(!i||!i.fmt){plain(el,t,empty);return;}"
         "if(i.fmt=='blank'){plain(el,t,M.blank);return;}"
         "if(i.fmt=='unknown'){plain(el,t,M.unk);return;}"
         "o=o||{};"
         "el.innerHTML='<h3>'+t+'</h3>'"
         "+'<div class=\"tgline\"><div class=\"chip\" style=\"background:'"
         "+(i.color||'#101828')+'\"></div>'"
         "+'<div><div class=\"tgname\">'+esc(i.brand||'')+' '+esc(i.material||'')+'</div>'"
         "+'<div class=\"hint\">'+esc(i.fmt)+(i.color?' - '+esc(i.color):'')+'</div></div></div>'"
         "+'<table>'"
         "+row(M.sku,i.sku,o.sku)"
         "+row(M.nozzle,i.nozzle?i.nozzle+' C':undefined,o.nozzle?o.nozzle+' C':undefined)"
         "+row(M.bed,i.bed?i.bed+' C':undefined,o.bed?o.bed+' C':undefined)"
         "+row(M.weight,i.weight?i.weight+' g':undefined,o.weight?o.weight+' g':undefined)"
         "+row(M.dia,i.dia?i.dia+' mm':undefined,o.dia?o.dia+' mm':undefined)"
         "+row(M.len,i.len?i.len+' m':undefined,o.len?o.len+' m':undefined)"
         "+'</table>';}"
         "function tgDraw(){"
         "swatch(document.getElementById('tg-cur'),tgCurI,tgNewI,M.cur,M.notag);"
         "swatch(document.getElementById('tg-new'),tgNewI,tgCurI,M.will,M.pickf);}"
         "function tgSync(){tgDraw();const b=document.getElementById('tg-btn');if(!b)return;"
         // Said before the write, not after it. The capacity check inside the
         // firmware refuses the same tag, but only once the user has already
         // pressed the button and put the tag on the reader.
         "const small=tgNeed&&tgBytes&&tgNeed>tgBytes;"
         "const fs=document.getElementById('tg-fmt');"
         "const fn=fs&&fs.selectedOptions[0]?fs.selectedOptions[0].textContent:'';"
         "const n=document.getElementById('tg-note');"
         "if(n)n.textContent=small"
         "?M.toosmall.replace('%s',fn).replace('%u',tgNeed).replace('%u',tgBytes)"
         ":((tgLinked&&tgUid&&tgLinked!=tgUid)?M.relink.replace('%s',tgLinked):'');"
         "const er=document.getElementById('tg-erase');"
         "if(er)er.disabled=!tgUid||tgCur=='blank';"
         "if(!tgNew){b.disabled=true;b.textContent=M.pickf;return;}"
         "if(small){b.disabled=true;b.textContent=M.write;return;}"
         "if(tgCur===tgNew){b.disabled=true;b.textContent=M.match;}"
         "else{b.disabled=false;b.textContent=tgCur&&tgCur!='blank'?M.over:M.write;}}"
         "function loadPreview(){const v=parseInt(document.getElementById('tg-id').value);"
         "const f=document.getElementById('tg-fmt').value;"
         "if(!v){tgNew='';tgNewI=null;tgSync();return;}"
         "fetch('/api/tag/preview?id='+v+'&fmt='+f).then(r=>r.json()).then(d=>{"
         "tgNew=d.ok?d.preview:'';tgLinked=d.ok?(d.linked||''):'';"
         "tgNeed=d.ok?(d.need||0):0;"
         "tgNewI=d.ok?d.info:null;tgSync();})"
         ".catch(()=>{tgNew='';tgNewI=null;tgNeed=0;tgSync();});}"
         "function setOpt(p,t){p.innerHTML='';const o=document.createElement('option');"
         "o.value='';o.textContent=t;p.appendChild(o);}"
         "function pickSpool(){const p=document.getElementById('tg-pick');"
         "if(p.value)document.getElementById('tg-id').value=p.value;loadPreview();}"
         "function loadSpools(){const p=document.getElementById('tg-pick');if(!p)return;"
         "setOpt(p,M.pick);"
         "fetch('/api/spools').then(r=>r.json()).then(d=>{"
         "if(d.error){setOpt(p,d.error);return;}"
         "setOpt(p,M.pick);"
         "d.forEach(s=>{const o=document.createElement('option');o.value=s.id;"
         "o.textContent='#'+s.id+'  '+s.label;p.appendChild(o);});"
         "}).catch(()=>setOpt(p,M.nolist));}"
         "function tgPoll(){fetch('/api/tag').then(r=>r.json()).then(d=>{"
         "document.getElementById('tg-uid').textContent="
         "d.uid?(M.onread+' '+d.uid+' ('+d.kind+')'):M.notag;"
         "tgUid=d.uid||'';tgCurI=d.uid?d.info:null;tgBytes=d.bytes||0;"
         "tgCur=d.content||'';tgSync();"
         "const s=document.getElementById('tg-s');"
         "if(d.state!='idle'){s.textContent=d.message;"
         "s.className='msg'+(d.state=='error'?' bad':'');}}).catch(()=>{});}"
         "function after(){setTimeout(tgPoll,1500);setTimeout(tgPoll,4000);}"
         "function eraseTag(){if(!confirm(M.eraseq))return;"
         "fetch('/api/tag/write',{method:'POST',body:'0,2,0'})"
         ".then(r=>r.json()).then(d=>{document.getElementById('tg-s').textContent="
         "d.message||M.queued;}).catch(()=>{});after();}"
         "function writeTag(){const v=parseInt(document.getElementById('tg-id').value);"
         "if(!v){document.getElementById('tg-s').textContent=M.pickf;return;}"
         "const f=document.getElementById('tg-fmt').value;"
         "const l=document.getElementById('tg-link').checked?1:0;"
         "fetch('/api/tag/write',{method:'POST',body:v+','+f+','+l})"
         ".then(r=>r.json()).then(d=>{document.getElementById('tg-s').textContent="
         "d.message||M.queued;}).catch(()=>{});after();}"
         "document.addEventListener('DOMContentLoaded',()=>{"
         "tgPoll();setInterval(tgPoll,3000);loadSpools();tgSync();});"
         "</script>");
  return h;
}

// The dropdown's values, in one place. Two call sites used to spell the same
// ternary out by hand, and a third format would have had to be added to both.
static TagFormat fmtFromInt(int f) {
  switch (f) {
    case 0:  return TAG_FMT_ACE;
    case 2:  return TAG_FMT_ERASE;
    case 3:  return TAG_FMT_FILAMAN;
    default: return TAG_FMT_OPENSPOOL;
  }
}

static void routes(WebServer &srv) {
  srv.on("/api/tag/preview", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_TAGS))) return;
    int id  = srv.arg("id").toInt();
    int fmt = srv.arg("fmt").toInt();
    char prev[128] = "", linked[40] = "";
    TagInfo ti;
    uint16_t need = 0;
    bool ok = tagPreview(id, fmtFromInt(fmt),
                         prev, sizeof(prev), linked, sizeof(linked), &ti, &need);
    char info[320];
    tagInfoJson(&ti, info, sizeof(info));
    // jsonEsc on both: prev carries the backend's vendor and filament names,
    // and a quotation mark in a brand made the reply malformed. r.json() then
    // throws and the preview silently stops updating - the same fault the
    // sibling route was fixed for.
    srv.send(200, "application/json",
      String("{\"ok\":") + (ok ? "true" : "false") + ",\"info\":" + info +
      ",\"need\":" + String((unsigned)need) +
      ",\"preview\":\"" + jsonEsc(prev) + "\",\"linked\":\"" + jsonEsc(linked) + "\"}");
  });

  srv.on("/api/spools", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_TAGS))) return;

    // Four fields per spool instead of the whole record. Without the filter a
    // large inventory is parsed in full - 268 spools came to 176 kB in the
    // lookup path this mirrors - and none of it is used here.
    StaticJsonDocument<256> filter;
    JsonObject f = filter.to<JsonArray>().createNestedObject();
    f["id"] = true;
    JsonObject ff = f.createNestedObject("filament");
    ff["name"] = true;
    ff["material"] = true;
    ff.createNestedObject("vendor")["name"] = true;

    // PSRAM, not the internal heap. This runs inside an HTTP handler, which is
    // the worst moment to be holding the inventory in the 320 kB the rest of
    // the firmware shares. Same reasoning as f2e61db for the GitHub release
    // list.
    SpiRamAllocator psram_alloc;
    JsonDocument doc(&psram_alloc);
    int code = backendGetSpoolListJson(backendBaseUrl(), false, doc, 8000, &filter);
    if (code != 200) {
      srv.send(200, "application/json",
                      String("{\"error\":\"backend HTTP ") + code + "\"}");
      return;
    }

    // Streamed rather than assembled. The old version built the entire reply
    // as one String on top of the parsed document, so the inventory was on
    // the heap twice at once.
    //
    // Deliberately not clipped to spool_list_limit: that limit exists because
    // an LVGL picker with hundreds of rows runs the device out of memory, and
    // a browser has no such problem. Clipping here would just hide spool 200
    // from the one page whose job is picking any spool.
    srv.setContentLength(CONTENT_LENGTH_UNKNOWN);
    srv.send(200, "application/json", "");
    String chunk = "[";
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
      if (!first) chunk += ",";
      first = false;
      chunk += "{\"id\":" + String(id) + ",\"label\":\"" + label + "\"}";
      if (chunk.length() >= 1024) { srv.sendContent(chunk); chunk = ""; }
    }
    chunk += "]";
    srv.sendContent(chunk);
    srv.sendContent("");   // terminates the chunked response
  });

  srv.on("/api/tag", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_TAGS))) return;
    // Reader state comes from the loop task; touching the reader here would
    // race the main NFC poll.
    char info[320];
    tagInfoJson(tagCachedInfo(), info, sizeof(info));
    String j = String("{\"info\":") + info +
               ",\"bytes\":"    + String((unsigned)tagCachedBytes()) +
               ",\"uid\":\""     + jsonEsc(tagCachedUid()) +
               "\",\"kind\":\""    + jsonEsc(tagCachedKind()) +
               "\",\"state\":\""   + jsonEsc(tagWriteState()) +
               "\",\"message\":\"" + jsonEsc(tagWriteMessage()) +
               "\",\"content\":\"" + jsonEsc(tagCachedContent()) + "\"}";
    srv.send(200, "application/json", j);
  });

  srv.on("/api/tag/write", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_TAGS))) return;
    if (!srv.hasArg("plain")) { srv.send(400, "application/json", "{\"error\":\"no body\"}"); return; }
    String body = srv.arg("plain");
    int c1 = body.indexOf(',');
    int c2 = c1 < 0 ? -1 : body.indexOf(',', c1 + 1);
    int id  = body.substring(0, c1 < 0 ? body.length() : c1).toInt();
    int fmt = c1 < 0 ? 0 : body.substring(c1 + 1, c2 < 0 ? body.length() : c2).toInt();
    bool link = c2 >= 0 && body.substring(c2 + 1).toInt() == 1;
    bool ok = tagWriteRequest(id, fmtFromInt(fmt), link);
    srv.send(200, "application/json",
      ok ? "{\"message\":\"Queued, keep the tag on the reader.\"}"
         : "{\"message\":\"Busy or invalid spool ID.\"}");
  });
}

extern const WebPage PAGE_TAGS;
const WebPage PAGE_TAGS = {
  "/tags", label, GATE_MAINT, nullptr,
  body, routes
};
