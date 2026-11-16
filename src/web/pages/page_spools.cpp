// Empty spools of the user's own: a refill wound onto another maker's spool,
// filament respooled, a printed spool. Each one gets a name and its weight,
// typed in or taken off the scale with the empty spool on it, and stands in
// the list under a card's Options > Empty spool (services/spool_mine.h).
// Kept on the scale, the same for every backend.
#include "web/web_pages.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <WebServer.h>
#include <math.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/spool_mine.h"
#include "services/user_options.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

// How often the page asks for the weight on the pad, and how many readings in
// a row have to agree within SP_STEADY_G before one is taken.
#define SP_POLL_MS    1000
#define SP_STEADY_N   3
#define SP_STEADY_G   2

static const char* label() { return T(STR_W_NAV_SPOOLS); }

// The rows are drawn and read back in the browser; the page only hands over
// the list it starts from and the words it needs.
static const char SP_JS[] PROGMEM =
  "let spR=[],spG=[];"
  // Escaped for an attribute too: textContent leaves the double quote, and a
  // name with one would end the value="..." it is drawn into.
  "function spE(s){const d=document.createElement('div');d.textContent=String(s);"
  "return d.innerHTML.replace(/\"/g,'&quot;');}"
  // The scale counts the name in bytes (SPOOL_CHOICE_NAME_MAX), maxlength in characters.
  "function spBytes(s){return new TextEncoder().encode(s).length;}"
  "function spF(t,a){let i=0;return t.replace(/%[sd]/g,()=>a[i++]);}"
  "function spLast(){return spG.length?spG[spG.length-1]:null;}"
  "function spSteady(){const g=spLast();return spG.length>=SPT.n&&g>=SPT.min&&"
  "Math.max(...spG)-Math.min(...spG)<=SPT.band;}"
  "function spRow(r,i){return '<div class=inrow style=\"margin-top:10px\">'+"
  "'<input type=text data-k=n data-i='+i+' maxlength=31 style=\"flex:3 1 180px\" placeholder=\"'+spE(SPT.ph)+"
  "'\" aria-label=\"'+spE(SPT.name)+'\" value=\"'+spE(r.n)+'\">'+"
  "'<input data-k=g data-i='+i+' type=number inputmode=numeric min='+SPT.min+' max='+SPT.maxg+"
  "' style=\"flex:1 1 90px;text-align:right\" placeholder=g aria-label=\"'+spE(SPT.weight)+'\" value=\"'+spE(r.g)+'\">'+"
  "'<button class=quiet data-a=take data-i='+i+' data-ic=scale>'+spE(SPT.take)+'</button>'+"
  "'<button class=quiet data-a=rm data-i='+i+' data-ic=rm title=\"'+spE(SPT.rm)+'\" aria-label=\"'+spE(SPT.rm)+'\"></button>'+"
  "'</div>'+(r.t?'<span class=hint>'+spE(SPT.taken)+'</span>':'');}"
  "function spDraw(){$('sp-rows').innerHTML=spR.map(spRow).join('');"
  "$('sp-n').textContent=spF(SPT.count,[spR.length,SPT.max]);$('sp-add').disabled=spR.length>=SPT.max;spStatus();}"
  "function spStatus(){const g=spLast(),ok=spSteady();"
  "$('sp-scale').textContent=(g===null||g<SPT.min)?SPT.empty:"
  "spF(SPT.now,[Math.round(g)+' g'])+', '+(ok?SPT.steady:SPT.moving);"
  "document.querySelectorAll('#sp-rows button[data-a=take]').forEach(b=>{b.disabled=!ok;});}"
  "function spPoll(){getJson('/api/spools/scale').then(d=>{"
  "if(d&&d.ready){spG.push(d.g);if(spG.length>SPT.n)spG.shift();}else spG=[];"
  "spStatus();setTimeout(spPoll,SPT.poll);});}"
  "$('sp-rows').addEventListener('input',e=>{const t=e.target,i=+t.dataset.i;if(!spR[i])return;"
  "if(t.dataset.k==='n')spR[i].n=t.value;else{spR[i].g=t.value;spR[i].t=false;}});"
  "$('sp-rows').addEventListener('click',e=>{const b=e.target.closest('button[data-a]');if(!b)return;"
  "const i=+b.dataset.i;if(!spR[i])return;"
  "if(b.dataset.a==='rm'){spR.splice(i,1);if(!spR.length)spR.push({n:'',g:''});}"
  "else if(spSteady()){spR[i].g=Math.round(spLast());spR[i].t=true;}spDraw();});"
  "$('sp-add').addEventListener('click',()=>{if(spR.length<SPT.max){spR.push({n:'',g:''});spDraw();}});"
  "$('sp-save').addEventListener('click',()=>{const out=[];"
  "for(const r of spR){const n=String(r.n).trim(),g=parseInt(r.g,10);if(!n&&r.g==='')continue;"
  "if(!n||spBytes(n)>SPT.nmax||!(g>=SPT.min&&g<=SPT.maxg)){flash('sp-m',SPT.bad,true,6000);return;}"
  "out.push({name:n,g:g});}"
  "postFlash('/api/spools/empty',JSON.stringify({spools:out}),'sp-m',4000);});"
  "spR=SPD.length?SPD.map(s=>({n:s.name,g:s.g})):[{n:'',g:''}];spDraw();spPoll();";

static String listJson() {
  SpoolChoice mine[SPOOL_MINE_MAX];
  const int n = spoolMineLoad(mine);
  JsonDocument doc;
  JsonArray arr = doc.to<JsonArray>();
  for (int i = 0; i < n; i++) {
    JsonObject o = arr.add<JsonObject>();
    o["name"] = mine[i].name;
    o["g"]    = mine[i].weight_g;
  }
  String out;
  serializeJson(doc, out);
  return out;
}

static void wordsJs(String& h) {
  h += F("const SPT={");
  const struct { const char* key; int id; } WORDS[] = {
    { "ph", STR_W_SPOOLS_NAME_PH }, { "name", STR_W_SPOOLS_NAME }, { "weight", STR_W_SPOOLS_WEIGHT },
    { "take", STR_W_SPOOLS_TAKE }, { "taken", STR_W_SPOOLS_TAKEN }, { "rm", STR_W_SPOOLS_REMOVE },
    { "count", STR_W_SPOOLS_COUNT }, { "empty", STR_W_SPOOLS_EMPTY }, { "now", STR_W_SPOOLS_NOW },
    { "steady", STR_W_SPOOLS_STEADY }, { "moving", STR_W_SPOOLS_MOVING }, { "bad", STR_W_SPOOLS_INVALID },
  };
  for (const auto& w : WORDS) {
    h += w.key;
    h += ':';
    h += jsStr(T(w.id));
    h += ',';
  }
  h += F("max:");   h += SPOOL_MINE_MAX;
  h += F(",min:");  h += SPOOL_MINE_MIN_G;
  h += F(",maxg:"); h += SPOOL_MINE_MAX_G;
  h += F(",nmax:"); h += SPOOL_CHOICE_NAME_MAX - 1;
  h += F(",n:");    h += SP_STEADY_N;
  h += F(",band:"); h += SP_STEADY_G;
  h += F(",poll:"); h += SP_POLL_MS;
  h += F("};const SPD=JSON.parse(");
  h += jsStr(listJson().c_str());
  h += F(");");
}

static String body() {
  String h;
  h.reserve(2200 + sizeof(SP_JS));
  h += F("<div class='grid'><div class='card wide'><h2>");
  h += T(STR_W_NAV_SPOOLS);
  h += F("</h2><p class='hint' style='margin-top:0'>");
  h += htmlEsc(T(STR_W_SPOOLS_INTRO));
  h += F("</p><p class='hint' id='sp-scale' style='margin-top:10px'></p><div id='sp-rows'></div>"
         "<div class='inrow' style='margin-top:16px'><button class='quiet' id='sp-add' data-ic='add'>");
  h += T(STR_W_SPOOLS_ADD);
  h += F("</button><span class='hint' id='sp-n'></span></div>"
         "<div class='inrow' style='margin-top:16px'><button id='sp-save' data-ic='ok'>");
  h += T(STR_W_SAVE);
  h += F("</button><span class='msg' id='sp-m'></span></div></div></div><script>");
  h += webShellJsStrings();
  wordsJs(h);
  h += FPSTR(SP_JS);
  h += F("</script>");
  return h;
}

// The whole list as the page sends it: {"spools":[{"name":"...","g":152}]}.
// Every row has to hold, or nothing is saved.
static bool takeList(const String& text, SpoolChoice out[SPOOL_MINE_MAX], int* n) {
  JsonDocument doc;
  if (deserializeJson(doc, text)) return false;
  JsonArrayConst arr = doc["spools"].as<JsonArrayConst>();
  if (arr.isNull() || arr.size() > SPOOL_MINE_MAX) return false;
  *n = 0;
  for (JsonObjectConst o : arr) {
    if (!spoolMineMake(o["name"] | "", o["g"] | 0, &out[*n])) return false;
    (*n)++;
  }
  return true;
}

static void routes(WebServer& srv) {
  srv.on("/api/spools/empty", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SPOOLS))) return;
    srv.send(200, "application/json", listJson());
  });

  srv.on("/api/spools/empty", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SPOOLS))) return;
    SpoolChoice list[SPOOL_MINE_MAX];
    int n = 0;
    if (!takeList(srv.arg("plain"), list, &n)) {
      logSD("Webserver: empty spools refused, a row was not valid");
      srv.send(400, "application/json", "{\"ok\":false}");
      return;
    }
    const bool ok = spoolMineSave(list, n);
    logSDf("Webserver: %d empty spool(s) of the user's own %s", n, ok ? "saved" : "NOT saved");
    srv.send(ok ? 200 : 500, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
  });

  // The weight on the pad, for "From the scale". Read in the loop task that
  // serves this request, so it cannot be torn.
  srv.on("/api/spools/scale", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SPOOLS))) return;
    const bool ready = g_scale_fitted && scale_ready;
    String j = "{\"ready\":";
    j += ready ? "true" : "false";
    j += ",\"g\":";
    j += String(ready ? scale_weight_g : 0.0f, 1);
    j += "}";
    srv.send(200, "application/json", j);
  });
}

extern const WebPage PAGE_SPOOLS;
const WebPage PAGE_SPOOLS = {
  "/spools", label, GATE_CONFIG, nullptr,
  body, routes
};
