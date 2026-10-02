// Colour scheme. The scale and this interface share one palette; this is where
// it is chosen, with a preview card per palette drawn in the browser from the
// same table the scale reads (ui/theme_palette.h). The scale takes a new
// palette with a restart, because LVGL copies a colour into an object when
// the object is made.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>

#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "ui/theme.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro, see page_drying.cpp.
#include "lang.h"

static const char* label() { return T(STR_W_NAV_THEME); }

// The mock screens, one stylesheet for both palettes: every colour is a
// variable the script sets on the preview from the palette table. Sizes in
// cqw so the 480 x 320 panel scales with its card.
static const char THEME_CSS[] PROGMEM =
    "<style>"
    ".tgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}"
    ".tcard{display:flex;flex-direction:column;gap:10px;padding:12px;border-radius:12px;"
    "background:var(--surface-2);border:1px solid var(--line-soft);cursor:pointer;text-align:left;"
    "font:inherit;color:var(--ink-2);white-space:normal;font-weight:400;"
    // The mocks size their type off the card: cqw inside .tm is card width.
    "container-type:inline-size}"
    // The shared button look would repaint the card on hover.
    ".tcard:hover{background:var(--surface-2)}"
    ".tcard[aria-pressed=true]{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}"
    ".tcard .thead{display:flex;align-items:center;justify-content:space-between;gap:8px;"
    "font-size:14px;font-weight:600;color:var(--ink)}"
    ".tm{position:relative;width:100%;aspect-ratio:3/2;"
    "overflow:hidden;border-radius:6px;background:var(--GROUND);font-size:4.2cqw;"
    "line-height:1.25;font-family:var(--sans);color:var(--INK)}"
    ".tm small{display:block;font-size:.72em;color:var(--CAPTION)}"
    ".tm b{font-weight:500}"
    ".tm-hdr{display:flex;justify-content:space-between;align-items:center;padding:1.2cqw 2cqw;"
    "border-bottom:1px solid var(--LINE);color:var(--INK_FAINT);font-size:.72em}"
    ".tm-chip{padding:0 1.4cqw;border:1px solid var(--ACCENT);border-radius:1cqw;"
    "background:var(--CHIP);color:var(--ACCENT)}"
    ".tm-st{padding:1.2cqw 2cqw;color:var(--GOOD)}"
    ".tm-row{display:flex;gap:3cqw;padding:0 2cqw 1.6cqw;align-items:center}"
    ".tm-sw{width:8cqw;height:8cqw;border-radius:1.4cqw;background:#9fd3e8;flex:none}"
    ".tm-div{height:1px;margin:0 2cqw 1.6cqw;background:var(--ROW)}"
    ".tm-bar{height:1.4cqw;margin:0 2cqw 2cqw;border-radius:1cqw;background:var(--RULE)}"
    ".tm-bar i{display:block;width:70%;height:100%;border-radius:1cqw;background:var(--GOOD)}"
    ".tm-btns{display:flex;gap:2cqw;padding:0 2cqw}"
    ".tm-btns span{flex:1;text-align:center;padding:2cqw 0;border-radius:1.6cqw;border:1px solid}"
    ".tm-go{background:var(--WEIGHT_BG);border-color:var(--WEIGHT_BG_PRESSED)!important;color:var(--WEIGHT_TEXT)}"
    ".tm-blue{background:var(--CHIP);border-color:var(--POPUP_BORDER)!important;color:var(--STATUS_BLUE)}"
    ".tm-title{padding:2.4cqw 2cqw;text-align:center;color:var(--ACCENT);font-size:1.1em}"
    ".tm-x{position:absolute;right:2cqw;top:1.6cqw;width:8cqw;height:7cqw;border-radius:1.4cqw;"
    "background:var(--BAD_BG);color:var(--BAD_TEXT);display:flex;align-items:center;justify-content:center}"
    ".tm-tiles{display:grid;grid-template-columns:1fr 1fr;gap:2cqw;padding:0 2cqw}"
    ".tm-tile{background:var(--ROW);border:1px solid var(--LINE_SOFT);border-radius:2cqw;"
    "padding:2cqw 2.4cqw;min-height:17cqw}"
    ".tm-tile i{display:block;width:4cqw;height:4cqw;border-radius:1cqw;background:var(--ACCENT);"
    "margin-bottom:1cqw}"
    ".tm-scrim{position:absolute;inset:0;background:var(--SCRIM);opacity:.7}"
    ".tm-pop{position:absolute;left:14%;right:14%;top:22%;padding:3cqw;border-radius:2.4cqw;"
    "background:var(--SURFACE);border:1px solid var(--POPUP_BORDER);text-align:center}"
    ".tm-pop p{color:var(--INK_2);font-size:.85em;margin:1.4cqw 0 2.6cqw}"
    ".tm-pop .tm-btns{padding:0}"
    ".tm-no{background:var(--BAD_BG);border-color:var(--BAD_BG_PRESSED)!important;color:var(--BAD_TEXT)}"
    ".tm-ok{background:var(--OK_BG);border-color:var(--OK_BG_PRESSED)!important;color:var(--OK_TEXT)}"
    // Own colours: rows of swatch chips, two sliders and a preview pair.
    ".clbl{color:var(--ink)}"
    ".csec{display:flex;flex-direction:column;gap:10px;padding:14px 0;border-bottom:1px solid var(--line-soft)}"
    ".cchips{display:flex;flex-wrap:wrap;gap:6px;align-items:center}"
    ".cchip{padding:6px 11px;font-size:12.5px;display:inline-flex;align-items:center;gap:7px}"
    ".cchip i,.hsw{display:inline-block;width:14px;height:14px;border-radius:4px;background:var(--c);"
    "box-shadow:inset 0 0 0 1px rgba(128,128,128,.45)}"
    ".cchip[aria-pressed=true]{background:var(--btn);color:var(--accent);border-color:var(--accent)}"
    "input[type=color]{width:42px;height:32px;padding:2px;border:1px solid var(--line);border-radius:8px;"
    "background:var(--ground);cursor:pointer}"
    ".cchips input[type=range]{flex:0 1 240px}"
    ".cprev{display:grid;grid-template-columns:1fr 1fr;gap:12px}"
    ".cprev .tcard{cursor:default}"
    "@media(max-width:700px){.cprev{grid-template-columns:1fr}}"
    "</style>";

static String body() {
  String h;
  h.reserve(9600);
  h += FPSTR(THEME_CSS);
  h += F("<div class='grid'><div class='card wide'><h2>");
  h += T(STR_W_C_THEME);
  h += F("</h2><p class='hint' style='margin-bottom:14px'>");
  h += T(STR_W_THEME_HINT);
  h += F("</p><div class='tgrid' id='tgrid'></div>"
         // Shown while the palette that would run is a light one: the panel
         // builds a frame in strips, which a light palette makes visible.
         "<p class='hint' id='tlight' style='margin-top:12px' hidden>");
  h += T(STR_W_THEME_LIGHT_NOTE);
  h += F("</p></div>");

  // The palette follows the backend: the family from it, light or dark from
  // the choice above.
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_THEME_FOLLOW_H);
  h += F("</h2><div class='rows'><div class='row' style='align-items:center'><div><div class='clbl'>");
  h += T(STR_W_THEME_FOLLOW);
  h += F("</div><div class='hint'>");
  h += T(STR_W_THEME_FOLLOW_HINT);
  h += F("</div></div><label class='switch'><input type='checkbox' id='follow'><i></i></label></div>"
         "<div class='row'><span>");
  h += T(STR_W_THEME_AFTER);
  h += F("</span><b id='fres' class='clbl'></b></div></div></div>");

  // This page alone in light or dark as the browser says. Saved on the spot:
  // the panel is not touched, so there is nothing to apply or restart.
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_THEME_WEB_H);
  h += F("</h2><div class='rows'><div class='row' style='align-items:center'><div><div class='clbl'>");
  h += T(STR_W_THEME_WEB_OS);
  h += F("</div><div class='hint'>");
  h += T(STR_W_THEME_WEB_OS_HINT);
  h += F("</div><span class='msg' id='wmsg'></span></div>"
         "<label class='switch'><input type='checkbox' id='webos'><i></i></label></div></div></div>");

  // Own colours over it: an accent, a tone and its strength.
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_THEME_OWN_H);
  h += F("</h2><p class='hint'>");
  h += T(STR_W_THEME_OWN_HINT);
  h += F("</p><div class='csec'><div><div class='clbl'>");
  h += T(STR_W_THEME_ACCENT);
  h += F("</div><div class='hint'>");
  h += T(STR_W_THEME_ACCENT_HINT);
  h += F("</div></div><div class='cchips' id='acc'></div><div class='cchips'><label class='hint' for='accpick'>");
  h += T(STR_W_THEME_OWN_COLOUR);
  h += F("</label><input type='color' id='accpick' value='#ff9442'><span class='pill' id='accpill'></span></div>"
         "<p class='hint' id='acchint'></p></div><div class='csec'><div><div class='clbl'>");
  h += T(STR_W_THEME_TONE);
  h += F("</div><div class='hint'>");
  h += T(STR_W_THEME_TONE_HINT);
  h += F("</div></div><div class='cchips' id='hue'></div><div class='cchips'><label class='hint' for='huerange'>");
  h += T(STR_W_THEME_HUE);
  h += F("</label><input type='range' id='huerange' min='0' max='359' value='300'><i class='hsw' id='hsw'></i></div>"
         "<div class='cchips'><label class='hint' for='strrange'>");
  h += T(STR_W_THEME_STRENGTH);
  h += F("</label><input type='range' id='strrange' min='0' max='100' value='50'><span class='hint' id='strlbl'></span>"
         "</div><p class='hint'>");
  h += T(STR_W_THEME_STRENGTH_HINT);
  h += F("</p></div><div class='csec' style='border-bottom:0'><div class='clbl'>");
  h += T(STR_W_THEME_PREVIEW);
  h += F("</div><div class='cprev' id='cprev'></div><div class='inrow'><button class='quiet' id='creset' type='button'>");
  h += T(STR_W_THEME_RESET);
  h += F("</button></div></div></div></div>");

  h += F("<div class='inrow'><button id='tapply' disabled>");
  h += T(STR_W_THEME_APPLY);
  h += F("</button><span class='msg' id='tmsg'></span></div>");

  h += F("<script>");
  h += webShellJsStrings();
  h += F("const TT={names:{dark:");
  h += jsStr(T(STR_W_THEME_DARK));
  h += F(",light:");
  h += jsStr(T(STR_W_THEME_LIGHT));
  h += F(",spoolman_dark:");
  h += jsStr(T(STR_W_THEME_SPOOLMAN_DARK));
  h += F(",spoolman_light:");
  h += jsStr(T(STR_W_THEME_SPOOLMAN_LIGHT));
  h += F(",filaman_dark:");
  h += jsStr(T(STR_W_THEME_FILAMAN_DARK));
  h += F(",filaman_light:");
  h += jsStr(T(STR_W_THEME_FILAMAN_LIGHT));
  h += F("},active:");
  h += jsStr(T(STR_W_THEME_ACTIVE));
  h += F(",later:");
  h += jsStr(T(STR_W_THEME_LATER));
  h += F(",restarting:");
  h += jsStr(T(STR_W_THEME_RESTARTING));
  h += F(",tag:");
  h += jsStr(T(STR_TAG_FOUND));
  h += F(",material:");
  h += jsStr(T(STR_DRY_MODE_MATERIAL));
  h += F(",vendor:");
  h += jsStr(T(STR_LBL_VENDOR));
  h += F(",scale:");
  h += jsStr(T(STR_LBL_SCALE));
  h += F(",weight:");
  h += jsStr(T(STR_BTN_WEIGHT));
  h += F(",dried:");
  h += jsStr(T(STR_BTN_DRIED));
  h += F(",settings:");
  h += jsStr(T(STR_SETTINGS_TITLE));
  h += F(",tiles:[");
  h += jsStr(T(STR_TILE_CONNECTION));
  h += F(",");
  h += jsStr(T(STR_TILE_SCALE));
  h += F(",");
  h += jsStr(T(STR_TILE_DISPLAY));
  h += F(",");
  h += jsStr(T(STR_TILE_SYSTEM));
  h += F("],cancel:");
  h += jsStr(T(STR_CANCEL));
  h += F(",yes:");
  h += jsStr(T(STR_AMS_TIMER_YES));
  h += F(",own:");
  h += jsStr(T(STR_W_THEME_SCHEME_OWN));
  h += F(",onbg:");
  h += jsStr(T(STR_W_THEME_ON_BG));
  h += F(",faint:");
  h += jsStr(T(STR_W_THEME_FAINT));
  h += F(",weaker:");
  h += jsStr(T(STR_W_THEME_WEAKER));
  h += F(",plus:");
  h += jsStr(T(STR_W_THEME_PLUS_OWN));
  h += F(",cn:{orange:");
  h += jsStr(T(STR_W_COL_ORANGE));
  h += F(",pink:");
  h += jsStr(T(STR_W_COL_PINK));
  h += F(",blue:");
  h += jsStr(T(STR_W_COL_BLUE));
  h += F(",violet:");
  h += jsStr(T(STR_W_COL_VIOLET));
  h += F(",yellow:");
  h += jsStr(T(STR_W_COL_YELLOW));
  h += F(",petrol:");
  h += jsStr(T(STR_W_COL_PETROL));
  h += F(",red:");
  h += jsStr(T(STR_W_COL_RED));
  h += F(",green:");
  h += jsStr(T(STR_W_COL_GREEN));
  h += F(",sand:");
  h += jsStr(T(STR_W_COL_SAND));
  h += F("}");
  h += F("};"
         // The two mock screens, filled from TT: nothing in here is a caption
         // of its own, every word is one the scale shows.
         "function esc(s){return String(s).replace(/[&<>]/g,function(c){"
         "return{'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}"
         "function mockMain(){return '<div class=\"tm\"><div class=\"tm-hdr\">"
         "<span>SpoolmanScale</span><span class=\"tm-chip\">NFC</span></div>"
         "<div class=\"tm-st\">&#9679; '+esc(TT.tag)+'</div>"
         "<div class=\"tm-row\"><i class=\"tm-sw\"></i>"
         "<div><small>'+esc(TT.material)+'</small><b>PLA</b></div>"
         "<div><small>Filament</small><b style=\"color:var(--INK_BRIGHT)\">Matte Ice Blue</b></div></div>"
         "<div class=\"tm-row\"><div><small>'+esc(TT.vendor)+'</small><b>Bambu Lab</b></div></div>"
         "<div class=\"tm-div\"></div>"
         "<div class=\"tm-row\"><div><small>Spoolman</small><b>915 g</b></div>"
         "<div><small>'+esc(TT.scale)+'</small><b style=\"color:var(--WARN)\">552 g</b></div>"
         "<div><small>Diff</small><b style=\"color:var(--BAD_TEXT)\">-363 g</b></div></div>"
         "<div class=\"tm-bar\"><i></i></div>"
         "<div class=\"tm-btns\"><span class=\"tm-go\">'+esc(TT.weight)+'</span>"
         "<span class=\"tm-blue\">'+esc(TT.dried)+'</span></div></div>';}"
         "function mockSettings(){var t=TT.tiles.map(function(n){"
         "return '<div class=\"tm-tile\"><i></i>'+esc(n)+'</div>';}).join('');"
         "return '<div class=\"tm\"><div class=\"tm-title\">'+esc(TT.settings)+'</div>"
         "<span class=\"tm-x\">&#10005;</span><div class=\"tm-tiles\">'+t+'</div>"
         "<div class=\"tm-scrim\"></div><div class=\"tm-pop\"><b>'+esc(TT.settings)+'</b>"
         "<p>'+esc(TT.tiles[1])+'?</p><div class=\"tm-btns\">"
         "<span class=\"tm-no\">'+esc(TT.cancel)+'</span>"
         "<span class=\"tm-ok\">'+esc(TT.yes)+'</span></div></div></div>';}"
         // The chosen palette and the own colours over it. CS is what the
         // controls say, CS0 what is stored: Apply is live only in between.
         "var sel=null,stored=null,BASE={},BACKEND='',CS0='',WEBK=['dark','light'],"
         "CS={accent:null,tone:-1,strength:50,follow:false},DARK={dark:1,spoolman_dark:1,filaman_dark:1};"
         "var ACC=[['ff9442','orange'],['ff5fa2','pink'],['2563eb','blue'],['8b5cf6','violet'],['e0b100','yellow'],['0e7490','petrol'],['e5484d','red']];"
         "var HUES=[[255,'4f7fd6','blue'],[200,'2f9aa6','petrol'],[150,'3f9f6a','green'],[300,'8a63d2','violet'],[20,'c85a5a','red'],[75,'c49a5c','sand']];"
         "function key(){return [sel,CS.accent||'-',CS.tone,CS.strength,CS.follow?1:0].join(',');}"
         "function resolved(){var s=sel||'dark';if(!CS.follow)return s;var d=DARK[s]?'_dark':'_light';"
         "if(BACKEND==='filaman')return 'filaman'+d;if(BACKEND==='spoolman')return 'spoolman'+d;"
         "return d==='_dark'?'dark':'light';}"
         "function paint(el,p){Object.keys(p).forEach(function(k){el.style.setProperty('--'+k,'#'+p[k]);});}"
         "function chip(g,sw,txt,on,fn){var b=document.createElement('button');b.type='button';"
         "b.className='quiet cchip';b.innerHTML='<i style=\"--c:#'+sw+'\"></i>'+(txt?esc(txt):'');"
         "if(!txt)b.setAttribute('aria-label','#'+sw);b.setAttribute('aria-pressed',on?'true':'false');"
         "b.addEventListener('click',fn);g.appendChild(b);}"
         "function update(){var id=resolved(),b=BASE[id];if(!b)return;var p=TC.apply(b,CS,!!DARK[id]);"
         "$('tlight').hidden=!!DARK[id];$('fres').textContent=(TT.names[id]||id)+(CS.accent||CS.tone>=0||CS.strength!==50?' '+TT.plus:'');"
         "var g=$('acc');g.textContent='';chip(g,b.ACCENT,TT.own,!CS.accent,function(){CS.accent=null;update();});"
         "ACC.forEach(function(a){chip(g,a[0],TT.cn[a[1]],CS.accent===a[0],function(){CS.accent=a[0];$('accpick').value='#'+a[0];update();});});"
         "g=$('hue');g.textContent='';chip(g,b.GROUND,TT.own,CS.tone<0,function(){CS.tone=-1;update();});"
         "HUES.forEach(function(h){chip(g,h[1],TT.cn[h[2]],CS.tone===h[0],function(){CS.tone=h[0];$('huerange').value=h[0];update();});});"
         "var cr=TC.contrast(p.ACCENT,p.GROUND),pl=$('accpill');pl.textContent=cr.toFixed(1)+':1 '+TT.onbg;"
         "pl.style.color=cr>=4.5?'var(--good)':cr>=3?'var(--warn)':'var(--bad)';"
         "$('acchint').textContent=cr<3?TT.faint:cr<4.5?TT.weaker:'';"
         "$('hsw').style.setProperty('--c','hsl('+$('huerange').value+',45%,50%)');"
         "$('strrange').value=CS.strength;$('strlbl').textContent=CS.strength+'%';$('follow').checked=CS.follow;"
         "var v=$('cprev');v.textContent='';[mockMain(),mockSettings()].forEach(function(m){"
         "var c=document.createElement('div');c.className='tcard';c.innerHTML=m;paint(c.querySelector('.tm'),p);v.appendChild(c);});"
         "$('tapply').disabled=(key()===CS0);}"
         "function pick(id){sel=id;document.querySelectorAll('.tcard[data-id]').forEach(function(c){"
         "c.setAttribute('aria-pressed',c.dataset.id===id?'true':'false');});update();}"
         "function render(d){stored=d.stored;BACKEND=d.backend;var o=d.custom||{};"
         "CS={accent:o.accent||null,tone:o.tone,strength:o.strength,follow:!!o.follow};"
         "var g=$('tgrid');g.textContent='';"
         "d.themes.forEach(function(th){BASE[th.id]=th.c;"
         "var c=document.createElement('button');c.type='button';c.className='tcard';"
         "c.dataset.id=th.id;"
         "c.innerHTML='<span class=\"thead\">'+esc(TT.names[th.id]||th.id)+"
         "(th.id===d.active?'<span class=\"pill ok\">'+esc(TT.active)+'</span>':'')+'</span>'"
         "+mockMain()+mockSettings();"
         "c.querySelectorAll('.tm').forEach(function(m){paint(m,th.c);});"
         "c.addEventListener('click',function(){pick(th.id);});g.appendChild(c);});"
         "if(CS.accent)$('accpick').value='#'+CS.accent;if(CS.tone>=0)$('huerange').value=CS.tone;"
         "sel=d.stored;CS0=key();pick(d.stored);"
         "WEBK=[d.web_dark,d.web_light];$('webos').checked=!!d.web_os;}"
         "$('follow').addEventListener('change',function(){CS.follow=this.checked;update();});"
         "$('webos').addEventListener('change',function(){var on=this.checked,box=this;"
         "post('/api/theme/web',on?'1':'0').then(function(r){"
         "if(!r.ok||!r.json||!r.json.ok){box.checked=!on;flash('wmsg',WS.err,true,4000);return;}"
         "SCH.set(on,WEBK[0],WEBK[1]);flash('wmsg',WS.ok,false,2500);});});"
         "$('accpick').addEventListener('input',function(){CS.accent=this.value.slice(1);update();});"
         "$('huerange').addEventListener('input',function(){CS.tone=+this.value;update();});"
         "$('strrange').addEventListener('input',function(){CS.strength=+this.value;update();});"
         "$('creset').addEventListener('click',function(){CS.accent=null;CS.tone=-1;CS.strength=50;update();});"
         // The palette first, then the own colours: the second answer carries
         // the restart decision.
         "$('tapply').addEventListener('click',function(){"
         "if(!sel)return;$('tapply').disabled=true;"
         "post('/api/theme',sel).then(function(r){if(!r.ok||!r.json||!r.json.ok)return r;"
         "return post('/api/theme/custom',[CS.accent||'-',CS.tone,CS.strength,CS.follow?1:0].join(','));})"
         ".then(function(r){"
         "if(!r.ok||!r.json||!r.json.ok){flash('tmsg',WS.err,true,4000);$('tapply').disabled=false;return;}"
         "stored=sel;CS0=key();"
         "if(!r.json.restart){flash('tmsg',TT.later,false);return;}"
         "post('/api/restart','').then(function(){flash('tmsg',TT.restarting,false);"
         "setTimeout(function(){location.reload();},9000);});});});"
         "getJson('/api/theme').then(function(d){if(d)render(d);"
         "else flash('tmsg',WS.err,true);});"
         "</script>");
  return h;
}

#define HEX_RGB_DIGITS 6

// "accent,tone,strength,follow" into c; false on anything out of range.
static bool parseCustom(const char* body, UiThemeCustom* c) {
  char acc[8] = {0};
  int tone = 0, strength = 0, follow = 0;
  if (!body || sscanf(body, "%7[^,],%d,%d,%d", acc, &tone, &strength, &follow) != 4) return false;
  c->has_accent = strcmp(acc, "-") != 0;
  c->accent = 0;
  if (c->has_accent) {
    if (strlen(acc) != HEX_RGB_DIGITS || strspn(acc, "0123456789abcdefABCDEF") != HEX_RGB_DIGITS) return false;
    c->accent = strtoul(acc, nullptr, 16);
  }
  if (tone != UI_TONE_NONE && (tone < 0 || tone > 359)) return false;
  if (strength < 0 || strength > UI_TONE_STRENGTH_MAX) return false;
  if (follow != 0 && follow != 1) return false;
  c->tone = (int16_t)tone;
  c->strength = (uint8_t)strength;
  c->follow = follow == 1;
  return true;
}

static void routes(WebServer &srv) {
  // Both palettes as name -> hex, for the preview. Read from the same table
  // the scale fills its colours from, so the preview cannot drift from it.
  srv.on("/api/theme", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_THEME))) return;
    String json;
    json.reserve(4800);
    json += F("{\"active\":\"");
    json += uiThemeKey(uiThemeActive());
    json += F("\",\"stored\":\"");
    json += uiThemeKey(uiThemeStored());
    json += F("\",\"themes\":[");
    char hex[8];
    for (uint8_t t = 0; t < UI_THEME_COUNT; t++) {
      if (t) json += ',';
      json += F("{\"id\":\"");
      json += uiThemeKey((UiThemeId)t);
      json += F("\",\"c\":{");
      for (size_t i = 0; i < uiPaletteCount(); i++) {
        if (i) json += ',';
        json += '"';
        json += uiPaletteName(i);
        snprintf(hex, sizeof(hex), "%06lx", (unsigned long)uiPaletteValue((UiThemeId)t, i));
        json += F("\":\"");
        json += hex;
        json += '"';
      }
      json += F("}}");
    }
    // The backend decides the family when the palette follows it; the own
    // colours as stored, for the controls.
    const UiThemeCustom own = uiThemeCustomStored();
    json += F("],\"backend\":\"");
    json += backendIsFilaMan() ? F("filaman") : backendIsBamBuddy() ? F("bambuddy") : F("spoolman");
    json += F("\",\"custom\":{\"accent\":");
    if (own.has_accent) {
      snprintf(hex, sizeof(hex), "%06lx", (unsigned long)own.accent);
      json += '"';
      json += hex;
      json += '"';
    } else {
      json += F("null");
    }
    json += F(",\"tone\":");
    json += (int)own.tone;
    json += F(",\"strength\":");
    json += (int)own.strength;
    json += F(",\"follow\":");
    json += own.follow ? F("true") : F("false");
    // The web pages' own setting, and the two palettes they would switch
    // between: the family the scale runs now.
    json += F("},\"web_os\":");
    json += uiWebFollowsSystem() ? F("true") : F("false");
    json += F(",\"web_dark\":\"");
    json += uiThemeKey(uiThemeInFamily(uiThemeActive(), true));
    json += F("\",\"web_light\":\"");
    json += uiThemeKey(uiThemeInFamily(uiThemeActive(), false));
    json += F("\"}");
    srv.send(200, "application/json", json);
  });

  // Body: the palette's key as plain text. Stored for the next boot; the
  // answer says whether this browser may restart the scale right away, which
  // is the maintenance gate's call, not this one's.
  srv.on("/api/theme", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_THEME))) return;
    UiThemeId id;
    if (!uiThemeFromKey(srv.arg("plain").c_str(), &id)) {
      srv.send(400, "application/json", "{\"ok\":false}");
      return;
    }
    if (!uiThemeStore(id)) {
      logSD("Theme: storing the choice failed");
      srv.send(500, "application/json", "{\"ok\":false}");
      return;
    }
    logSDf("Theme: %s chosen, active after restart", uiThemeKey(id));
    srv.send(200, "application/json",
             webGateOpen(GATE_MAINT) ? "{\"ok\":true,\"restart\":true}"
                                     : "{\"ok\":true,\"restart\":false}");
  });

  // Body: "1" or "0". The web pages take light or dark from the browser, or
  // the scale's palette. Nothing on the panel changes, so no restart.
  srv.on("/api/theme/web", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_THEME))) return;
    const String b = srv.arg("plain");
    if (b != "0" && b != "1") {
      srv.send(400, "application/json", "{\"ok\":false}");
      return;
    }
    if (!uiWebFollowsSystemStore(b == "1")) {
      logSD("Theme: storing the web setting failed");
      srv.send(500, "application/json", "{\"ok\":false}");
      return;
    }
    logSDf("Theme: web pages %s", b == "1" ? "follow the browser" : "follow the scale");
    srv.send(200, "application/json", "{\"ok\":true}");
  });

  // Body: "accent,tone,strength,follow", e.g. "ff9442,300,50,1"; "-" for no
  // accent, -1 for the palette's own tone. Stored for the next boot.
  srv.on("/api/theme/custom", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_THEME))) return;
    UiThemeCustom c;
    if (!parseCustom(srv.arg("plain").c_str(), &c)) {
      srv.send(400, "application/json", "{\"ok\":false}");
      return;
    }
    if (!uiThemeCustomStore(c)) {
      logSD("Theme: storing the own colours failed");
      srv.send(500, "application/json", "{\"ok\":false}");
      return;
    }
    logSDf("Theme: own colours accent %s%06lx, tone %d, strength %u, follow %d",
           c.has_accent ? "#" : "none ", (unsigned long)c.accent, (int)c.tone,
           (unsigned)c.strength, c.follow ? 1 : 0);
    srv.send(200, "application/json",
             webGateOpen(GATE_MAINT) ? "{\"ok\":true,\"restart\":true}"
                                     : "{\"ok\":true,\"restart\":false}");
  });
}

extern const WebPage PAGE_THEME;
const WebPage PAGE_THEME = {
  "/theme", label, GATE_CONFIG, nullptr,
  body, routes
};
