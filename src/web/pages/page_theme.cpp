// Colour scheme. The scale and this interface share one palette; this is where
// it is chosen, with a preview of both palettes drawn in the browser from the
// same table the scale reads (ui/theme_palette.h). The scale takes a new
// palette with a restart, because LVGL copies a colour into an object when
// the object is made.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>

#include "hardware/sd_logger.h"
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
    ".tm-st{padding:1.2cqw 2cqw;color:var(--ACCENT)}"
    ".tm-row{display:flex;gap:3cqw;padding:0 2cqw 1.6cqw;align-items:center}"
    ".tm-sw{width:8cqw;height:8cqw;border-radius:1.4cqw;background:#9fd3e8;flex:none}"
    ".tm-div{height:1px;margin:0 2cqw 1.6cqw;background:var(--ROW)}"
    ".tm-bar{height:1.4cqw;margin:0 2cqw 2cqw;border-radius:1cqw;background:var(--RULE)}"
    ".tm-bar i{display:block;width:70%;height:100%;border-radius:1cqw;background:var(--ACCENT)}"
    ".tm-btns{display:flex;gap:2cqw;padding:0 2cqw}"
    ".tm-btns span{flex:1;text-align:center;padding:2cqw 0;border-radius:1.6cqw;border:1px solid}"
    ".tm-go{background:var(--GO_BG);border-color:var(--GO_BG_PRESSED)!important;color:var(--OK_TEXT_2)}"
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
    "</style>";

static String body() {
  String h;
  h.reserve(5200);
  h += FPSTR(THEME_CSS);
  h += F("<div class='grid'><div class='card wide'><h2>");
  h += T(STR_W_C_THEME);
  h += F("</h2><p class='hint' style='margin-bottom:14px'>");
  h += T(STR_W_THEME_HINT);
  h += F("</p><div class='tgrid' id='tgrid'></div>"
         "<div class='inrow' style='margin-top:16px'>"
         "<button id='tapply' disabled>");
  h += T(STR_W_THEME_APPLY);
  h += F("</button><span class='msg' id='tmsg'></span></div></div></div>");

  h += F("<script>");
  h += webShellJsStrings();
  h += F("const TT={names:{dark:");
  h += jsStr(T(STR_W_THEME_DARK));
  h += F(",light:");
  h += jsStr(T(STR_W_THEME_LIGHT));
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
         "var sel=null,stored=null;"
         "function pick(id){sel=id;"
         "document.querySelectorAll('.tcard').forEach(function(c){"
         "c.setAttribute('aria-pressed',c.dataset.id===id?'true':'false');});"
         "$('tapply').disabled=(id===stored);}"
         "function render(d){stored=d.stored;var g=$('tgrid');g.textContent='';"
         "d.themes.forEach(function(th){"
         "var c=document.createElement('button');c.type='button';c.className='tcard';"
         "c.dataset.id=th.id;"
         "c.innerHTML='<span class=\"thead\">'+esc(TT.names[th.id]||th.id)+"
         "(th.id===d.active?'<span class=\"pill ok\">'+esc(TT.active)+'</span>':'')+'</span>'"
         "+mockMain()+mockSettings();"
         "Object.keys(th.c).forEach(function(k){"
         "c.querySelectorAll('.tm').forEach(function(m){m.style.setProperty('--'+k,'#'+th.c[k]);});});"
         "c.addEventListener('click',function(){pick(th.id);});g.appendChild(c);});"
         "pick(d.stored);}"
         "$('tapply').addEventListener('click',function(){"
         "if(!sel)return;$('tapply').disabled=true;"
         "post('/api/theme',sel).then(function(r){"
         "if(!r.ok||!r.json||!r.json.ok){flash('tmsg',WS.err,true,4000);$('tapply').disabled=false;return;}"
         "stored=sel;"
         "if(!r.json.restart){flash('tmsg',TT.later,false);return;}"
         "post('/api/restart','').then(function(){flash('tmsg',TT.restarting,false);"
         "setTimeout(function(){location.reload();},9000);});});});"
         "getJson('/api/theme').then(function(d){if(d)render(d);"
         "else flash('tmsg',WS.err,true);});"
         "</script>");
  return h;
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
    json += F("]}");
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
}

extern const WebPage PAGE_THEME;
const WebPage PAGE_THEME = {
  "/theme", label, GATE_CONFIG, nullptr,
  body, routes
};
