#include "theme_web.h"
#include "app_config.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "hardware/display.h"
#include "ota_web_server.h"
#include "prefs_store.h"
#include "web_access.h"
#include "web_shell.h"
#include "ui/theme.h"

static String hex6(uint32_t v) {
  char b[8];
  snprintf(b, sizeof(b), "#%06lx", (unsigned long)(v & 0xFFFFFFu));
  return String(b);
}

static uint32_t parseHex6(const String &s) {
  String t = s;
  t.trim();
  if (t.startsWith("#")) t = t.substring(1);
  return (uint32_t)strtoul(t.c_str(), nullptr, 16) & 0xFFFFFFu;
}

// ------------------------------------------------------------------- state

static String themeStateJson() {
  String j = "{\"gain\":" + String(displayGetUiGain());
  j += ",\"preset\":" + String(themeCurrentPreset());
  j += ",\"colors\":{";
  for (int i = 0; i < TH_COUNT; i++) {
    if (i) j += ",";
    j += "\"" + String(themeTokenId(i)) + "\":\"" + hex6(g_theme[i]) + "\"";
  }
  j += "}}";
  return j;
}

// -------------------------------------------------------------------- page

static String themePage() {
  String h;
  h.reserve(13000);
  h += webShellHead("Theme");

  // Page-specific widgets only. Everything structural -- palette, card, logo,
  // links, footer -- comes from the shared shell so this reads as the same
  // project as the other pages rather than a bolted-on tool.
  h += F("<style>"
         /* The shell caps content at 480px, which is right for a status page but
            wrong for a 20-row colour editor. Widened here only, so the rest of
            the site keeps its narrow column. */
         ".nav,.links,.card{max-width:1180px}"
         ".tgrid{display:grid;grid-template-columns:minmax(320px,460px) 1fr;gap:20px;"
         "align-items:start;width:100%;max-width:1180px}"
         ".tcol{display:flex;flex-direction:column}"
         ".tcol .card{margin-bottom:20px}"
         /* Colours flow into as many columns as the window allows rather than
            one long list. */
         ".cgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));"
         "gap:8px 22px}"
         ".crow{display:grid;grid-template-columns:1fr auto auto;gap:10px;align-items:center}"
         ".crow label{font-size:13px;color:#c8d8f0}"
         "@media(max-width:860px){.tgrid{grid-template-columns:1fr}}"
         "input[type=color]{width:42px;height:28px;border:1px solid #1a3060;border-radius:6px;"
         "background:#06080f;padding:2px;cursor:pointer}"
         "input[type=text]{width:88px;font:12px ui-monospace,Consolas,monospace;background:#06080f;"
         "color:#e8f0ff;border:1px solid #1a3060;border-radius:6px;padding:6px 8px}"
         "input[type=text]:focus{outline:none;border-color:#28d49a}"
         "input[type=range]{width:100%;accent-color:#28d49a}"
         "textarea{width:100%;height:60px;font:12px ui-monospace,Consolas,monospace;background:#06080f;"
         "color:#e8f0ff;border:1px solid #1a3060;border-radius:8px;padding:8px;box-sizing:border-box}"
         ".tbtn{padding:8px 14px;background:#0a1828;color:#28d49a;border:1px solid #1a3060;"
         "border-radius:8px;font-size:13px;cursor:pointer;font-family:inherit;margin:0 6px 6px 0}"
         ".tbtn:hover{background:#1a3060}"
         "#msg{font-size:12px;color:#40c080;min-height:16px;margin-top:8px}"
         /* 1:1 stand-in for the 480x320 panel */
         "#pv{width:100%;aspect-ratio:3/2;position:relative;border:1px solid #1a3060;"
         "border-radius:8px;overflow:hidden;font-size:12px}"
         "#pv .bar{position:absolute;left:0;top:0;right:0;height:11%}"
         "#pv .ttl{position:absolute;left:2.5%;top:2.5%;font-size:16px;font-weight:600}"
         "#pv .card2{position:absolute;left:2.5%;top:16%;width:52%;height:22%;border-radius:6px}"
         "#pv .btn2{position:absolute;top:16%;width:19%;height:22%;border-radius:6px;"
         "display:flex;align-items:center;justify-content:center;font-weight:600;font-size:11px}"
         "#pv .tiers{position:absolute;left:2.5%;top:44%;display:flex;gap:10px;flex-wrap:wrap}"
         "#pv .tile2{position:absolute;top:57%;width:45%;height:19%;border-radius:8px;border:1px solid}"
         "</style>");

  h += webShellNav("/theme");
  h += webShellLinks();

  h += F("<div class='tgrid'><div class='tcol'>"
         "<div class='card'><h2>Preview</h2><div id='pv'>"
         "<div class='bar'></div><div class='ttl'>SpoolmanScale</div>"
         "<div class='card2'><div style='padding:8px'>"
         "<div class='c-text' style='font-size:13px'>PLA Matte</div>"
         "<div class='c-muted' style='font-size:11px;margin-top:5px'>742 g left</div>"
         "</div></div>"
         "<div class='btn2' id='pv-ok' style='left:57%'>CONFIRM</div>"
         "<div class='btn2' id='pv-no' style='left:78%'>CANCEL</div>"
         "<div class='tiers'>"
         "<span class='c-bright'>Bright</span><span class='c-text'>Body</span>"
         "<span class='c-muted'>Muted</span><span class='c-dim'>Hint</span>"
         "<span class='c-warn'>Warning</span><span class='c-ok'>Success</span>"
         "<span class='c-danger'>Danger</span></div>"
         "<div class='tile2' id='pv-tile' style='left:2.5%'></div>"
         "<div class='tile2' id='pv-tile2' style='left:52.5%'></div>"
         "</div>"
         "<p class='hint' style='text-align:left'>Edits apply to the panel as you make them, "
         "but are not kept until you press Save. The main screen adopts a new palette after a "
         "restart; settings screens update as you reopen them.</p></div>"
         "</div><div class='tcol'>");

  h += F("<div class='card'><h2>Presets</h2>");
  for (int i = 0; i < THEME_PRESET_COUNT; i++) {
    h += "<button class='tbtn' onclick=\"preset(" + String(i) + ")\">" +
         String(themePresetName(i)) + "</button>";
  }
  h += F("</div>");

  h += F("<div class='card'><h2>UI brightness</h2>"
         "<input type='range' id='gain' min='100' max='260' step='10' "
         "oninput=\"gv.textContent=this.value;push()\"> "
         "<div class='hint' style='text-align:left'>Gamma lift, currently "
         "<span id='gv' style='color:#28d49a'></span>. Raises shadows and midtones without "
         "touching white, and applies everywhere immediately. Past about 200 the darkest "
         "tones start merging.</div></div>");

  h += F("<div class='card'><h2>Share</h2>"
         "<textarea id='io' spellcheck='false'></textarea>"
         "<div style='margin-top:10px'>"
         "<button class='tbtn' onclick='copyStr()'>Copy</button>"
         "<button class='tbtn' onclick='impStr()'>Apply pasted</button></div>"
         "<p class='hint' style='text-align:left'>Paste someone else's string and press Apply. "
         "Colours are keyed by name and the string carries the version it came from, so one "
         "written by a different build still applies: anything it does not mention keeps its "
         "current value, and you are told what was left alone.</p></div>"
         "</div></div>");

  h += F("<div class='card'><h2>Colours</h2><div class='cgrid'>");
  for (int i = 0; i < TH_COUNT; i++) {
    String id = String(themeTokenId(i));
    h += "<div class='crow'>";
    h += "<label for='" + id + "'>" + String(themeTokenLabel(i)) + "</label>";
    h += "<input type='text' id='" + id + "_h' spellcheck='false' "
         "oninput=\"hexEdit('" + id + "')\">";
    h += "<input type='color' id='" + id + "' oninput=\"pickEdit('" + id + "')\">";
    h += "</div>";
  }
  h += F("</div><div style='margin-top:14px'>"
         "<button class='tbtn' onclick='save()'>Save to device</button>"
         "<button class='tbtn' onclick='reset_()'>Reset to default</button>"
         "<button class='tbtn' onclick='doRestart()'>Restart device</button></div>"
         "<div id='msg'></div></div>");

  h += "<script>const FW='" + String(FW_VERSION) + "';";
  h += F("const IDS=[");
  for (int i = 0; i < TH_COUNT; i++) {
    if (i) h += ",";
    h += "'" + String(themeTokenId(i)) + "'";
  }
  h += F("];"
         "let st={};"
         "function g(id){return document.getElementById(id)}"
         "function norm(v){v=(v||'').trim().replace(/^#/,'');"
         "if(/^[0-9a-fA-F]{3}$/.test(v))v=v[0]+v[0]+v[1]+v[1]+v[2]+v[2];"
         "return /^[0-9a-fA-F]{6}$/.test(v)?('#'+v.toLowerCase()):null}"
         "function paint(){"
         "const c=st.colors,p=g('pv');"
         "p.style.background=c.bg;"
         "p.querySelector('.bar').style.background=c.surface;"
         "p.querySelector('.ttl').style.color=c.accent;"
         "p.querySelector('.card2').style.background=c.surface2;"
         "g('pv-ok').style.background=c.accent;g('pv-ok').style.color=c.black;"
         "g('pv-no').style.background=c.dangerbg;g('pv-no').style.color=c.dangertext;"
         "for(const e of p.querySelectorAll('.c-text'))e.style.color=c.text;"
         "for(const e of p.querySelectorAll('.c-bright'))e.style.color=c.textbright;"
         "for(const e of p.querySelectorAll('.c-muted'))e.style.color=c.textmuted;"
         "for(const e of p.querySelectorAll('.c-dim'))e.style.color=c.textdim;"
         "for(const e of p.querySelectorAll('.c-warn'))e.style.color=c.warning;"
         "for(const e of p.querySelectorAll('.c-ok'))e.style.color=c.oktext;"
         "for(const e of p.querySelectorAll('.c-danger'))e.style.color=c.dangertext;"
         "for(const t of [g('pv-tile'),g('pv-tile2')]){"
         "t.style.background=c.tile;t.style.borderColor=c.border}"
         "g('io').value=expStr()}"
         "function fill(){for(const i of IDS){g(i).value=st.colors[i];"
         "g(i+'_h').value=st.colors[i];g(i+'_h').style.borderColor='#1a3060'}"
         "g('gain').value=st.gain;g('gv').textContent=st.gain;paint()}"
         "async function load(){st=await(await fetch('/theme/state')).json();fill()}"
         "let t=null;"
         "function queue(){clearTimeout(t);t=setTimeout(send,120)}"
         "function pickEdit(id){st.colors[id]=g(id).value.toLowerCase();"
         "g(id+'_h').value=st.colors[id];g(id+'_h').style.borderColor='#1a3060';"
         "paint();queue()}"
         "function hexEdit(id){const el=g(id+'_h'),n=norm(el.value);"
         "if(!n){el.style.borderColor='#ff8080';return}"
         "el.style.borderColor='#1a3060';g(id).value=n;st.colors[id]=n;paint();queue()}"
         "function push(){st.gain=+g('gain').value;paint();queue()}"
         "async function send(){"
         "const p=new URLSearchParams();"
         "for(const i of IDS)p.append(i,st.colors[i]);"
         "p.append('gain',st.gain);"
         "await fetch('/theme/set',{method:'POST',body:p});"
         "g('msg').textContent='applied to panel (not saved yet)'}"
         "function expStr(){return 'SMS5:fw='+FW+','+IDS.map(function(i){"
         "return i+'='+(st.colors[i]||'#000000').replace('#','')}).join(',')"
         "+',gain='+st.gain}"
         "function copyStr(){const e=g('io');e.select();"
         "try{document.execCommand('copy');g('msg').textContent='copied'}"
         "catch(x){g('msg').textContent='select and copy manually'}}"
         "function impStr(){const t=g('io').value.trim();"
         "if(t.slice(0,5)!=='SMS5:'){"
         "g('msg').textContent='not a theme string (expects SMS5:...)';return}"
         "const seen={},named={};let bad=0,unk=0,from='';"
         "for(const part of t.slice(5).split(',')){"
         "const e=part.indexOf('=');if(e<0){if(part.trim())bad++;continue}"
         "const k=part.slice(0,e).trim(),v=part.slice(e+1).trim();"
         "if(k==='fw'){from=v;continue}"
         "if(k==='gain'){st.gain=Math.min(300,Math.max(100,parseInt(v,10)||100));continue}"
         "if(IDS.indexOf(k)<0){unk++;continue}"
         "named[k]=1;const n=norm(v);if(!n){bad++;continue}"
         "st.colors[k]=n;seen[k]=1}"
         "const miss=IDS.filter(function(i){return !named[i]}).length;"
         "fill();send();"
         "const notes=[];"
         "if(from&&from!==FW)notes.push('written by '+from+', this device runs '+FW);"
         "if(!from)notes.push('no version in the string');"
         "if(miss)notes.push(miss+' colour(s) it does not mention, left as they were');"
         "if(unk)notes.push(unk+' name(s) this build does not have, ignored');"
         "if(bad)notes.push(bad+' unreadable');"
         "g('msg').textContent='imported'+(notes.length?' - '+notes.join('; '):'')"
         "+' - press Save to keep it'}"
         "async function preset(i){"
         "await fetch('/theme/preset',{method:'POST',"
         "body:new URLSearchParams({i:i})});await load();"
         "g('msg').textContent='preset applied and saved'}"
         "async function save(){await fetch('/theme/save',{method:'POST'});"
         "g('msg').textContent='saved - press Restart device to update the main screen'}"
         "async function reset_(){await fetch('/theme/preset',{method:'POST',"
         "body:new URLSearchParams({i:0})});await load();"
         "g('msg').textContent='reset to default'}"
         "load();"
         "</script>");
  h += webShellRestartUi();
  h += webShellFoot();
  return h;
}

// ------------------------------------------------------------------ routes

void registerThemeRoutes(WebServer &srv) {
  srv.on("/theme", HTTP_GET, [&srv]() {
    if (!webThemeEnabled()) { webSendDisabled(srv, "The theme editor",
                              "Settings > System > Web interface"); return; }
    srv.send(200, "text/html", themePage());
  });

  srv.on("/theme/state", HTTP_GET, [&srv]() {
    if (!webThemeEnabled()) { webSendDisabled(srv, "The theme editor",
                              "Settings > System > Web interface"); return; }
    srv.send(200, "application/json", themeStateJson());
  });

  // Live apply, no persistence: this is what fires while a picker is dragged.
  srv.on("/theme/set", HTTP_POST, [&srv]() {
    if (!webThemeEnabled()) { webSendDisabled(srv, "The theme editor",
                              "Settings > System > Web interface"); return; }
    for (int i = 0; i < TH_COUNT; i++) {
      const char *id = themeTokenId(i);
      if (srv.hasArg(id)) g_theme[i] = parseHex6(srv.arg(id));
    }
    if (srv.hasArg("gain")) {
      displaySetUiGain((uint16_t)srv.arg("gain").toInt());
    }
    theme_dirty_pending = true;
    srv.send(200, "text/plain", "ok");
  });

  srv.on("/theme/preset", HTTP_POST, [&srv]() {
    if (!webThemeEnabled()) { webSendDisabled(srv, "The theme editor",
                              "Settings > System > Web interface"); return; }
    const int i = srv.hasArg("i") ? srv.arg("i").toInt() : 0;
    themeApplyPreset(i);
    themeSave();
    theme_dirty_pending = true;
    srv.send(200, "text/plain", "ok");
  });

  srv.on("/theme/save", HTTP_POST, [&srv]() {
    if (!webThemeEnabled()) { webSendDisabled(srv, "The theme editor",
                              "Settings > System > Web interface"); return; }
    themeSave();
    prefsPutUInt("ui_gain", displayGetUiGain());
    srv.send(200, "text/plain", "ok");
  });
}
