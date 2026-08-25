#include "web/web_shell.h"

#include <string.h>

#include <ArduinoJson.h>   // before lang.h: T() collides with its template parameter

#include "app_config.h"
#include "lang.h"
#include "services/backend.h"
#include "app/app_state.h"
#include "services/device_name.h"
#include "services/wifi_manager.h"
#include "web/web_access.h"
#include "web/web_pages.h"

// The mark the pages show and the tab icon, served from /logo.jpg and
// /favicon.jpg by web_assets.cpp rather than pasted into every page. As a
// data URI it was 7.1 kB of base64 the browser could not cache, rebuilt on
// the heap for every request.
static const char LOGO_B64[] =
  "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";


const char* webShellLogoBase64() { return LOGO_B64; }

// Wraps a translated string as a JavaScript string literal, quotes included.
// Every T() text that ends up inside a <script> block goes through this: the
// German table carries apostrophes and quotation marks, and one unescaped
// quote takes the whole page's script down without a word in the console.
//
// "<" is escaped as well. A literal "</script>" inside a JS string still ends
// the script element as far as the HTML parser is concerned, so a translation
// that ever contained one would break out of it.
String jsStr(const char *in) {
  String o = "\"";
  for (const char *p = in ? in : ""; *p; p++) {
    switch (*p) {
      case '"':  o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n";  break;
      case '\r': break;
      case '<':  o += "\\x3C"; break;
      default:   o += *p;
    }
  }
  o += "\"";
  return o;
}

// ---------------------------------------------------------------------------
// The palette is the device's own, unchanged. What carries the look is the
// type scale, the state pills and the space - a 720 px column instead of the
// 480 px this was written at when the only viewer anyone pictured was a
// phone.
//
// No web font on purpose. The scale sits on a LAN that may have no route to
// the internet, so a font link would fail silently and drop to whatever the
// browser picked.
// ---------------------------------------------------------------------------
String webShellHead(const char *subtitle) {
  char ver[24];
  strncpy(ver, FW_VERSION, sizeof(ver) - 1);
  ver[sizeof(ver) - 1] = '\0';

  String h;
  h.reserve(4200);
  h += F("<!DOCTYPE html><html><head>"
      "<meta charset='utf-8'>"
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<link rel='icon' type='image/png' href='/favicon.png'>"
      "<link rel='apple-touch-icon' href='/apple-touch-icon.png'>"
      "<title>SpoolmanScale - ");
  h += subtitle;
  h += F("</title><style>"
      ":root{"
      "--ground:#06080f;--surface:#0c1828;--surface-2:#0a1220;"
      "--line:#1a3060;--line-soft:#14243c;"
      "--ink:#e8f0ff;--ink-2:#c8d8f0;--ink-3:#4a6fa0;--ink-4:#2a4060;"
      // Quiet body copy had been sitting on --ink-4, which is 1.7:1 on the
      // card - a hint nobody could read, and an empty state that looked
      // like a page that had failed to load. 5.2:1, still clearly secondary.
      "--ink-soft:#6d8cb8;"
      "--accent:#28d49a;--accent-dim:#123f34;--accent-line:#1d6b56;"
      "--warn:#f0b838;--bad:#ff6b6b;--w:720px;"
      "--sans:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
      "--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}"
      "*{box-sizing:border-box;margin:0;padding:0}"
      "body{background:var(--ground);color:var(--ink);font-family:var(--sans);"
      "font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased;"
      "padding:28px 20px 40px;display:flex;flex-direction:column;align-items:center;"
      "gap:20px;min-height:100vh}"
      ".wrap{width:100%;max-width:var(--w);display:flex;flex-direction:column;gap:18px}"
      // header
      ".head{display:grid;grid-template-columns:52px 1fr auto;align-items:center;gap:16px}"
      ".mark{width:52px;height:52px;border-radius:13px;overflow:hidden;"
      "border:1px solid var(--line)}"
      ".mark img{width:100%;height:100%;display:block;object-fit:cover}"
      ".wordmark{font-size:21px;font-weight:650;letter-spacing:-.02em;color:var(--accent)}"
      ".wordmark span{color:var(--ink)}"
      ".subline{font-size:12px;color:var(--ink-3);margin-top:2px;font-variant-numeric:tabular-nums}"
      ".addr{display:flex;flex-direction:column;line-height:1.35;background:var(--surface-2);"
      "border:1px solid var(--line-soft);border-radius:10px;padding:8px 12px}"
      ".addr b{font-family:var(--mono);font-size:13px;font-weight:500;color:var(--accent)}"
      ".addr i{font-family:var(--mono);font-size:11px;font-style:normal;color:var(--ink-3)}"
      // nav
      ".nav{display:flex;flex-wrap:wrap;gap:4px;background:var(--surface-2);"
      "border:1px solid var(--line-soft);border-radius:12px;padding:5px}"
      ".nav a{color:var(--ink-3);text-decoration:none;font-size:13.5px;font-weight:500;"
      "padding:8px 14px;border-radius:8px;transition:background .14s,color .14s}"
      ".nav a:hover{color:var(--ink-2);background:#0f1e33}"
      ".nav a.on{background:var(--accent-dim);color:var(--ink);"
      "box-shadow:inset 0 0 0 1px var(--accent-line)}"
      // cards
      ".grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}"
      ".card{background:var(--surface);border:1px solid var(--line-soft);"
      "border-radius:14px;padding:18px 20px 20px}"
      ".card.wide{grid-column:1/-1}"
      ".card h2{font-size:11px;font-weight:650;letter-spacing:.1em;text-transform:uppercase;"
      "color:var(--ink-3);margin-bottom:14px}"
      ".note{font-size:12.5px;color:var(--ink-soft);line-height:1.55;margin-top:12px}"
      ".note b{color:var(--ink-2);font-weight:500}"
      // data rows: mono only for machine strings
      ".rows{display:flex;flex-direction:column}"
      ".row{display:flex;align-items:baseline;justify-content:space-between;gap:16px;"
      "padding:9px 0;border-bottom:1px solid var(--line-soft);font-size:14px}"
      ".row:last-child{border-bottom:0;padding-bottom:0}.row:first-child{padding-top:0}"
      ".k{color:var(--ink-3)}"
      ".v{color:var(--ink-2);text-align:right;font-variant-numeric:tabular-nums}"
      ".v.mono{font-family:var(--mono);font-size:13px}"
      ".v em{font-style:normal;color:var(--ink-soft);font-size:12.5px;margin-left:6px}"
      // state as a shape, not only a word
      ".pill{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;font-weight:600;"
      "letter-spacing:.04em;padding:3px 9px;border-radius:999px;border:1px solid}"
      ".pill:before{content:'';width:6px;height:6px;border-radius:50%;background:currentColor}"
      ".ok{color:var(--accent);border-color:var(--accent-line);background:#0b2b23}"
      ".wr{color:var(--warn);border-color:#55420f;background:#221a06}"
      ".bd{color:var(--bad);border-color:#6b2626;background:#2a0f0f}"
      ".sig{display:inline-flex;gap:2px;align-items:flex-end;height:12px;margin-left:8px}"
      ".sig i{width:3px;border-radius:1px;background:var(--ink-4)}"
      ".sig i:nth-child(1){height:4px}.sig i:nth-child(2){height:7px}"
      ".sig i:nth-child(3){height:10px}.sig i:nth-child(4){height:13px}"
      // forms
      ".field{display:flex;flex-direction:column;gap:7px}.field+.field{margin-top:16px}"
      ".field label{font-size:13px;color:var(--ink-2)}"
      ".hint{font-size:12px;color:var(--ink-soft);line-height:1.55}"
      ".inrow{display:flex;gap:10px;align-items:center;flex-wrap:wrap}"
      "input[type=text],input[type=password],input[type=number],input[type=file],select{"
      "flex:1;min-width:0;background:var(--ground);border:1px solid var(--line);"
      "border-radius:9px;color:var(--ink);font:inherit;font-size:14px;padding:9px 12px}"
      "input[type=number]{flex:0 0 86px;text-align:center}"
      "input:focus,select:focus,button:focus-visible,a:focus-visible{"
      "outline:2px solid var(--accent);outline-offset:1px}"
      ".suffix{font-family:var(--mono);font-size:13px;color:var(--ink-3);white-space:nowrap}"
      ".msg{font-size:12.5px;color:var(--accent);min-height:1.2em}"
      ".msg.bad{color:var(--bad)}"
      "button{appearance:none;cursor:pointer;font:inherit;font-size:13.5px;font-weight:550;"
      "padding:9px 16px;border-radius:9px;background:#0f2a22;color:var(--accent);"
      "border:1px solid var(--accent-line);transition:background .14s;white-space:nowrap}"
      "button:hover{background:#164034}"
      "button:disabled{opacity:.5;cursor:default}"
      "button.quiet{background:#0f1b2c;color:var(--ink-2);border-color:var(--line)}"
      "button.quiet:hover{background:#16273e}"
      "button.danger{background:#2a0f0f;color:var(--bad);border-color:#6b2626}"
      "button.danger:hover{background:#3a1616}"
      "button.block{width:100%;margin-top:16px}"
      ".range{display:flex;align-items:center;gap:12px}"
      "input[type=range]{flex:1;accent-color:var(--accent)}"
      ".range output{font-family:var(--mono);font-size:13px;color:var(--ink);width:34px;text-align:right}"
      // tables and lists
      "table{width:100%;border-collapse:collapse;font-size:13.5px}"
      "th{font-size:10.5px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;"
      "color:var(--ink-soft);text-align:left;padding:0 8px 8px 0}"
      "td{padding:5px 8px 5px 0;border-top:1px solid var(--line-soft);color:var(--ink-2)}"
      ".listrow{display:flex;align-items:center;justify-content:space-between;gap:12px;"
      "padding:10px 12px;border-radius:9px;background:var(--surface-2);"
      "border:1px solid var(--line-soft)}"
      ".listrow+.listrow{margin-top:7px}"
      ".listrow .nm{font-family:var(--mono);font-size:13px;color:var(--ink-2)}"
      ".listrow .sz{font-family:var(--mono);font-size:11.5px;color:var(--ink-soft)}"
      // Links, one row at the bottom. They take the page's own button
      // vocabulary rather than a look of their own: the quiet button for three
      // of them, the primary one for Ko-fi. They used to sit at 3.64:1 text on
      // a fill darker than any real button, with a 1.20:1 border - text on a
      // hint of surface, not something that reads as pressable.
      ".links{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}"
      ".links a{display:flex;align-items:center;justify-content:center;gap:8px;"
      "padding:11px 8px;border-radius:9px;text-decoration:none;"
      "font-size:13.5px;font-weight:550;"
      "background:#0f1b2c;color:var(--ink-2);border:1px solid var(--line);"
      "transition:background .14s}"
      ".links a:hover{background:#16273e}"
      ".links a.support{background:#0f2a22;color:var(--accent);"
      "border-color:var(--accent-line)}"
      ".links a.support:hover{background:#164034}"
      // currentColor, so each mark takes the colour of the button it sits in:
      // green inside Ko-fi, grey in the other three.
      ".links svg{width:15px;height:15px;flex:none;fill:currentColor}"
      // Ko-fi carries the long label and falls back to the bare name where it
      // will not fit. display:none takes the hidden one out of the flex row
      // and out of the accessibility tree, so there is neither a phantom gap
      // nor a link that reads itself twice.
      ".links .sm{display:none}"
      // Was --ink-4, which is 1.91:1 against the page - the last line still
      // carrying the fault the hints and notes were moved off in beta.38.
      ".foot{font-size:11.5px;color:var(--ink-soft);text-align:center;line-height:1.6}"
      "@media(max-width:700px){.grid{grid-template-columns:1fr}"
      ".links{grid-template-columns:1fr 1fr}"
      ".head{grid-template-columns:44px 1fr}.addr{grid-column:1/-1}}"
      // Derived, not guessed: at two columns the cell is (V-50)/2 wide, and
      // the German label needs 150px, which solves to V >= 350. German is the
      // longer language here and sets the edge.
      "@media(max-width:360px){.links .lg{display:none}"
      ".links .sm{display:inline}}"
      "@media(prefers-reduced-motion:reduce){*{transition:none!important}}"
      "</style></head><body><div class='wrap'>");
  return h;
}

// The address block sits in the header because it is the one thing people
// come to this page to read or to type, and it used to be a row halfway down
// the status list. Name large, IP small underneath - not either or, because
// some Android versions still will not resolve a .local name.
String webShellHeader() {
  String h;
  h += F("<div class='head'><div class='mark'>"
         "<img src='/logo.jpg' width='52' height='52' alt='SpoolmanScale'></div><div>"
         "<div class='wordmark'>Spoolman<span>Scale</span></div>"
         "<div class='subline'>");
  h += FW_VERSION;
  h += F(" &nbsp;&middot;&nbsp; ESP32-S3</div></div>");

  if (wifi_ok) {
    char alt[48];
    deviceAltAddress(alt, sizeof(alt));
    h += F("<div class='addr'><b>");
    // deviceAltAddress() is empty exactly when the big line already carries
    // the bare IP, so the two never say the same thing twice.
    const String ip = wifiManagerLocalIP().toString();
    h += alt[0] ? deviceFqdn() : ip.c_str();
    h += F("</b><i>");
    h += alt;
    h += F("</i></div>");
  }
  h += F("</div>");
  return h;
}

String webShellNav(const char *active) {
  String n = F("<div class='nav'>");
  // One strip built from the one table. There used to be two of these in two
  // files with two hand kept lists, and they disagreed about BamBuddy.
  for (size_t i = 0; i < WEB_PAGE_COUNT; i++) {
    const WebPage &p = *WEB_PAGES[i];
    if (!webPageVisible(p)) continue;
    n += String(F("<a class='")) + (strcmp(p.path, active) == 0 ? "on" : "") +
         "' href='" + p.path + "'>" + webPageLabel(p) + "</a>";
  }
  n += F("</div>");
  return n;
}

// Marks are inline rather than fetched. Ko-fi hands out a ready made button as
// an image from their CDN, and the scale often sits on a LAN with no route out
// - it would render as a broken image on exactly the button meant to collect
// goodwill, for the same reason there is no web font here.
//
// An external sprite plus <use> would be cacheable and much smaller, but the
// referenced document does not inherit the host page's currentColor in most
// browsers, and colour per button is the point.
//
// GitHub and Discord publish monochrome marks for this. Ko-fi and MakerWorld
// get a plain heart and a plain cube instead of a redrawn logo: it keeps the
// row uniform and sidesteps the question of whether a traced mark is the mark.
#define SVG_OPEN "<svg viewBox='0 0 24 24' aria-hidden='true' focusable='false'><path d='"
#define SVG_END  "'/></svg>"

String webShellLinks() {
  String h;
  h.reserve(2600);
  h += F(
    "<div class='links'>"
    "<a href='https://github.com/Niko11111/SpoolmanScale' target='_blank' rel='noopener'>"
    SVG_OPEN
    "M12 .5C5.37.5 0 5.87 0 12.5c0 5.3 3.44 9.8 8.21 11.39.6.11.82-.26.82-.58"
    "v-2.03c-3.34.73-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75."
    "08-.73.08-.73 1.2.08 1.84 1.24 1.84 1.24 1.07 1.84 2.81 1.31 3.5 1 .11-.78."
    "42-1.31.76-1.61-2.67-.3-5.47-1.34-5.47-5.96 0-1.32.47-2.39 1.24-3.23-.12-."
    "31-.54-1.53.12-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 016.01 0c2.29-1.55 "
    "3.3-1.23 3.3-1.23.66 1.65.24 2.87.12 3.18.77.84 1.24 1.91 1.24 3.23 0 4.63"
    "-2.81 5.65-5.49 5.95.43.37.82 1.1.82 2.22v3.29c0 .32.22.7.83.58A12.01 12.01"
    " 0 0024 12.5C24 5.87 18.63.5 12 .5z"
    SVG_END "GitHub</a>"

    "<a class='support' title='Ko-fi' href='https://ko-fi.com/formfollowsfunction' target='_blank' rel='noopener'>"
    SVG_OPEN
    "M12 21s-6.7-4.35-9.1-7.8C.6 10.1 2.1 6 5.8 6c2 0 3.4 1.1 4.2 2.2C10.8 7.1 "
    "12.2 6 14.2 6c3.7 0 5.2 4.1 2.9 7.2C18.7 16.65 12 21 12 21z"
    SVG_END "<span class='lg'>");
  h += T(STR_W_KOFI);
  // The name leaves the label on wide screens, so it stays reachable on hover.
  h += F("</span><span class='sm'>Ko-fi</span></a>"

    "<a href='https://discord.gg/TQvdxGuFcq' target='_blank' rel='noopener'>"
    SVG_OPEN
    "M20.3 4.4a19.8 19.8 0 00-4.9-1.5l-.6 1.2a18.3 18.3 0 00-5.5 0l-.6-1.2a19.7 "
    "19.7 0 00-4.9 1.5C.5 9 -.3 13.6.1 18a19.9 19.9 0 006 3l1.2-2a13.1 13.1 0 01"
    "-1.9-.9l.4-.3a14 14 0 0012.1 0l.4.3a13 13 0 01-1.9.9l1.2 2a19.8 19.8 0 006"
    "-3c.5-5.2-.8-9.7-3.5-13.6zM8 15.3c-1.2 0-2.2-1.1-2.2-2.4S6.8 10.5 8 10.5s2."
    "2 1.1 2.2 2.4S9.2 15.3 8 15.3zm8 0c-1.2 0-2.2-1.1-2.2-2.4s1-2.4 2.2-2.4 2.2"
    " 1.1 2.2 2.4-1 2.4-2.2 2.4z"
    SVG_END "Discord</a>"

    "<a href='https://makerworld.com/de/@FormFollowsF/upload' target='_blank' rel='noopener'>"
    SVG_OPEN
    "M12 2.5l8.5 4.75v9.5L12 21.5l-8.5-4.75v-9.5L12 2.5zm0 2.29L6.06 8.1 12 11.4"
    "l5.94-3.3L12 4.79zM5.5 9.79v5.79l5.5 3.07v-5.79L5.5 9.79zm13 0l-5.5 3.07v5."
    "79l5.5-3.07V9.79z"
    SVG_END "MakerWorld</a>"
    "</div>");
  return h;
}

// Links and disclaimer close every page. They used to be a 2x2 block of
// saturated buttons directly under the logo, which put the loudest thing on
// the page where the eye lands first and pushed the content below the fold.
//
// All three backends are named whatever the active one is. This device is
// called SpoolmanScale, so naming only the active one would leave out the
// very name that could suggest an affiliation.
// Which sections the device is not serving, named, plus where the switches
// are. Read from the same table the tab strip reads, so it can never name a
// page the navigation disagrees about.
//
// It says something in both states on purpose. A reader who finds no Backend
// tab has no way to tell a missing feature from a shut switch, and the two
// writing gates are off by default - which is exactly how people ended up
// unable to enter their FilaMan credentials after flashing. A reader who
// finds everything open should still know the device is what decides that.
//
// A page left out because it does not apply to this device is not listed: it
// is absent, not switched off, and no switch would bring it back.
static String webShellGateNote() {
  String closed;
  for (size_t i = 0; i < WEB_PAGE_COUNT; i++) {
    const WebPage &p = *WEB_PAGES[i];
    if (p.applies && !p.applies()) continue;
    if (webGateOpen(p.gate)) continue;
    if (closed.length()) closed += F(", ");
    closed += webPageLabel(p);
  }

  String n;
  n.reserve(320);
  n += F("<p class='foot'>");
  if (closed.length()) {
    n += closed;
    n += ' ';
    n += T(STR_W_FOOT_GATE_OFF);
  } else {
    n += T(STR_W_FOOT_GATE_ALL);
  }
  n += F(" <b>");
  n += T(STR_W_OFF_PATH);
  n += F("</b>.</p>");
  return n;
}

String webShellFoot() {
  String f = webShellLinks();
  f += webShellGateNote();
  f += F("<p class='foot'>");
  f += T(STR_W_DISCLAIMER);
  f += F("</p></div></body></html>");     // closes .wrap
  return f;
}

// Restart overlay. The device is unreachable while it boots, so the page has
// to say so and then find its own way back rather than leaving a dead tab.
//
// How long a boot takes is not a constant: an SD card adds roughly twenty
// seconds, so the page asks the device what it has before deciding what
// counts as too long. Guessing low would report a healthy boot as a failure.
String webShellRestartUi() {
  String h;
  h.reserve(2600);
  h += F("<style>"
         "#rbox{display:none;position:fixed;inset:0;background:rgba(6,8,15,.92);z-index:99;"
         "align-items:center;justify-content:center}"
         "#rbox .rc{background:var(--surface);border:1px solid var(--line);border-radius:14px;"
         "padding:32px 40px;text-align:center;max-width:360px}"
         ".spin{width:44px;height:44px;margin:0 auto 18px;border:3px solid var(--line);"
         "border-top-color:var(--accent);border-radius:50%;animation:sp 1s linear infinite}"
         "@keyframes sp{to{transform:rotate(360deg)}}"
         "#rtitle{color:var(--ink);font-size:16px;font-weight:600;margin-bottom:8px}"
         "#rsec{color:var(--ink-3);font-size:13px;line-height:1.5}"
         "</style>"
         "<div id='rbox'><div class='rc'><div class='spin'></div>"
         "<div id='rtitle'>");
  h += T(STR_W_RESTARTING);
  h += F("</div><div id='rsec'>");
  h += T(STR_W_RESTART_WAIT);
  h += F("</div></div></div><script>"
         "const RT={ask:");
  h += jsStr(T(STR_W_RESTART_ASK));
  h += F(",wait:");   h += jsStr(T(STR_W_RESTART_WAIT));
  h += F(",sd:");     h += jsStr(T(STR_W_RESTART_SD));
  h += F(",still:");  h += jsStr(T(STR_W_RESTART_LONG));
  h += F(",gone:");   h += jsStr(T(STR_W_RESTART_GONE));
  h += F(",reload:"); h += jsStr(T(STR_W_RELOAD));
  h += F("};"
         "async function doRestart(){"
         "if(!confirm(RT.ask))return;"
         "let sd=false;"
         "try{sd=(await(await fetch('/status.json',{cache:'no-store'})).json()).sd}catch(e){}"
         "try{await fetch('/api/restart',{method:'POST'})}catch(e){}"
         "const box=document.getElementById('rbox'),m=document.getElementById('rsec');"
         "box.style.display='flex';"
         "const expect=sd?35:10,limit=180;let t=0;"
         "const iv=setInterval(async()=>{t++;"
         "if(t<2){m.textContent=RT.wait}"
         "else if(t<expect){m.textContent=RT.wait+' - '+t+'s'+(sd?RT.sd:'')}"
         "else if(t<limit){m.textContent=RT.still+' - '+t+'s'}"
         "else{clearInterval(iv);"
         "m.innerHTML=RT.gone+\" <a href='' style='color:var(--accent)'>\"+RT.reload+'</a>';return}"
         // The old server answers for a moment after the request, so give it a
         // beat before the first poll or we reload against the dying instance.
         "if(t<2)return;"
         "try{const r=await fetch('/status.json',{cache:'no-store'});"
         "if(r.ok){clearInterval(iv);location.reload()}}catch(e){}"
         "},1000);}"
         "</script>");
  return h;
}
