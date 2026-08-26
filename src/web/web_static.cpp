#include "web/web_static.h"

#include <Arduino.h>
#include <pgmspace.h>

#include "app_config.h"

// One literal in flash. Adjacent string literals are concatenated by the
// compiler, so the comments between them cost nothing and the rules stay
// grouped the way they were written.
static const char APP_CSS[] PROGMEM =
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
      // Switches. There was no style for a checkbox at all: the two the
      // interface already had were browser default, forced to 16x16 by an
      // inline style, and wrapped in a label whose styles were copied from
      // one page to the other by hand. A generated settings row needs one
      // shape it can rely on.
      //
      // Built from the tokens the rest of the sheet uses, so it reads as the
      // same control family as the buttons: the accent green for on, the
      // quiet line colour for off. The real input stays on top of the track
      // at full size rather than being hidden, which keeps the hit area, the
      // keyboard focus and the label association that a div cannot fake.
      ".switch{position:relative;display:inline-block;flex:0 0 40px;width:40px;height:22px}"
      ".switch input{position:absolute;inset:0;width:100%;height:100%;margin:0;"
      "opacity:0;cursor:pointer;z-index:1}"
      ".switch i{position:absolute;inset:0;border-radius:999px;background:var(--surface-2);"
      "border:1px solid var(--line);transition:background .14s,border-color .14s}"
      ".switch i:after{content:'';position:absolute;left:3px;top:3px;width:14px;height:14px;"
      "border-radius:50%;background:var(--ink-3);"
      "transition:transform .14s,background .14s}"
      ".switch input:checked+i{background:#0f2a22;border-color:var(--accent-line)}"
      ".switch input:checked+i:after{transform:translateX(18px);background:var(--accent)}"
      ".switch input:focus-visible+i{outline:2px solid var(--accent);outline-offset:1px}"
      ".switch input:disabled{cursor:default}"
      ".switch input:disabled+i{opacity:.5}"
      // The label a switch sits in. Both existing checkboxes carried this as
      // an inline style copied from one page to the other; the second copy
      // even says so in its comment.
      ".check{display:flex;align-items:center;gap:10px;font-size:13px;"
      "color:var(--ink-2);cursor:pointer}"
      ".check+.check{margin-top:10px}"

      // A settings row: name and its one line of explanation on the left, the
      // control on the right. Close to .row/.k/.v, which carries a label and a
      // value - but a setting needs a second line under the name, and .row has
      // nowhere to put one.
      ".orow{display:flex;justify-content:space-between;align-items:flex-start;"
      "gap:16px;padding:12px 0;border-bottom:1px solid var(--line-soft)}"
      ".orow:last-child{border-bottom:0;padding-bottom:0}"
      ".orow:first-child{padding-top:0}"
      ".ol{display:flex;flex-direction:column;gap:3px;min-width:0}"
      ".on{font-size:14px;color:var(--ink-2)}"
      // Quiet text goes on --ink-soft. --ink-4 is a shape colour for rules and
      // inactive bars; as text on a card it is 1.7:1 and invisible.
      ".os{font-size:12px;color:var(--ink-soft);line-height:1.45}"
      ".ov{flex:0 0 auto;display:flex;align-items:center;gap:10px;padding-top:2px}"
      // The help circle the device shows as a "?" next to the row. Same idea
      // here, and it opens the same text - as a line under the row rather than
      // a modal, because a page has room and a 480px panel does not.
      ".oq{flex:0 0 22px;width:22px;height:22px;padding:0;border-radius:50%;"
      "font-size:12px;line-height:1;display:flex;align-items:center;"
      "justify-content:center}"
      ".oi{font-size:12.5px;color:var(--ink-soft);line-height:1.55;"
      "padding:0 0 12px;display:none}"
      ".oi.open{display:block}"
      // A row the device owns. Says so instead of showing a control that
      // cannot work here.
      ".od{font-size:12px;color:var(--ink-3);white-space:nowrap}"
;

const char* webStaticVersion() { return FW_VERSION; }

// The block every page's script used to carry its own copy of. There were
// three flash() implementations with three different signatures, and the POST
// boilerplate stood nine times in page_config.cpp alone.
//
// It is a route rather than something the shell pastes into each page,
// because the last attempt at sharing it was a copy: page_config.cpp still
// carries the scar in a comment - "when the pages were split the shared block
// stayed behind on one of them and every Save button here called a function
// that was no longer on the page".
//
// No translated string lives in here. The device serves pages in whichever
// language it is set to, and this file is cached across both - so the strings
// stay in the page and are assigned into WS.
static const char APP_JS[] PROGMEM =
  "var WS={ok:'OK',err:'Error'};\n"

  "function $(i){return document.getElementById(i);}\n"

  // One message line, for every page. ms omitted leaves the text standing,
  // which is what a host test result or a rejected name wants; after() lets a
  // caller hand the line back to whatever else writes there instead of
  // clearing it.
  "function flash(id,t,bad,ms,after){"
  "var e=$(id);if(!e)return;"
  "e.textContent=t;e.className='msg'+(bad?' bad':'');"
  "if(e._ft){clearTimeout(e._ft);e._ft=0;}"
  "if(ms)e._ft=setTimeout(function(){e._ft=0;"
  "if(after)after();else e.textContent='';},ms);}\n"

  // Never rejects. A closed gate answers /api/* with 403 as text/plain,
  // r.json() throws on that, and an uncaught rejection leaves an empty card
  // that looks like a fault in the firmware rather than a shut switch.
  //
  // Hands back both readings of the body so a caller can take whichever its
  // route speaks: .text for the plain replies, .json for the ones that answer
  // with an object. That is what lets the two formats coexist while they do.
  "function post(u,body){"
  "return fetch(u,{method:'POST',headers:{'Content-Type':'text/plain'},"
  "body:String(body)})"
  ".then(function(r){return r.text().then(function(t){"
  "var j=null;try{j=JSON.parse(t);}catch(e){}"
  "return{ok:r.ok,text:t,json:j};});})"
  ".catch(function(){return{ok:false,text:'',json:null};});}\n"

  // POST and report in one call. A route that answers with prose says it
  // itself - /api/host replies with the result of a real health check, and
  // overwriting that with \"saved\" would throw away the only useful part.
  "function postFlash(u,body,id,ms,after){"
  "return post(u,body).then(function(r){"
  "var okv=r.json?(r.json.ok!==false):r.ok;"
  "var msg=(r.json===null&&r.text)?r.text:(okv?WS.ok:WS.err);"
  "flash(id,msg,!okv,ms,okv?after:null);"
  "return r;});}\n"

  // Resolves with null instead of rejecting, same reason as post().
  "function getJson(u){"
  "return fetch(u,{cache:'no-store'}).then(function(r){"
  "if(!r.ok)throw 0;return r.json();}).catch(function(){return null;});}\n"
;

void registerStaticRoutes(WebServer &srv) {
  srv.on("/app.css", HTTP_GET, [&srv]() {
    // Immutable for a year: the URL carries the firmware version, so the
    // content behind a given URL genuinely never changes. A new firmware
    // links a new URL rather than waiting for a cache to expire.
    srv.sendHeader("Cache-Control", "public, max-age=31536000, immutable");
    srv.send_P(200, "text/css", APP_CSS);
  });

  srv.on("/app.js", HTTP_GET, [&srv]() {
    srv.sendHeader("Cache-Control", "public, max-age=31536000, immutable");
    srv.send_P(200, "application/javascript", APP_JS);
  });
}
