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
      "--warn:#f0b838;--bad:#ff6b6b;--w:860px;"
      // Fills that used to stand as numbers in the rules below.
      "--hover:#0f1e33;--btn:#0f2a22;--btn-hover:#164034;--good:#28d49a;"
      "--quiet:#0f1b2c;--quiet-hover:#16273e;--ok-bg:#0b2b23;"
      "--warn-line:#55420f;--warn-bg:#221a06;"
      "--bad-line:#6b2626;--bad-bg:#2a0f0f;--bad-hover:#3a1616;"
      "--sans:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
      "--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}"
      // The light palette, chosen with the scale's own (see web_shell.cpp and
      // ui/theme_palette.h). Only the colours change; every rule below reads
      // them through the variables.
      ":root[data-theme=light]{"
      "--ground:#eef3f9;--surface:#ffffff;--surface-2:#f4f7fb;"
      "--line:#b9c8dd;--line-soft:#dbe3ee;"
      "--ink:#0f1a2a;--ink-2:#243449;--ink-3:#4a6488;--ink-4:#a6b6cc;--ink-soft:#50627c;"
      "--accent:#0a8a60;--accent-dim:#d6f1e6;--accent-line:#7cc9aa;"
      "--warn:#9a6a00;--bad:#c62f2f;"
      "--hover:#e3eaf4;--btn:#e1f5ec;--btn-hover:#cdeedf;--good:#0a8a60;"
      "--quiet:#eef2f8;--quiet-hover:#e1e8f2;--ok-bg:#e1f5ec;"
      "--warn-line:#e2c77a;--warn-bg:#fdf4dc;"
      "--bad-line:#eaa4a4;--bad-bg:#fdeaea;--bad-hover:#f9d9d9}"
      // Spoolman's own colours (client 0.27): graphite or paper, orange as
      // the house colour, green kept for a good state.
      ":root[data-theme=spoolman_dark]{"
      "--ground:#1f1f1f;--surface:#252525;--surface-2:#1c1c1c;"
      "--line:#3d3d3d;--line-soft:#333333;"
      "--ink:#ececec;--ink-2:#c9c9c9;--ink-3:#a7a7a7;--ink-4:#4a4a4a;--ink-soft:#a7a7a7;"
      "--accent:#e38c47;--accent-dim:#35291f;--accent-line:#8a6a4d;"
      "--warn:#f4c542;--bad:#f08a78;--good:#7fcd7f;"
      "--hover:#2e2e2e;--btn:#35291f;--btn-hover:#4a3424;"
      "--quiet:#2e2e2e;--quiet-hover:#383838;--ok-bg:#2a352a;"
      "--warn-line:#5a4a1a;--warn-bg:#2e2a1c;"
      "--bad-line:#5a3028;--bad-bg:#36261f;--bad-hover:#4a2c24}"
      ":root[data-theme=spoolman_light]{"
      "--ground:#efece6;--surface:#fbfaf8;--surface-2:#f5f3ef;"
      "--line:#b8b5ae;--line-soft:#dcd9d2;"
      "--ink:#141414;--ink-2:#232323;--ink-3:#525252;--ink-4:#bdb9b1;--ink-soft:#4f4f4f;"
      "--accent:#a8501a;--accent-dim:#f3e2d4;--accent-line:#d9a882;"
      "--warn:#8a6500;--bad:#b3261e;--good:#2a7a2e;"
      "--hover:#ebe7e0;--btn:#f5e7dc;--btn-hover:#eed8c6;"
      "--quiet:#f3f1ed;--quiet-hover:#e8e5df;--ok-bg:#e3eedf;"
      "--warn-line:#e2c77a;--warn-bg:#fbf3dc;"
      "--bad-line:#eaa4a4;--bad-bg:#fbe9e6;--bad-hover:#f6d6d0}"
      // FilaMan's own colours (1.3.7, themes "brand" and "light"): bottle
      // green with mint, or cream with a deeper green that holds as text.
      ":root[data-theme=filaman_dark]{"
      "--ground:#0c1612;--surface:#13261d;--surface-2:#10201a;"
      "--line:#2c4a3c;--line-soft:#1f3a2c;"
      "--ink:#e9f3ec;--ink-2:#cfe0d6;--ink-3:#b5c7bd;--ink-4:#2c4a3c;--ink-soft:#b5c7bd;"
      "--accent:#4ee3a2;--accent-dim:#1d4a36;--accent-line:#2f6a50;"
      "--warn:#f7c86a;--bad:#fca5a5;--good:#86efac;"
      "--hover:#183225;--btn:#1d4a36;--btn-hover:#24573f;"
      "--quiet:#183225;--quiet-hover:#22402f;--ok-bg:#1a4a33;"
      "--warn-line:#5a4f2a;--warn-bg:#2a2616;"
      "--bad-line:#5e2424;--bad-bg:#3a1616;--bad-hover:#4a1c1c}"
      ":root[data-theme=filaman_light]{"
      "--ground:#f8f6f1;--surface:#ffffff;--surface-2:#f1ece3;"
      "--line:#b9bdb3;--line-soft:#dcdcd6;"
      "--ink:#1a231e;--ink-2:#2a352f;--ink-3:#53645a;--ink-4:#b6bdb3;--ink-soft:#53645a;"
      "--accent:#0f7a52;--accent-dim:#d9efe3;--accent-line:#8ccaaa;"
      "--warn:#8a5a00;--bad:#b91c1c;--good:#15803d;"
      "--hover:#efeae0;--btn:#e1f3e8;--btn-hover:#cdeadb;"
      "--quiet:#f3efe7;--quiet-hover:#e8e3d8;--ok-bg:#e1f3e8;"
      "--warn-line:#e2c77a;--warn-bg:#fbf3dc;"
      "--bad-line:#eaa4a4;--bad-bg:#fbe9e6;--bad-hover:#f6d6d0}"
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
      ".nav a:hover{color:var(--ink-2);background:var(--hover)}"
      ".nav a.on{background:var(--accent-dim);color:var(--ink);"
      "box-shadow:inset 0 0 0 1px var(--accent-line)}"
      // cards
      ".grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}"
      ".card{background:var(--surface);border:1px solid var(--line-soft);"
      "border-radius:14px;padding:18px 20px 20px}"
      ".card.wide{grid-column:1/-1}"
      // Spans both columns like .wide, but takes a column of its own once the
      // grid has three - the status page's inventory card.
      ".card.w2{grid-column:1/-1}"
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
      ".ok{color:var(--good);border-color:var(--accent-line);background:var(--ok-bg)}"
      ".wr{color:var(--warn);border-color:var(--warn-line);background:var(--warn-bg)}"
      ".bd{color:var(--bad);border-color:var(--bad-line);background:var(--bad-bg)}"
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
      "padding:9px 16px;border-radius:9px;background:var(--btn);color:var(--accent);"
      "border:1px solid var(--accent-line);transition:background .14s;white-space:nowrap}"
      "button:hover{background:var(--btn-hover)}"
      "button:disabled{opacity:.5;cursor:default}"
      "button.quiet{background:var(--quiet);color:var(--ink-2);border-color:var(--line)}"
      "button.quiet:hover{background:var(--quiet-hover)}"
      "button.danger{background:var(--bad-bg);color:var(--bad);border-color:var(--bad-line)}"
      "button.danger:hover{background:var(--bad-hover)}"
      "button.block{width:100%;margin-top:16px}"
      // A file input in the page's own button vocabulary. The native control
      // stays in the label, hidden, so the label click opens the picker and
      // the form still posts the file; the chosen name shows beside it.
      ".filebtn{display:inline-flex;align-items:center;cursor:pointer;font:inherit;"
      "font-size:13.5px;font-weight:550;padding:9px 16px;border-radius:9px;"
      "background:var(--quiet);color:var(--ink-2);border:1px solid var(--line);white-space:nowrap}"
      ".filebtn:hover{background:var(--quiet-hover)}"
      ".filebtn input{display:none}"
      ".fname{flex:1;min-width:0;font-family:var(--mono);font-size:12.5px;color:var(--ink-soft);"
      "overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
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
      "background:var(--quiet);color:var(--ink-2);border:1px solid var(--line);"
      "transition:background .14s}"
      ".links a:hover{background:var(--quiet-hover)}"
      ".links a.support{background:var(--btn);color:var(--accent);"
      "border-color:var(--accent-line)}"
      ".links a.support:hover{background:var(--btn-hover)}"
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
      // Three columns for the status page on a wide screen: two cards in a
      // 860 px column left two thirds of a 1440 px window empty.
      "@media(min-width:1100px){.g3{grid-template-columns:repeat(3,1fr)}"
      ".g3 .card.w2{grid-column:auto}}"
      "@media(max-width:700px){.grid{grid-template-columns:1fr}"
      ".links{grid-template-columns:1fr 1fr}"
      // The mark follows its column: a 52 px image in a 44 px cell pushed the
      // wordmark over by 8 px.
      ".head{grid-template-columns:44px 1fr}.mark{width:44px;height:44px}"
      ".addr{grid-column:1/-1}}"
      // A log row carries three buttons. Below 500 px they take a line of their
      // own under the name rather than squeezing it out.
      "@media(max-width:500px){.listrow{flex-wrap:wrap}"
      ".listrow>span:last-child{width:100%;justify-content:flex-end}}"
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
      ".switch input:checked+i{background:var(--btn);border-color:var(--accent-line)}"
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
      // Which backend. Three segments side by side, the same shape the device
      // shows them in - and the active one is disabled rather than merely
      // highlighted, because there is nothing to switch to there.
      ".btabs{display:flex;gap:8px;flex-wrap:wrap}"
      ".btab{flex:1 1 0;min-width:104px;justify-content:center;"
      "background:var(--quiet);color:var(--ink-2);border-color:var(--line)}"
      ".btab:hover{background:var(--quiet-hover)}"
      ".btab.on{background:var(--btn);color:var(--accent);"
      "border-color:var(--accent-line);opacity:1;cursor:default}"
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

  // Own colours (ui/theme_custom.cpp), the same sums in the browser: TC.apply
  // for the preview on the design page, TC.page() for every page, run here in
  // the head where the stylesheet is already in and nothing is drawn yet.
  // web_shell.cpp writes the choice into data-accent, data-tone, data-tstr.
  "var TC=(function(){\n"
  "var TINT=[['GROUND',0],['SURFACE',0],['ROW',0],['ROW_PRESSED',0],['LINE',0],['LINE_SOFT',0],['DIVIDER',0],['POPUP_BORDER',0],['EMPTY',0],['SCRIM',0],['RULE',0],['DISABLED_BG',0],['QUIET_BG_PRESSED',0],['DISABLED_TEXT',1],['UNAVAILABLE',1],['INK',1],['INK_2',1],['INK_SOFT',1],['CAPTION',1],['INK_FAINT',1],['INK_BRIGHT',1],['OFF_TEXT',1],['ID_TEXT',1]];\n"
  "var WEB_TINT=[['--ground',0],['--surface',0],['--surface-2',0],['--line',0],['--line-soft',0],['--hover',0],['--quiet',0],['--quiet-hover',0],['--ink',1],['--ink-2',1],['--ink-3',1],['--ink-4',1],['--ink-soft',1]];\n"
  "var WEB_ACC=['--accent-dim','--accent-line','--btn','--btn-hover'];\n"
  "function lin(c){c/=255;return c<=0.04045?c/12.92:Math.pow((c+0.055)/1.055,2.4);}\n"
  "function gam(c){c=Math.min(1,Math.max(0,c));c=c<=0.0031308?12.92*c:1.055*Math.pow(c,1/2.4)-0.055;return Math.round(c*255);}\n"
  "function rgb(h){h=h.replace('#','').trim();return[parseInt(h.substr(0,2),16),parseInt(h.substr(2,2),16),parseInt(h.substr(4,2),16)];}\n"
  "function hex(c){return c.map(function(x){return(x<16?'0':'')+x.toString(16);}).join('');}\n"
  "function cb(x){return x<0?-Math.pow(-x,1/3):Math.pow(x,1/3);}\n"
  "function lch(h){var c=rgb(h).map(lin);\n"
  "var l=cb(0.4122214708*c[0]+0.5363325363*c[1]+0.0514459929*c[2]),m=cb(0.2119034982*c[0]+0.6806995451*c[1]+0.1073969566*c[2]),s=cb(0.0883024619*c[0]+0.2817188376*c[1]+0.6299787005*c[2]);\n"
  "var A=1.9779984951*l-2.4285922050*m+0.4505937099*s,B=0.0259040371*l+0.7827717662*m-0.8086757660*s,H=Math.atan2(B,A)*180/Math.PI;\n"
  "return[0.2104542553*l+0.7936177850*m-0.0040720468*s,Math.sqrt(A*A+B*B),H<0?H+360:H];}\n"
  "function lrgb(o){var A=o[1]*Math.cos(o[2]*Math.PI/180),B=o[1]*Math.sin(o[2]*Math.PI/180);\n"
  "var l=o[0]+0.3963377774*A+0.2158037573*B,m=o[0]-0.1055613458*A-0.0638541728*B,s=o[0]-0.0894841775*A-1.2914855480*B;l=l*l*l;m=m*m*m;s=s*s*s;\n"
  "return[4.0767416621*l-3.3077115913*m+0.2309699292*s,-1.2684380046*l+2.6097574011*m-0.3413193965*s,-0.0041960863*l-0.7034186147*m+1.7076147010*s];}\n"
  "function from(o){var c;for(;;){c=lrgb(o);if(c.every(function(v){return v>=-1e-4&&v<=1.0001;})||o[1]<=0)break;o[1]=Math.max(0,o[1]-0.002);}return hex(c.map(gam));}\n"
  "function lum(h){var c=rgb(h).map(lin);return 0.2126*c[0]+0.7152*c[1]+0.0722*c[2];}\n"
  "function contrast(a,b){var x=lum(a),y=lum(b);return(Math.max(x,y)+0.05)/(Math.min(x,y)+0.05);}\n"
  "function tint(h,tone,k,text){var o=lch(h);if(o[0]<0.002||o[0]>0.998)return h;\n"
  "if(tone<0)o[1]*=k;else{o[1]=Math.max(o[1],text?0.012:0.03)*k;o[2]=tone;}return from(o);}\n"
  "function toward(f,a,cap){var o=lch(f),p=lch(a);o[2]=p[2];o[1]=Math.min(p[1],cap||0.06);return from(o);}\n"
  "function shade(h,s){return hex(rgb(h).map(function(x){return Math.max(0,Math.min(255,x+s));}));}\n"
  "function tinting(c){return c.tone>=0||c.strength!==50;}\n"
  "function apply(base,c,dark){var p={},k;for(k in base)p[k]=base[k];\n"
  "if(tinting(c))TINT.forEach(function(r){p[r[0]]=tint(base[r[0]],c.tone,c.strength/50,r[1]);});\n"
  "if(c.accent){p.ACCENT=c.accent;p.LV_PRIMARY=c.accent;\n"
  "p.ON_ACCENT=contrast('0b0f0d',c.accent)>=contrast('ffffff',c.accent)?'0b0f0d':'ffffff';p.ACCENT_CHIP=toward(base.ACCENT_CHIP,c.accent);\n"
  "['CAPTION','INK_FAINT'].forEach(function(n){p[n]=toward(p[n],c.accent,0.10);});\n"
  "['DIVIDER','RULE','LINE','CHIP','POPUP_BORDER'].forEach(function(n){p[n]=toward(p[n],c.accent);});\n"
  "p.STATUS_BLUE=c.accent;p.ALT_TEXT=c.accent;p.WEIGHT_BG=c.accent;p.WEIGHT_BG_PRESSED=shade(c.accent,dark?16:-16);\n"
  "['WEIGHT_TEXT','WEIGHT_AUTO','WEIGHT_SENT','WEIGHT_COUNT'].forEach(function(n){p[n]=p.ON_ACCENT;});}\n"
  "return p;}\n"
  "function page(){var d=document.documentElement,a=d.getAttribute('data-accent'),t=d.getAttribute('data-tone');if(!a&&!t)return;\n"
  "var c={accent:a||null,tone:t?+t:-1,strength:+(d.getAttribute('data-tstr')||50)},cs=getComputedStyle(d);\n"
  "function get(v){return cs.getPropertyValue(v).trim();}\n"
  "if(tinting(c))WEB_TINT.forEach(function(r){var v=get(r[0]);if(v)d.style.setProperty(r[0],'#'+tint(v,c.tone,c.strength/50,r[1]));});\n"
  "if(c.accent){d.style.setProperty('--accent','#'+c.accent);WEB_ACC.forEach(function(v){var x=get(v);if(x)d.style.setProperty(v,'#'+toward(x,c.accent));});}}\n"
  "return{apply:apply,contrast:contrast,page:page};})();\n"
  "TC.page();\n"
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
