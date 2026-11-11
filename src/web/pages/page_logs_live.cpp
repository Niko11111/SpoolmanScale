#include "web/pages/page_logs_live.h"

#include <Arduino.h>

#include "web/web_access.h"
#include "web/web_shell.h"
#include "lang.h"

// The page's own rules, on top of /app.css and in the scale's palette: the
// bar stays at the top, the log takes the rest of the window.
static const char LIVE_STYLE[] PROGMEM =
  "<style>"
  "body{display:block;padding:0;margin:0}"
  "#bar{position:sticky;top:0;z-index:2;display:flex;flex-wrap:wrap;gap:8px;"
  "align-items:center;padding:10px 14px;background:var(--surface);"
  "border-bottom:1px solid var(--line)}"
  "#bar b{font-size:16px;margin-right:8px;color:var(--ink)}"
  "#q{font:inherit;font-size:14px;min-width:200px;flex:1;max-width:360px;padding:6px 10px;"
  "border-radius:8px;border:1px solid var(--line);background:var(--surface-2);color:var(--ink)}"
  "button.on{background:var(--accent-dim);border-color:var(--accent-line);color:var(--accent)}"
  "#st{color:var(--ink-soft);font-size:13px;margin-left:auto}"
  "#out{margin:0;padding:12px 16px 40px;font-family:var(--mono);color:var(--ink-2);"
  "white-space:pre-wrap;word-break:break-word;line-height:1.45}"
  ".ok{color:var(--good)}.warn{color:var(--warn)}.err{color:var(--bad)}.ts{color:var(--ink-soft)}"
  "</style>";

// One request at a time: the next poll waits until the last one has answered,
// so a slow scale never has two of them in flight. The view follows the end
// of the log until it is scrolled up, and again once it is back at the end.
//
// How a line is coloured: the first phrase it contains, case ignored, decides.
// The log speaks English whatever the language setting, so the phrases are
// English, and a reworded log line is a one-line fix here. Errors come first,
// so "did not read back" stays red although it also says "read".
static const char LIVE_SCRIPT[] PROGMEM =
  "var RULES=["
  "['err','error'],['err','fail'],['err','refus'],['err','not written'],['err','unreadable'],"
  "['err','abort'],['err','did not read back'],['err','not found'],['err','lost'],"
  "['ok','written and verified'],['ok','wrote spool'],['ok','http 200'],['ok','http 201'],"
  "['ok','http 204'],['ok','-> ok'],['ok',' ok '],['ok','identified'],['ok','settled'],"
  "['warn','no answer'],['warn','silent'],['warn','stopped answering'],['warn','noisy'],"
  "['warn','waiting'],['warn','weak'],['warn','retry'],['warn','again']];"
  "var NL=String.fromCharCode(10),seq=null,lines=[],follow=true,q='',fs=16,MAX=5000,"
  "busy=false,auto=false,POLL_MS=2000;"
  "try{fs=parseInt(localStorage.getItem('livelogfs'))||16;}catch(e){}"
  "var out=document.getElementById('out'),st=document.getElementById('st'),"
  "fw=document.getElementById('fw'),cp=document.getElementById('cp');"
  "function size(d){fs=Math.max(10,Math.min(32,fs+d));out.style.fontSize=fs+'px';"
  "try{localStorage.setItem('livelogfs',fs);}catch(e){}}"
  "function kind(l){var s=' '+l.toLowerCase()+' ';"
  "for(var i=0;i<RULES.length;i++)if(s.indexOf(RULES[i][1])>=0)return RULES[i][0];return '';}"
  "function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}"
  "function one(l){var c=kind(l);"
  "var m=l.match(/^(\\[[^\\]]*\\])(.*)$/),"
  "t=m?'<span class=\"ts\">'+esc(m[1])+'</span>'+esc(m[2]):esc(l);"
  "return c?'<span class=\"'+c+'\">'+t+'</span>':t;}"
  "function toEnd(){auto=true;window.scrollTo(0,document.body.scrollHeight);}"
  "function render(){var f=q.toLowerCase(),o=[],n=0;"
  "for(var i=0;i<lines.length;i++){"
  "if(f&&lines[i].toLowerCase().indexOf(f)<0)continue;o.push(one(lines[i]));n++;}"
  "out.innerHTML=o.join(NL);"
  "st.textContent=n+(f?' / '+lines.length:'')+' - '+new Date().toLocaleTimeString();"
  "if(follow)toEnd();}"
  "function take(d){if(d.rst)lines=[];"
  "if(d.t){var a=d.t.split(NL);for(var i=0;i<a.length;i++)if(a[i])lines.push(a[i]);"
  "if(lines.length>MAX)lines=lines.slice(-MAX);}"
  "if(d.rst||d.t)render();}"
  "function poll(){if(busy||document.hidden)return;busy=true;"
  "fetch('/api/log/session'+(seq===null?'':'?since='+seq)).then(function(r){"
  "seq=parseInt(r.headers.get('X-Log-Seq')||seq||0);"
  "var rst=r.headers.get('X-Log-Reset')==='1';"
  "return r.text().then(function(t){return{t:t,rst:rst};});})"
  ".then(take).catch(function(){st.textContent='-';})"
  ".finally(function(){busy=false;});}"
  "function setFollow(v){follow=v;fw.classList.toggle('on',v);"
  "fw.textContent=v?L_FOLLOW:L_PAUSE;if(v)toEnd();}"
  "function atEnd(){return window.innerHeight+window.scrollY>=document.body.scrollHeight-20;}"
  "window.addEventListener('scroll',function(){if(auto){auto=false;return;}"
  "if(follow&&!atEnd())setFollow(false);else if(!follow&&atEnd())setFollow(true);});"
  "function copied(ok){cp.textContent=ok?L_COPIED:L_COPYFAIL;"
  "setTimeout(function(){cp.textContent=L_COPY;},1500);}"
  "function copy(){var t=out.innerText;"
  "if(navigator.clipboard&&window.isSecureContext){"
  "navigator.clipboard.writeText(t).then(function(){copied(true);},function(){copied(false);});"
  "return;}"
  "var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();"
  "var ok=false;try{ok=document.execCommand('copy');}catch(e){}"
  "document.body.removeChild(x);copied(ok);}"
  "fw.addEventListener('click',function(){setFollow(!follow);});"
  "document.getElementById('sm').addEventListener('click',function(){size(-2);});"
  "document.getElementById('lg').addEventListener('click',function(){size(2);});"
  "document.getElementById('q').addEventListener('input',function(e){q=e.target.value;render();});"
  "cp.addEventListener('click',copy);"
  "size(0);setFollow(true);poll();setInterval(poll,POLL_MS);";

// The bar: title, smaller, larger, follow or pause, filter, copy, status.
static void appendBar(String &h) {
  h += F("<div id='bar'><b>");
  h += T(STR_W_C_SESSION);
  h += F("</b><button id='sm' class='quiet' title='");
  h += htmlEsc(T(STR_W_LIVE_SMALLER));
  h += F("'>A-</button><button id='lg' class='quiet' title='");
  h += htmlEsc(T(STR_W_LIVE_LARGER));
  h += F("'>A+</button><button id='fw' class='quiet on'></button>"
         "<input id='q' type='search' placeholder='");
  h += htmlEsc(T(STR_W_LIVE_FILTER));
  h += F("'><button id='cp' class='quiet'>");
  h += T(STR_W_SESSION_COPY);
  h += F("</button><span id='st'></span></div><pre id='out'></pre>");
}

static void appendScript(String &h) {
  h += F("<script>var L_FOLLOW=");
  h += jsStr(T(STR_W_LIVE_FOLLOW));
  h += F(",L_PAUSE=");    h += jsStr(T(STR_W_LIVE_PAUSE));
  h += F(",L_COPY=");     h += jsStr(T(STR_W_SESSION_COPY));
  h += F(",L_COPIED=");   h += jsStr(T(STR_W_SESSION_COPIED));
  h += F(",L_COPYFAIL="); h += jsStr(T(STR_W_SESSION_COPYFAIL));
  h += F(";");
  h += FPSTR(LIVE_SCRIPT);
  h += F("</script>");
}

void logLiveRoutes(WebServer &srv) {
  srv.on("/log/live", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    String h;
    h.reserve(6000);
    h += webShellDocOpen();
    h += F("<head><meta charset='utf-8'>"
           "<meta name='viewport' content='width=device-width,initial-scale=1'>"
           "<link rel='icon' type='image/png' href='/favicon.png'><title>");
    h += T(STR_W_C_SESSION);
    h += F("</title>");
    h += webShellAssets();
    h += FPSTR(LIVE_STYLE);
    h += F("</head><body>");
    appendBar(h);
    appendScript(h);
    h += F("</body></html>");
    srv.sendHeader("Cache-Control", "no-store");
    srv.send(200, "text/html; charset=utf-8", h);
  });
}
