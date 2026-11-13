#include "web/pages/page_logs_session.h"

#include "web/web_shell.h"
// Last on purpose, as in every page: T() is a macro.
#include "lang.h"

// The card in the page's palette. Full screen lays the same card over the
// window instead of opening a second view of the log.
static const char SESSION_STYLE[] PROGMEM =
  "<style>"
  "#slcard .sltools{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-top:16px}"
  "#slcard .sltools input{flex:1;min-width:140px;max-width:320px}"
  "#sl{max-height:340px;overflow:auto;background:var(--ground);border:1px solid var(--line);"
  "border-radius:8px;padding:10px;line-height:1.5;white-space:pre-wrap;"
  "word-break:break-word;margin:16px 0}"
  "#sl .ok{color:var(--good)}#sl .warn{color:var(--warn)}#sl .err{color:var(--bad)}"
  "#sl .ts{color:var(--ink-soft)}"
  "#slcard.full{position:fixed;inset:0;z-index:100;margin:0;width:auto;max-width:none;"
  "border-radius:0;display:flex;flex-direction:column;overflow:hidden}"
  "#slcard.full #sl{flex:1;max-height:none}"
  "#slcard.full #slnote{display:none}"
  "</style>";

// One request at a time: the next poll waits until the last one has answered,
// and one that never answers is given up after SL_STUCK_MS. An error answer
// (flashing, gate shut, login) is no log line. A sequence number below the one
// asked for means the scale restarted, and the next poll fetches the ring from
// scratch. The view follows the end until it is scrolled up, and again once it
// is back at the end.
//
// How a line is coloured: the first phrase it contains, case ignored, decides.
// The log speaks English whatever the language setting, so the phrases are
// English, and a reworded log line is a one-line fix here. Errors come first,
// so "did not read back" stays red although it also says "read".
static const char SESSION_SCRIPT[] PROGMEM =
  "var SL_RULES=["
  "['err','error'],['err','fail'],['err','refus'],['err','not written'],['err','unreadable'],"
  "['err','abort'],['err','did not read back'],['err','not found'],['err','lost'],"
  "['ok','written and verified'],['ok','wrote spool'],['ok','http 200'],['ok','http 201'],"
  "['ok','http 204'],['ok','-> ok'],['ok',' ok '],['ok','identified'],['ok','settled'],"
  "['warn','no answer'],['warn','silent'],['warn','stopped answering'],['warn','noisy'],"
  "['warn','waiting'],['warn','weak'],['warn','retry'],['warn','again']];"
  "var slSeq=null,slLines=[],slFollow=true,slPend=0,slAuto=false,slQ='',slFs=12,"
  "slBusy=false,slSince=0,slReq=0,SL_MAX=2000,SL_POLL_MS=3000,SL_STUCK_MS=10000,"
  "SL_NL=String.fromCharCode(10);"
  "try{slFs=parseInt(localStorage.getItem('slfs'))||12;}catch(e){}"
  "function slEl(i){return document.getElementById(i);}"
  "function slKind(l){var s=' '+l.toLowerCase()+' ';"
  "for(var i=0;i<SL_RULES.length;i++)if(s.indexOf(SL_RULES[i][1])>=0)return SL_RULES[i][0];"
  "return '';}"
  "function slEsc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}"
  "function slOne(l){var c=slKind(l),m=l.match(/^(\\[[^\\]]*\\])(.*)$/),"
  "t=m?'<span class=\"ts\">'+slEsc(m[1])+'</span>'+slEsc(m[2]):slEsc(l);"
  "return c?'<span class=\"'+c+'\">'+t+'</span>':t;}"
  "function slShown(){var f=slQ.toLowerCase();if(!f)return slLines;"
  "return slLines.filter(function(l){return l.toLowerCase().indexOf(f)>=0;});}"
  "function slNote(){var s=slEl('sls');if(!s)return;"
  "s.textContent=slFollow?(SESSION_AT+' '+new Date().toLocaleTimeString()"
  "+' - '+slShown().length+' '+SESSION_LINES)"
  ":(SESSION_PAUSED+(slPend?' - '+slPend+' '+SESSION_NEW:''));}"
  "function slAtEnd(){var e=slEl('sl');return e.scrollTop+e.clientHeight>=e.scrollHeight-20;}"
  "function slToEnd(){var e=slEl('sl');if(slAtEnd())return;slAuto=true;"
  "e.scrollTop=e.scrollHeight;}"
  "function slRender(){var e=slEl('sl'),a=slShown();"
  "e.innerHTML=a.length?a.map(slOne).join(SL_NL):slEsc(SESSION_EMPTY);"
  "slPend=0;slNote();if(slFollow)slToEnd();}"
  "function slTake(d){if(d.rst)slLines=[];"
  "var a=d.t?d.t.split(SL_NL).filter(function(x){return x;}):[];"
  "slLines=slLines.concat(a);if(slLines.length>SL_MAX)slLines=slLines.slice(-SL_MAX);"
  "if(!d.rst&&!a.length){slNote();return;}"
  "if(slFollow||d.rst)slRender();else{slPend+=a.length;slNote();}}"
  "function slFwLabel(){var f=slEl('slfw');if(f)f.textContent=slFollow?L_LIVE:L_PAUSED;}"
  "function slSetFollow(v){slFollow=v;slFwLabel();"
  "if(v){if(slPend)slRender();else slToEnd();}slNote();}"
  "function loadSession(manual){var b=slEl('slb');"
  "if(!manual&&document.hidden)return;"
  "if(slBusy&&!manual&&Date.now()-slSince<SL_STUCK_MS)return;"
  "if(manual){slSeq=null;slFollow=true;slPend=0;slFwLabel();"
  "if(b){b.disabled=true;b.textContent=SESSION_BUSY;}}"
  "slBusy=true;slSince=Date.now();var my=++slReq,asked=slSeq;"
  "fetch('/api/log/session'+(asked===null?'':'?since='+asked)).then(function(r){"
  "if(!r.ok)throw 0;var n=parseInt(r.headers.get('X-Log-Seq'));"
  "if(asked!==null&&!isNaN(n)&&n<asked){slSeq=null;return null;}"
  "var rst=r.headers.get('X-Log-Reset')==='1';"
  "return r.text().then(function(t){if(!isNaN(n))slSeq=n;return{t:t,rst:rst};});})"
  ".then(function(d){if(my===slReq&&d)slTake(d);})"
  ".catch(function(){var s=slEl('sls');if(s)s.textContent='-';})"
  ".finally(function(){if(my===slReq)slBusy=false;"
  "if(b&&manual){b.disabled=false;b.textContent=SESSION_REFRESH;}});}"
  "function slCopy(){var e=slEl('sl'),b=slEl('slc');if(!e||!b)return;"
  "var txt=e.textContent||'';"
  "var done=function(ok){b.textContent=ok?SESSION_COPIED:SESSION_COPYFAIL;"
  "setTimeout(function(){b.textContent=SESSION_COPY;},1500);};"
  "if(navigator.clipboard&&window.isSecureContext){"
  "navigator.clipboard.writeText(txt).then(function(){done(true);},"
  "function(){done(false);});return;}"
  "var t=document.createElement('textarea');t.value=txt;t.setAttribute('readonly','');"
  "t.style.position='fixed';t.style.top='-1000px';"
  "document.body.appendChild(t);t.select();"
  "var ok=false;try{ok=document.execCommand('copy');}catch(err){ok=false;}"
  "document.body.removeChild(t);done(ok);}"
  "function slSize(d){slFs=Math.max(10,Math.min(24,slFs+d));slEl('sl').style.fontSize=slFs+'px';"
  "try{localStorage.setItem('slfs',slFs);}catch(e){}if(slFollow)slToEnd();}"
  "function slIsFull(){return slEl('slcard').classList.contains('full');}"
  "function slFull(v){slEl('slcard').classList.toggle('full',v);"
  "document.body.style.overflow=v?'hidden':'';"
  "slEl('slfs').textContent=v?L_FULL_EXIT:L_FULL;if(slFollow)slToEnd();}"
  "function slWatch(){var e=slEl('sl');if(!e)return;slSize(0);slFwLabel();"
  "slEl('slb').addEventListener('click',function(){loadSession(true);});"
  "slEl('slc').addEventListener('click',slCopy);"
  "slEl('slsm').addEventListener('click',function(){slSize(-2);});"
  "slEl('sllg').addEventListener('click',function(){slSize(2);});"
  "slEl('slfw').addEventListener('click',function(){slSetFollow(!slFollow);});"
  "slEl('slfs').addEventListener('click',function(){slFull(!slIsFull());});"
  "slEl('slq').addEventListener('input',function(ev){slQ=ev.target.value;slRender();});"
  "document.addEventListener('keydown',function(ev){"
  "if(ev.key==='Escape'&&slIsFull())slFull(false);});"
  "e.addEventListener('scroll',function(){if(slAuto){slAuto=false;return;}"
  "if(slFollow&&!slAtEnd())slSetFollow(false);"
  "else if(!slFollow&&slAtEnd())slSetFollow(true);});"
  "loadSession(true);setInterval(function(){loadSession(false);},SL_POLL_MS);}"
  "slWatch();";

String sessionLogCard() {
  String h;
  h.reserve(1200);
  h += FPSTR(SESSION_STYLE);
  h += F("<div class='card wide' id='slcard'><h2>");
  h += T(STR_W_C_SESSION);
  h += F("</h2><p class='note' id='slnote'>");
  h += T(STR_W_SESSION_NOTE);
  h += F("</p><div class='sltools'><button id='slsm' class='quiet' title='");
  h += htmlEsc(T(STR_W_LIVE_SMALLER));
  h += F("'>A-</button><button id='sllg' class='quiet' title='");
  h += htmlEsc(T(STR_W_LIVE_LARGER));
  h += F("'>A+</button><input id='slq' type='text' placeholder='");
  h += htmlEsc(T(STR_W_LIVE_FILTER));
  h += F("'><button id='slfw' class='quiet'></button><button id='slfs' class='quiet'>");
  h += T(STR_W_SESSION_FULL);
  h += F("</button></div><pre id='sl'></pre>"
         "<div style='display:flex;flex-wrap:wrap;gap:12px;align-items:center'>"
         "<button id='slb' class='quiet'>");
  h += T(STR_W_SESSION_REFRESH);
  h += F("</button><button id='slc' class='quiet'>");
  h += T(STR_W_SESSION_COPY);
  h += F("</button><span id='sls' class='note' style='margin:0'></span></div></div>");
  return h;
}

String sessionLogScript() {
  String h;
  h.reserve(sizeof(SESSION_SCRIPT) + 1200);
  h += F("<script>const SESSION_EMPTY=");
  h += jsStr(T(STR_W_SESSION_EMPTY));
  h += F(",SESSION_BUSY=");     h += jsStr(T(STR_W_SESSION_BUSY));
  h += F(",SESSION_REFRESH=");  h += jsStr(T(STR_W_SESSION_REFRESH));
  h += F(",SESSION_AT=");       h += jsStr(T(STR_W_SESSION_UPDATED));
  h += F(",SESSION_LINES=");    h += jsStr(T(STR_W_SESSION_LINES));
  h += F(",SESSION_PAUSED=");   h += jsStr(T(STR_W_SESSION_PAUSED));
  h += F(",SESSION_NEW=");      h += jsStr(T(STR_W_SESSION_NEW));
  h += F(",SESSION_COPY=");     h += jsStr(T(STR_W_SESSION_COPY));
  h += F(",SESSION_COPIED=");   h += jsStr(T(STR_W_SESSION_COPIED));
  h += F(",SESSION_COPYFAIL="); h += jsStr(T(STR_W_SESSION_COPYFAIL));
  h += F(",L_LIVE=");           h += jsStr(T(STR_W_LIVE_FOLLOW));
  h += F(",L_PAUSED=");         h += jsStr(T(STR_W_LIVE_PAUSE));
  h += F(",L_FULL=");           h += jsStr(T(STR_W_SESSION_FULL));
  h += F(",L_FULL_EXIT=");      h += jsStr(T(STR_W_SESSION_FULL_EXIT));
  h += F(";");
  h += FPSTR(SESSION_SCRIPT);
  h += F("</script>");
  return h;
}
