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
#include "services/backend_job.h"
#include "services/prefs_store.h"
#include "services/tag_field.h"
#include "services/tag_link.h"
#include "services/tag_write.h"
#include "services/user_options.h"
#include "web/web_access.h"
#include "web/web_jobs.h"
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
         // Below the pair and across both columns: the two tag cards stay side
         // by side, which is what the compare note under the buttons describes.
         "<div class='card wide' style='background:var(--surface-2);padding:14px' id='tg-matched'></div>"
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
         "<label class='check' style='margin-top:14px'><span class='switch'>"
         "<input id='tg-link' type='checkbox' checked><i></i></span>");
  h += T(STR_W_TAG_LINK);
  h += F("</label>"
         "<div class='inrow' style='margin-top:16px'>"
         "<button id='tg-btn' onclick='writeTag()' disabled></button>"
         "<button id='tg-erase' class='danger' onclick='eraseTag()' disabled>");
  h += T(STR_W_TAG_ERASE);
  // Binds the tag without writing it: the one way in the browser for a tag
  // that can only be read, and for an NTAG whose contents should stay.
  h += F("</button><button id='tg-lnk' class='quiet' disabled>");
  h += T(STR_W_TAG_LINKONLY);
  h += F("</button><span class='msg' id='tg-s'></span></div>"
         // Its own line: a write keeps its result standing in tg-s, and the
         // poll would paint over a link's answer every three seconds.
         "<div id='tg-ls' class='msg' style='margin-top:10px'></div>"
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
  h += F("</p></div>");

  // What the scale does on its own after a link, as opposed to what this page
  // does when the button above is pressed. Same two settings as Settings >
  // Scale on the device, and the note says which of the two is which - the
  // format selector above belongs to the write on this page and nothing else.
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_C_TAGOPTS);
  h += F("</h2>"
         "<div class='field'><label>");
  h += T(STR_W_TAGOPT_ASK);
  h += F("</label><div class='inrow'>"
         "<select id='to-ask' style='min-width:210px'>"
         "<option value='0'>");
  h += T(STR_TW_MODE_OFF);
  h += F("</option><option value='1'>");
  h += T(STR_TW_MODE_ASK);
  h += F("</option><option value='2'>");
  h += T(STR_TW_MODE_ALWAYS);
  h += F("</option></select></div></div>"
         "<label class='check' style='margin-top:14px'><span class='switch'>"
         "<input id='to-mism' type='checkbox'><i></i></span>");
  h += T(STR_W_TAGOPT_MISM);
  h += F("</label>"
         "<div class='field' style='margin-top:14px'><label>");
  h += T(STR_W_TAGOPT_FMT);
  h += F("</label><div class='inrow'>"
         "<select id='to-fmt' style='min-width:210px'>"
         "<option value='1'>OpenSpool</option>"
         "<option value='3'>FilaMan</option>"
         "<option value='0'>Anycubic ACE</option>"
         "</select></div></div>"
         // No save button: each control writes when it is changed, the way the
         // switches on the config page do. A settings card that looks saved
         // but is not is the failure this avoids.
         "<div class='inrow' style='margin-top:16px'>"
         "<span class='msg' id='to-s'></span></div>"
         "<p class='note' style='margin-top:10px'>");
  h += T(STR_W_TAGOPT_NOTE);
  h += F("</p></div></div>");

  // Its own script. When the pages were split the shared block stayed behind
  // on the drying page, so every function this page calls was missing and the
  // whole page did nothing at all.
  h += F("<style>#tg-cur h3,#tg-matched h3,#tg-new h3{font-size:10.5px;font-weight:650;"
         "letter-spacing:.1em;text-transform:uppercase;color:var(--ink-soft);margin-bottom:10px}"
         ".tgline{display:flex;align-items:center;gap:9px;margin-bottom:8px}"
         ".chip{width:26px;height:26px;border-radius:7px;border:1px solid #ffffff22;flex:none}"
         ".tgname{font-size:13.5px;color:var(--ink);line-height:1.3}"
         ".tglink{color:var(--accent)}"
         "#tg-cur table td,#tg-matched table td,#tg-new table td{font-size:11.5px;"
         "font-family:var(--mono);color:var(--ink-3);padding:3px 8px 3px 0;border:0;"
         "overflow-wrap:anywhere}"
         // Across both columns the values would otherwise start in the middle.
         "#tg-matched table{width:auto}"
         "tr.diff td{color:var(--warn)}</style>");

  h += F("<script>const TO={saved:");
  h += jsStr(T(STR_W_SAVED));
  h += F(",err:");  h += jsStr(T(STR_W_LOAD_FAIL));
  h += F("};"
         // All three values in one line, same shape as /api/tag/write above, so
         // the route stays a handful of lines and needs no JSON parser.
         "function loadTagOpts(){fetch('/api/tagopts').then(r=>r.json()).then(d=>{"
         "document.getElementById('to-ask').value=String(d.ask);"
         "document.getElementById('to-mism').checked=!!d.mism;"
         "document.getElementById('to-fmt').value=String(d.fmt);"
         "}).catch(()=>{});}"
         "function saveTagOpts(){"
         "const a=document.getElementById('to-ask').value;"
         "const m=document.getElementById('to-mism').checked?1:0;"
         "const f=document.getElementById('to-fmt').value;"
         "const s=document.getElementById('to-s');"
         "fetch('/api/tagopts',{method:'POST',body:a+','+f+','+m})"
         ".then(r=>r.json()).then(()=>{s.textContent=TO.saved;"
         "setTimeout(()=>{s.textContent='';},4000);})"
         // The controls already show what was asked for, so a failed write has
         // to put them back rather than leave a switch claiming a state the
         // scale is not in. Re-reading is the shortest way to the truth.
         ".catch(()=>{s.textContent=TO.err;loadTagOpts();});}"
         "['to-ask','to-mism','to-fmt'].forEach(function(id){"
         "document.getElementById(id).addEventListener('change',saveTagOpts);});"
         "loadTagOpts();"
         "</script>");

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
  h += F(",norec:");   h += jsStr(T(STR_W_TAG_NOREC));
  h += F(",ro:");      h += jsStr(T(STR_TW_ERR_NOT_NTAG));
  h += F(",tray:");    h += jsStr(T(STR_W_TAG_TRAY));
  h += F(",prod:");    h += jsStr(T(STR_LBL_PRODUCTION_DATE));
  h += F(",onscale:"); h += jsStr(T(STR_W_TAG_ONSCALE));
  h += F(",nospool:"); h += jsStr(T(STR_W_TAG_NOSPOOL));
  h += F(",remain:");  h += jsStr(T(STR_AMSD_REMAINING));
  h += F(",total:");   h += jsStr(T(STR_LBL_TOTAL_CAP));
  h += F(",tare:");    h += jsStr(T(STR_LBL_SPOOL_WEIGHT_EMPTY));
  h += F(",loc:");     h += jsStr(T(STR_BTN_LOCATION));
  h += F(",art:");     h += jsStr(T(STR_LBL_ARTICLE_NO_SHORT));
  h += F(",used:");    h += jsStr(T(STR_LBL_LAST_USED));
  h += F(",dried:");   h += jsStr(T(STR_LBL_LAST_DRIED));
  h += F(",rolink:");  h += jsStr(T(STR_W_TAG_RO_LINK));
  h += F(",lask:");    h += jsStr(T(STR_W_TL_ASK_REPLACE));
  h += F(",ladd:");    h += jsStr(T(STR_W_TL_ASK_ADD));
  h += F(",lbusy:");   h += jsStr(T(STR_W_TL_REFUSED));
  h += F("};"
         "let tgCur='',tgNew='',tgLinked='',tgUid='',tgCurI=null,tgNewI=null,tgMatched=null,"
         "tgBytes=0,tgNeed=0,tgKindCode=0,tgAdds=false;"
         // The quote as well: esc() also fills an href.
         "function esc(t){return String(t).replace(/[<>&\"]/g,c=>"
         "({'<':'&lt;','>':'&gt;','&':'&amp;','\"':'&quot;'}[c]));}"
         // A row is only drawn when the side it belongs to has the field, and
         // it is highlighted when the two sides disagree - that difference is
         // the whole reason both are shown.
         "function row(k,a,b){if(a===undefined&&b===undefined)return '';"
         "const d=(a!==undefined&&b!==undefined&&a!==b)?' class=\"diff\"':'';"
         "return '<tr'+d+'><td>'+k+'</td><td>'+esc(a===undefined?'-':a)+'</td></tr>';}"
         // The spool card has one side only, and an empty field is no row -
         // "-" included, which is how the device says "never" for a date.
         "function one(k,v){return(v===undefined||v===null||v===''||v==='-')?'':row(k,v);}"
         "function plain(el,t,x){el.innerHTML='<h3>'+t+'</h3>'"
         "+'<div class=\"hint\">'+x+'</div>';}"
         "function head(c,n,x){return '<div class=\"tgline\"><div class=\"chip\" style=\"background:'"
         "+(c||'#101828')+'\"></div><div><div class=\"tgname\">'+n+'</div>'"
         "+'<div class=\"hint\">'+x+'</div></div></div>';}"
         "function swatch(el,i,o,t,empty){if(!el)return;"
         "if(!i||!i.fmt){plain(el,t,empty);return;}"
         // A MIFARE tag that is neither Bambu's nor Snapmaker's. The UID is in
         // the line above the cards already.
         "if(i.fmt=='unsupported'){plain(el,t,M.norec);return;}"
         "if(i.fmt=='blank'){plain(el,t,M.blank);return;}"
         "if(i.fmt=='unknown'){plain(el,t,M.unk);return;}"
         "o=o||{};"
         "el.innerHTML='<h3>'+t+'</h3>'"
         "+head(i.color,esc(i.brand||'')+' '+esc(i.material||''),"
         "esc(i.fmt)+(i.color?' - '+esc(i.color):''))"
         "+'<table>'"
         "+row(M.sku,i.sku,o.sku)"
         "+row(M.nozzle,i.nozzle?i.nozzle+' C':undefined,o.nozzle?o.nozzle+' C':undefined)"
         "+row(M.bed,i.bed?i.bed+' C':undefined,o.bed?o.bed+' C':undefined)"
         "+row(M.weight,i.weight?i.weight+' g':undefined,o.weight?o.weight+' g':undefined)"
         "+row(M.dia,i.dia?i.dia+' mm':undefined,o.dia?o.dia+' mm':undefined)"
         "+row(M.len,i.len?i.len+' m':undefined,o.len?o.len+' m':undefined)"
         "+row(M.prod,i.prod_date,o.prod_date)"
         "+row(M.tray,i.tray_uuid,o.tray_uuid)"
         "+'</table>';}"
         // The spool the scale shows, which is not necessarily the tag's: one
         // picked from the list stays after its tag is lifted. Hence its own
         // title rather than "matched".
         "function spool(el){if(!el)return;const m=tgMatched;"
         "if(!m||!m.found){plain(el,M.onscale,M.nospool);return;}"
         "const id=m.url?'<a class=\"tglink\" href=\"'+esc(m.url)+'\" target=\"_blank\" rel=\"noopener\">#'"
         "+m.id+'</a>':'#'+m.id;"
         "const vm=[m.vendor,m.material].filter(Boolean).map(esc).join(' ');"
         "let b='';(m.binds||[]).forEach(x=>{b+=one(esc(x.k),x.v);});"
         "el.innerHTML='<h3>'+M.onscale+'</h3>'"
         "+head(m.color,esc(m.name||''),id+(vm?' - '+vm:''))"
         "+'<table>'"
         "+one(M.remain,m.total?m.remaining+' / '+m.total+' g':undefined)"
         "+one(M.tare,m.tare?m.tare+' g':undefined)"
         "+one(M.loc,m.location)+one(M.art,m.article_nr)"
         "+one(M.used,m.last_used)+one(M.dried,m.last_dried)+b"
         "+'</table>';}"
         "function tgDraw(){"
         "swatch(document.getElementById('tg-cur'),tgCurI,tgNewI,M.cur,M.notag);"
         "spool(document.getElementById('tg-matched'));"
         "swatch(document.getElementById('tg-new'),tgNewI,tgCurI,M.will,M.pickf);}"
         "function tgSync(){tgDraw();const b=document.getElementById('tg-btn');if(!b)return;"
         // Said before the write, not after it. The capacity check inside the
         // firmware refuses the same tag, but only once the user has already
         // pressed the button and put the tag on the reader.
         "const small=tgNeed&&tgBytes&&tgNeed>tgBytes;"
         "const fs=document.getElementById('tg-fmt');"
         "const fn=fs&&fs.selectedOptions[0]?fs.selectedOptions[0].textContent:'';"
         "const n=document.getElementById('tg-note');"
         "const er=document.getElementById('tg-erase');"
         // The kind alone decides. An NTAG that reports no size is still
         // writable, and the write itself says so if it does not fit.
         "const ro=tgKindCode===1;"
         // Any tag can be linked, a read-only one included; it needs a spool.
         "const lk=document.getElementById('tg-lnk');"
         "if(lk)lk.disabled=!tgUid||!parseInt(document.getElementById('tg-id').value);"
         "if(n)n.textContent=ro?M.rolink:!tgNew?M.pickf:small"
         "?M.toosmall.replace('%s',fn).replace('%u',tgNeed).replace('%u',tgBytes)"
         // tgLinked is already "a different tag than the one on the reader" - the
         // comparison used to happen here and compared "047F3ABBD12A81" against
         // "04:7F:3A:BB:D1:2A:81", so the warning appeared for the very tag the
         // user was holding.
         ":(tgLinked?M.relink.replace('%s',tgLinked):'');"
         "if(ro){b.disabled=true;b.textContent=M.write;if(er)er.disabled=true;return;}"
         "if(er)er.disabled=!tgUid||tgCur=='blank';"
         "if(!tgNew){b.disabled=true;b.textContent=M.write;return;}"
         "if(small){b.disabled=true;b.textContent=M.write;return;}"
         "if(tgCur===tgNew){b.disabled=true;b.textContent=M.match;}"
         "else{b.disabled=false;b.textContent=tgCur&&tgCur!='blank'?M.over:M.write;}}"
         "function loadPreview(){const v=parseInt(document.getElementById('tg-id').value);"
         "const f=document.getElementById('tg-fmt').value;"
         "if(!v){document.getElementById('tg-pick').value='';tgNew='';tgNewI=null;tgSync();return;}"
         "fetch('/api/tag/preview?id='+v+'&fmt='+f).then(r=>r.json()).then(d=>{"
         "tgNew=d.ok?d.preview:'';tgLinked=d.ok?(d.linked||''):'';"
         "tgNeed=d.ok?(d.need||0):0;"
         "tgNewI=d.ok?d.info:null;tgSync();})"
         ".catch(()=>{tgNew='';tgNewI=null;tgNeed=0;tgSync();});}"
         "function setOpt(p,t){p.innerHTML='';const o=document.createElement('option');"
         "o.value='';o.textContent=t;p.appendChild(o);}"
         // Back to "pick a spool" empties the number too, or the preview of
         // the spool picked before would stay standing.
         "function pickSpool(){const p=document.getElementById('tg-pick');"
         "document.getElementById('tg-id').value=p.value||'';loadPreview();}"
         // 202 means the device is still fetching; asked again until it is not.
         "function loadSpools(n){const p=document.getElementById('tg-pick');if(!p)return;"
         "if(!n)setOpt(p,M.pick);"
         "fetch('/api/spools',{cache:'no-store'}).then(r=>{"
         "if(r.status===202){if((n||0)<40)setTimeout(()=>loadSpools((n||0)+1),700);"
         "else setOpt(p,M.nolist);return null;}return r.json();}).then(d=>{"
         "if(!d)return;"
         "if(d.error){setOpt(p,d.error);return;}"
         "setOpt(p,M.pick);"
         "d.forEach(s=>{const o=document.createElement('option');o.value=s.id;"
         "o.textContent='#'+s.id+'  '+s.label;p.appendChild(o);});"
         "}).catch(()=>setOpt(p,M.nolist));}"
         "function tgPoll(){fetch('/api/tag').then(r=>r.json()).then(d=>{"
         "document.getElementById('tg-uid').textContent="
         "d.uid?(M.onread+' '+d.uid+' ('+d.kind+')'):M.notag;"
         "tgUid=d.uid||'';tgCurI=d.uid?d.info:null;tgBytes=d.bytes||0;tgKindCode=d.kindcode||0;"
         "tgCur=d.content||'';tgMatched=d.matched;tgAdds=!!d.linkadds;tgSync();"
         "const ls=document.getElementById('tg-ls');"
         "if(ls){ls.textContent=d.linkstate&&d.linkstate!='idle'?d.linkmsg:'';"
         "ls.className='msg'+(d.linkstate=='error'?' bad':'');}"
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
         // The spool already carries a different tag: say what linking does to
         // it before doing it. tgLinked comes from the preview of the picked
         // spool and is empty when that tag is the one on the reader.
         "function linkTag(){const v=parseInt(document.getElementById('tg-id').value);"
         "if(!v||!tgUid)return;"
         "if(tgLinked&&!confirm((tgAdds?M.ladd:M.lask).replace('%d',v).replace('%s',tgLinked)))return;"
         "const ls=document.getElementById('tg-ls');"
         "fetch('/api/tag/link',{method:'POST',body:v+','+tgUid})"
         ".then(r=>r.json()).then(d=>{if(!d.ok&&ls)ls.textContent=M.lbusy;})"
         ".catch(()=>{});after();}"
         "document.addEventListener('DOMContentLoaded',()=>{"
         "const lk=document.getElementById('tg-lnk');if(lk)lk.addEventListener('click',linkTag);"
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

// What tag_write.cpp reports, said in the user's language. That file builds
// English prose because it cannot reach lang.h (T() collides with ArduinoJson's
// template parameter), so it hands out the parts - see TagWriteReport - and the
// sentence is put together here, where T() is available.
static String tagWriteMessageLocal() {
  const char *st = tagWriteState();
  if (!strcmp(st, "idle")) return String("");

  const TagWriteReport *r = tagWriteReportData();
  char buf[256];

  if (!strcmp(st, "pending")) {
    if (r->erase) return String(T(STR_W_TW_ERASING));
    snprintf(buf, sizeof(buf), T(STR_W_TW_WRITING), r->spool_id);
    return String(buf);
  }

  if (r->erase)
    return String(r->code == TW_OK ? T(STR_W_TW_ERASED) : T(STR_W_TW_ERASE_FAIL));

  String out;
  if (r->code == TW_OK) {
    snprintf(buf, sizeof(buf), T(STR_W_TW_WROTE), r->spool_id, r->name,
             tagFormatLabel(r->fmt));
    out = buf;
  } else {
    out = T(tagWriteResultString(r->code));
  }

  // The link is its own sentence half: a tag can be written and still not be
  // bound, which is exactly the case that has to be readable.
  if (r->link == TAG_LINK_OK) {
    if (r->link_note[0]) {
      snprintf(buf, sizeof(buf), T(STR_W_TW_LINKED_NOTE), r->link_note);
      out += buf;
    } else {
      out += T(STR_W_TW_LINKED);
    }
  } else if (r->link == TAG_LINK_FAIL) {
    snprintf(buf, sizeof(buf), T(STR_W_TW_LINK_FAIL), r->link_http);
    out += buf;
  }
  return out;
}

// "NTAG, beschreibbar, 496 Byte". Same reason as above: tagCachedKind() is
// English, tagCachedKindCode() is the part that translates.
static String tagKindLocal() {
  const uint8_t k = tagCachedKindCode();
  if (k == TAG_KIND_NONE) return String("");
  if (k == TAG_KIND_MIFARE) return String(T(STR_W_TAG_KIND_MIFARE));

  String out = T(STR_W_TAG_KIND_NTAG);
  const uint16_t b = tagCachedBytes();
  if (b) {
    char buf[24];
    snprintf(buf, sizeof(buf), T(STR_W_TAG_KIND_BYTES), (unsigned)b);
    out += buf;
  }
  return out;
}

// Where a link from this page stands, for the poll. OK covers "already bound",
// which is not a failure: the spool is found by that tag either way.
static const char* tagLinkStateName() {
  switch (tagLinkReportData()->code) {
    case TL_NONE:    return "idle";
    case TL_BUSY:    return "pending";
    case TL_OK:
    case TL_ALREADY: return "ok";
    default:         return "error";
  }
}

// The same for the sentence, which tag_link.cpp cannot build in the user's
// language.
static String tagLinkMessageLocal() {
  const TagLinkReport *r = tagLinkReportData();
  char buf[192];
  switch (r->code) {
    case TL_NONE:    return String("");
    case TL_BUSY:    snprintf(buf, sizeof(buf), T(STR_W_TL_BUSY), r->spool_id); break;
    case TL_OK:      snprintf(buf, sizeof(buf), T(STR_W_TL_OK), r->spool_id); break;
    case TL_ALREADY: snprintf(buf, sizeof(buf), T(STR_W_TL_ALREADY), r->spool_id); break;
    case TL_HELD:    snprintf(buf, sizeof(buf), T(STR_W_TL_HELD), r->other_spool); break;
    case TL_CHANGED: copyT(buf, sizeof(buf), STR_W_TL_CHANGED); break;
    case TL_NO_TAG:  copyT(buf, sizeof(buf), STR_TW_ERR_NO_TAG); break;
    case TL_NETWORK: copyT(buf, sizeof(buf), STR_LINK_NO_CONNECTION); break;
    default:         copyT(buf, sizeof(buf), STR_W_TL_FAILED); break;
  }
  return String(buf);
}

// The spool the scale shows, for the card between the two tag cards. All of
// it is in RAM already: the page asks every three seconds and must not cost
// the backend a request each time.
static String spoolJson() {
  if (!sm_found || sm_id <= 0) return String("{\"found\":false}");

  char url[160];
  backendSpoolPageUrl(sm_id, url, sizeof(url));

  // Only six plain hex digits reach the style attribute the card puts this
  // in. A spool with several colours, or anything odd, shows no chip.
  char col[8] = "";
  const char *c = sm_color_global[0] == '#' ? sm_color_global + 1 : sm_color_global;
  bool hex = true;
  for (int i = 0; i < 6 && hex; i++) hex = isxdigit((unsigned char)c[i]) != 0;
  if (hex) snprintf(col, sizeof(col), "#%.6s", c);

  // Every tag field that holds something, captioned the way the settings
  // name it, so the card shows which one binds this spool.
  String binds = "[";
  auto add = [&binds](const char *k, const char *v) {
    if (!v || !v[0]) return;
    if (binds.length() > 1) binds += ',';
    binds += String("{\"k\":\"") + jsonEsc(k) + "\",\"v\":\"" + jsonEsc(v) + "\"}";
  };
  for (uint8_t i = 0; i < TAG_FIELD_COUNT; i++)
    add(T(tagFieldSpec(i).str_name), sm_tag_values[i]);
  add("extra." RFID_TAG_FIELD, sm_hw_uid_value);
  binds += ']';

  return String("{\"found\":true,\"id\":") + sm_id +
         ",\"url\":\""        + jsonEsc(url) +
         "\",\"name\":\""     + jsonEsc(sm_filament_name) +
         "\",\"vendor\":\""   + jsonEsc(sm_vendor_g) +
         "\",\"material\":\"" + jsonEsc(sm_material_global) +
         "\",\"color\":\""    + col +
         "\",\"remaining\":"  + String(lroundf(sm_remaining)) +
         ",\"total\":"        + String(lroundf(sm_total)) +
         ",\"tare\":"         + String(lroundf(sm_spool_weight)) +
         ",\"location\":\""   + jsonEsc(sm_location_name) +
         "\",\"article_nr\":\"" + jsonEsc(sm_article_nr) +
         "\",\"last_used\":\""  + jsonEsc(sm_last_used) +
         "\",\"last_dried\":\"" + jsonEsc(sm_last_dried) +
         "\",\"binds\":" + binds + "}";
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
    // Start or collect. The list takes up to eight seconds to come in and
    // used to be fetched inside this handler, holding the loop task for
    // that long; it runs on the web worker now and the page asks again
    // until the answer is ready - 202 says "not yet".
    if (webJobState() == WJS_DONE && webJobKind() == WJ_SPOOLS) {
      const WebJobResult& r = webJobResult();
      if (!r.ok) {
        srv.send(200, "application/json",
                 String("{\"error\":\"backend HTTP ") + r.code + "\"}");
      } else {
        srv.send(200, "application/json", r.body);
      }
      webJobTake();
      return;
    }
    if (webJobState() == WJS_RUNNING || backendJobState() == BJS_RUNNING) {
      // Ours, another job's, or the lookup's inventory on the backend
      // worker: the page asks again either way.
      srv.send(202, "application/json", "{\"pending\":true}");
      return;
    }
    if (webJobState() == WJS_DONE) webJobTake();   // somebody else's leftover
    if (!webJobStart(WJ_SPOOLS, nullptr, false)) {
      srv.send(200, "application/json", "{\"error\":\"busy\"}");
      return;
    }
    srv.send(202, "application/json", "{\"pending\":true}");
  });

  srv.on("/api/tag", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_TAGS))) return;
    // Reader state comes from the loop task; touching the reader here would
    // race the main NFC poll.
    char info[320];
    tagInfoJson(tagCachedInfo(), info, sizeof(info));
    String j = String("{\"info\":") + info +
               ",\"bytes\":"    + String((unsigned)tagCachedBytes()) +
               ",\"kindcode\":" + String((int)tagCachedKindCode()) +
               ",\"uid\":\""     + jsonEsc(tagCachedUid()) +
               "\",\"kind\":\""    + jsonEsc(tagKindLocal().c_str()) +
               "\",\"state\":\""   + jsonEsc(tagWriteState()) +
               "\",\"message\":\"" + jsonEsc(tagWriteMessageLocal().c_str()) +
               "\",\"content\":\"" + jsonEsc(tagCachedContent()) +
               "\",\"linkstate\":\"" + tagLinkStateName() +
               "\",\"linkmsg\":\"" + jsonEsc(tagLinkMessageLocal().c_str()) +
               "\",\"linkadds\":" + (tagLinkKeepsOtherTags() ? "true" : "false") +
               ",\"matched\":" + spoolJson() + "}";
    srv.send(200, "application/json", j);
  });

  // GATE_CONFIG rather than GATE_MAINT: this changes what the device does
  // later, it does not write a tag now. The gate is a property of the route,
  // not of the page it happens to sit on.
  srv.on("/api/tagopts", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_C_TAGOPTS))) return;
    srv.send(200, "application/json",
             String("{\"ask\":") + String((int)g_tagwrite_mode) +
             ",\"mism\":" + (g_tagmismatch_ask ? "true" : "false") +
             ",\"fmt\":" + String((int)g_tagwrite_fmt) + "}");
  });

  srv.on("/api/tagopts", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_C_TAGOPTS))) return;
    if (!srv.hasArg("plain")) { srv.send(400, "application/json", "{\"error\":\"no body\"}"); return; }
    String body = srv.arg("plain");
    const int c1 = body.indexOf(',');
    const int c2 = c1 < 0 ? -1 : body.indexOf(',', c1 + 1);
    // 0 off, 1 ask, 2 write every time. A page from before this was a choice
    // sends 0 or 1, which lands on the same two states it always meant.
    const int mode = body.substring(0, c1 < 0 ? body.length() : c1).toInt();
    if (mode >= TAGWRITE_OFF && mode <= TAGWRITE_ALWAYS)
      g_tagwrite_mode = (uint8_t)mode;
    if (c1 >= 0) {
      const int f = body.substring(c1 + 1, c2 < 0 ? body.length() : c2).toInt();
      // Only the three the device can write. Erase answers an unlink and is
      // not offered here, and an unknown number must not reach NVS.
      if (f == TAG_FMT_ACE || f == TAG_FMT_OPENSPOOL || f == TAG_FMT_FILAMAN)
        g_tagwrite_fmt = (uint8_t)f;
    }
    // Absent from a page still sitting in a browser from before this switch
    // existed. Leaving the setting alone is the honest reading of a body that
    // does not mention it - turning it off would be a decision nobody made.
    if (c2 >= 0) {
      g_tagmismatch_ask = body.substring(c2 + 1).toInt() == 1;
      prefsPutBool("tagmism_ask", g_tagmismatch_ask);
    }
    prefsPutUChar("tagwr_mode", g_tagwrite_mode);
    prefsPutUChar("tagwrite_fmt", g_tagwrite_fmt);
    logSDf("Web: tag write mode=%d mismatch ask=%d format=%s",
           (int)g_tagwrite_mode, (int)g_tagmismatch_ask, tagFormatLabel(g_tagwrite_fmt));
    srv.send(200, "application/json", "{\"ok\":true}");
  });

  // "id,uid": the spool, and the tag the page was showing when it was asked.
  // Parked only; tagLinkTick() makes the request on the loop task and refuses
  // if a different tag lies on the reader by then.
  srv.on("/api/tag/link", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_TAGS))) return;
    if (!srv.hasArg("plain")) { srv.send(400, "application/json", "{\"error\":\"no body\"}"); return; }
    String body = srv.arg("plain");
    const int c = body.indexOf(',');
    const int id = body.substring(0, c < 0 ? body.length() : c).toInt();
    String uid = c < 0 ? String("") : body.substring(c + 1);
    uid.trim();
    const bool ok = tagLinkRequest(id, uid.c_str());
    srv.send(200, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
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
