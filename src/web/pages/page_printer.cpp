// Printer: the label printer, set up from the desk. The same things the
// touchscreen offers under Connection > Bluetooth, on one page: the master
// switch, the devices the last scan saw with the one that is the printer,
// model and label stock, a test print, and the way to drop the printer.
//
// A scan and a print are the scale's business: both start the BLE stack and
// block the loop for seconds, so a route only parks the flag the touchscreen
// sets too, and the page polls for the outcome. The overlay stands on the
// device meanwhile, whichever screen is showing.
//
// The page is always in the tab strip, switch on or off: it is also where a
// visitor learns which printers the scale can drive.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>

#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "services/ble_service.h"
#include "services/label_printer.h"
#include "ui/ble_devices_screen.h"
#include "ui/printer_screen.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

static const char* label() { return T(STR_W_NAV_PRINTER); }

// A device name is whatever the device advertised: quoted for JSON here, and
// only ever set as textContent on the other side.
static String jsonText(const char* s) {
  String out;
  for (; s && *s; s++) {
    const char c = *s;
    if (c == '"' || c == '\\') { out += '\\'; out += c; }
    else if ((unsigned char)c < 0x20) { out += ' '; }
    else out += c;
  }
  return out;
}

static String stateJson() {
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  String j;
  j.reserve(1200);
  j += F("{\"ble\":");
  j += bleEnabled() ? F("true") : F("false");
  j += F(",\"stuck\":");
  j += bleStackStuck() ? F("true") : F("false");
  // False when the controller's memory went back to the heap at boot: the
  // switch is on, but only a restart brings the radio.
  j += F(",\"stack\":");
  j += bleStackAvailable() ? F("true") : F("false");
  j += F(",\"scanning\":");
  j += bleDevicesScanning() ? F("true") : F("false");
  j += F(",\"scanned\":");
  j += bleDevicesScanned() ? F("true") : F("false");
  j += F(",\"devices\":[");
  for (int i = 0; i < bleDevicesCount(); i++) {
    const BleDevice* d = bleDevicesAt(i);
    if (!d) break;
    if (i) j += ',';
    j += F("{\"name\":\"");
    j += jsonText(d->name);
    j += F("\",\"address\":\"");
    j += d->address;
    j += F("\",\"rssi\":");
    j += String((int)d->rssi);
    j += F(",\"printer\":");
    j += labelPrinterIsDevice(d->address) ? F("true") : F("false");
    j += '}';
  }
  j += F("],\"printer\":{\"configured\":");
  j += labelPrinterConfigured(c) ? F("true") : F("false");
  j += F(",\"model\":");
  j += String((int)c.model);
  j += F(",\"name\":\"");
  j += jsonText(c.name);
  j += F("\",\"address\":\"");
  j += c.address;
  j += F("\",\"w\":");
  j += String((unsigned)c.media_width_mm);
  j += F(",\"h\":");
  j += String((unsigned)c.media_length_mm);
  // Where the label runs in the print row, for the strip on the page.
  int16_t lo, hi;
  labelPrinterOffsetRange(c, &lo, &hi);
  j += F("},\"pos\":{\"off\":");
  j += String((int)labelPrinterOffset(c));
  j += F(",\"min\":");
  j += String((int)lo);
  j += F(",\"max\":");
  j += String((int)hi);
  j += F(",\"row\":");
  j += String((unsigned)labelPrinterRasterWidth(c.model, c.media_width_mm));
  j += F(",\"cx\":");
  j += String((unsigned)labelPrinterContentX(c));
  j += F(",\"cw\":");
  j += String((unsigned)labelPrinterContentWidth(c.model, c.media_width_mm));
  j += F(",\"dpi\":");
  j += String((unsigned)labelPrinterProfile(c.model).dpi);
  j += F("},\"lastTest\":");
  const int last = printerLastTestResult();
  if (last < 0) j += F("null");
  else { j += '"'; j += jsonText(T(last)); j += '"'; }
  j += '}';
  return j;
}

// Which printers the scale can drive: a row per brand, a pill per model,
// green where someone has printed on one. Built from the profiles, so the
// card and the model list never disagree. It was a row per model, which
// repeated "experimental, untested" five times and outgrew the Bluetooth
// card next to it with every model added.
static void supportedCard(String& h) {
  h += F("<style>"
         ".pr-m{display:flex;flex-wrap:wrap;gap:6px;justify-content:flex-end}"
         ".pill.ex{color:var(--ink-soft);border-color:var(--line);background:var(--surface-2)}"
         ".pr-leg{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0 8px}"
         "</style><div class='card'><h2>");
  h += T(STR_W_P_SUPPORTED);
  h += F("</h2>");
  for (int i = 0; i < LABEL_PRINTER_MODEL_COUNT; i++) {
    const char* brand = labelPrinterProfile(LABEL_PRINTER_MODELS[i]).brand;
    bool seen = false;
    for (int j = 0; j < i && !seen; j++)
      seen = strcmp(labelPrinterProfile(LABEL_PRINTER_MODELS[j]).brand, brand) == 0;
    if (seen) continue;
    h += F("<div class='row'><span class='k'>");
    h += brand;
    h += F("</span><span class='v pr-m'>");
    for (int j = i; j < LABEL_PRINTER_MODEL_COUNT; j++) {
      const LabelPrinterProfile& p = labelPrinterProfile(LABEL_PRINTER_MODELS[j]);
      if (strcmp(p.brand, brand) != 0) continue;
      h += p.experimental ? F("<span class='pill ex'>") : F("<span class='pill ok'>");
      h += p.name;
      h += F("</span>");
    }
    h += F("</span></div>");
  }
  h += F("<div class='pr-leg'><span class='pill ok'>");
  h += T(STR_W_P_TESTED);
  h += F("</span><span class='pill ex'>");
  h += T(STR_W_P_EXPERIMENTAL);
  h += F("</span></div><span class='hint'>");
  h += T(STR_W_P_SUPPORTED_HINT);
  // The models that print through a ribbon, named once in the hint. In
  // brackets rather than after a colon, which French spaces differently.
  bool ribbon = false;
  for (int i = 0; i < LABEL_PRINTER_MODEL_COUNT; i++) {
    const LabelPrinterProfile& p = labelPrinterProfile(LABEL_PRINTER_MODELS[i]);
    if (p.direct_thermal) continue;
    h += ribbon ? F(", ") : F(" ");
    if (!ribbon) { h += T(STR_PRN_RIBBON_SHORT); h += F(" ("); }
    h += p.brand; h += ' '; h += p.name;
    ribbon = true;
  }
  if (ribbon) h += F(").");
  h += ' ';
  h += T(STR_PRN_HEAT_SHORT);
  h += F("</span></div>");
}

static String body() {
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  String h;
  h.reserve(9000);

  // ---- the master switch ---------------------------------------------------
  h += F("<div class='grid'><div class='card'><h2>");
  h += T(STR_BT_TITLE);
  h += F("</h2><div class='field'>"
         "<label class='check'><span class='switch'>"
         "<input id='bl' type='checkbox'");
  if (bleEnabled()) h += F(" checked");
  h += F("><i></i></span>");
  h += T(STR_BT_SWITCH);
  h += F("</label><span class='hint'>");
  h += T(STR_W_P_BLE_HINT);
  h += F("</span><span class='msg' id='bl-s'></span>"
         // Shown while the switch is on and the stack cannot start: the
         // touchscreen asks for the restart in a popup, the page asks here.
         "<div id='br' style='display:none'><span class='msg bad'>");
  h += T(STR_W_P_RESTART_HINT);
  h += F("</span><div class='inrow'><button id='rb' class='quiet'>");
  h += T(STR_W_RESTART);
  h += F("</button><span class='msg' id='rb-s'></span></div></div></div></div>");

  supportedCard(h);

  // ---- the printer ---------------------------------------------------------
  h += F("<div class='card wide'><h2>");
  h += T(STR_PRN_TITLE);
  h += F("</h2><div class='field'><label>");
  h += T(STR_PRN_DEVICE);
  h += F("</label><div class='inrow'><span id='pd' class='v'></span>"
         "<button id='fb' class='quiet'>");
  h += T(STR_PRN_FORGET);
  h += F("</button></div><span class='msg' id='pd-s'></span></div>");

  // The devices the last scan saw. Rows are built by the script from JSON,
  // so a device name never lands inside markup.
  h += F("<div class='field'><label>");
  h += T(STR_W_P_DEVICES);
  h += F("</label><div id='dv'></div><div class='inrow'><button id='sc' class='quiet'>");
  h += T(STR_BT_SCAN_WEB);
  h += F("</button><span class='hint' style='flex:1'>");
  h += T(STR_W_P_SCAN_HINT);
  h += F("</span></div><span class='msg' id='dv-s'></span></div>");

  h += F("<div class='field'><label>");
  h += T(STR_PRN_MODEL);
  h += F("</label><select id='pm'>");
  {
    for (int i = 0; i < LABEL_PRINTER_MODEL_COUNT; i++) {
      const LabelPrinterModel m = LABEL_PRINTER_MODELS[i];
      const LabelPrinterProfile& p = labelPrinterProfile(m);
      h += F("<option value='");
      h += String((int)m);
      h += F("'");
      if (c.model == m) h += F(" selected");
      h += F(">");
      h += p.brand; h += ' '; h += p.name;
      if (p.experimental) { h += ' '; h += T(STR_PRN_EXPERIMENTAL); }
      h += F("</option>");
    }
  }
  h += F("</select><span class='msg' id='pm-s'></span></div>");

  h += F("<div class='field'><label>");
  h += T(STR_PRN_MEDIA);
  h += F("</label><select id='ps'>");
  {
    bool listed = false;
    for (int i = 0; i < LABEL_MEDIA_SIZE_COUNT; i++) {
      const LabelMediaSize& s = LABEL_MEDIA_SIZES[i];
      const bool cur = s.width_mm == c.media_width_mm && s.length_mm == c.media_length_mm;
      listed = listed || cur;
      h += F("<option value='");
      h += String(s.width_mm); h += 'x'; h += String(s.length_mm);
      h += F("'");
      if (cur) h += F(" selected");
      h += F(">");
      h += String(s.width_mm); h += F(" x "); h += String(s.length_mm); h += F(" mm</option>");
    }
    if (!listed) {
      // A size set elsewhere and not in the table: shown so it is not
      // silently replaced, inert so it cannot be picked again.
      h += F("<option value='' selected disabled>");
      h += String(c.media_width_mm); h += F(" x "); h += String(c.media_length_mm); h += F(" mm</option>");
    }
  }
  h += F("</select><span class='hint'>");
  h += T(STR_W_P_MEDIA_HINT);
  h += F("</span><span class='msg' id='ps-s'></span></div>");

  h += F("<div class='field'><div class='inrow'><button id='tb'>");
  h += T(STR_PRN_TEST);
  h += F("</button><span class='hint' style='flex:1'>");
  h += T(STR_W_P_TEST_HINT);
  h += F("</span></div><span class='msg' id='tb-s'></span>"
         "<div class='row' id='ltr'><span class='k'>");
  h += T(STR_W_P_LAST_TEST);
  h += F("</span><span class='v' id='lt'></span></div></div></div>");

  // ---- where the label runs under the head ---------------------------------
  // The strip is the print row, the block on it the label: it moves with
  // every change, so the setting reads without words.
  h += F("<style>"
         ".pp-track{position:relative;height:38px;margin-top:4px;border-radius:9px;"
         "background:var(--surface-2);border:1px solid var(--line)}"
         ".pp-mid{position:absolute;left:50%;top:6px;bottom:6px;"
         "border-left:1px dashed var(--ink-4)}"
         ".pp-lab{position:absolute;top:4px;bottom:4px;border-radius:6px;"
         "background:var(--accent-dim);border:1px solid var(--accent-line);"
         "color:var(--accent);font-family:var(--mono);font-size:12px;"
         "display:flex;align-items:center;justify-content:center;"
         "transition:left .2s,width .2s}"
         ".pp-scale{display:flex;justify-content:space-between;margin-top:6px;"
         "font-family:var(--mono);font-size:11px;color:var(--ink-soft)}"
         ".pp-set{display:grid;grid-template-columns:1fr 1fr;gap:16px 24px;margin-top:18px}"
         ".pp-set .field{margin-top:0}"
         ".pp-step{min-width:40px;padding-left:0;padding-right:0;justify-content:center}"
         "#cb-s:empty{display:none}"
         // The example: a calibration label in miniature, 6 px to the mm,
         // its left edge on 8, and that number going into the field.
         ".pp-ex{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-top:14px}"
         ".pp-paper{position:relative;flex:0 0 124px;height:72px;border-radius:7px;"
         "background:var(--ink-2);overflow:hidden}"
         ".pp-flags{position:absolute;left:0;right:0;top:6px;height:16px;"
         "border-bottom:1px solid var(--ground);background:repeating-linear-gradient("
         "90deg,var(--ground) 0 1px,transparent 1px 24px)}"
         ".pp-ticks{position:absolute;left:0;right:0;top:18px;height:4px;"
         "background:repeating-linear-gradient(90deg,var(--ground) 0 1px,transparent 1px 6px)}"
         ".pp-n{position:absolute;top:5px;font:700 10px/12px var(--mono);color:var(--ground);"
         "padding:0 2px;background:var(--ink-2)}"
         ".pp-n.hit{background:var(--accent);border-radius:3px}"
         ".pp-fr{position:absolute;left:5px;right:5px;top:30px;bottom:5px;"
         "border:1.5px solid var(--ground)}"
         ".pp-go{display:flex;align-items:center;gap:8px;color:var(--accent);"
         "font:600 22px var(--mono)}"
         ".pp-go b{font-size:15px}"
         ".pp-go b{font-weight:600;padding:6px 12px;border-radius:9px;"
         "background:var(--ground);border:1px solid var(--line);color:var(--ink)}"
         ".pp-txt{flex:1 1 260px;display:flex;flex-direction:column;gap:6px}"
         ".pp-txt span:first-child{font-size:13px;color:var(--ink-2);line-height:1.5}"
         "@media(max-width:620px){.pp-set{grid-template-columns:1fr}}"
         "</style>");
  // Only with a printer, like the row on the scale: the offset is kept per
  // device, and without one there is nothing to keep it for. paint() follows
  // a printer picked or forgotten on this page.
  h += F("<div class='card wide' id='pc'");
  if (!labelPrinterConfigured(c)) h += F(" style='display:none'");
  h += F("><h2>");
  h += T(STR_W_P_CAL_TITLE);
  h += F("</h2><div class='pp-track'><div class='pp-mid'></div>"
         "<div class='pp-lab' id='pl'></div></div>"
         "<div class='pp-scale'><span>0</span><span id='pr'></span></div>"
         "<div class='hint' id='pf' style='display:none;margin-top:8px'>");
  h += T(STR_W_P_CAL_FILLS);
  h += F("</div><div class='pp-set'><div class='field'><label>");
  h += T(STR_W_P_CAL_ROLL);
  h += F("</label><div class='btabs' id='pa'><button class='btab' data-a='left'>");
  h += T(STR_W_P_CAL_LEFT);
  h += F("</button><button class='btab' data-a='0'>");
  h += T(STR_W_P_CAL_CENTER);
  h += F("</button><button class='btab' data-a='right'>");
  h += T(STR_W_P_CAL_RIGHT);
  h += F("</button></div></div><div class='field'><label for='xo'>");
  h += T(STR_W_P_CAL_OFFSET);
  h += F("</label><div class='inrow'>"
         "<button class='quiet pp-step' id='xm' aria-label='-1 mm'>&minus;</button>"
         "<input id='xo' type='number' step='1'>"
         "<button class='quiet pp-step' id='xp' aria-label='+1 mm'>+</button>"
         "<span class='suffix'>mm</span></div>"
         "<span class='msg' id='xo-s'></span></div></div>"
         "<div class='field'><div class='inrow'><button id='cb'>");
  h += T(STR_W_P_CAL_PRINT);
  h += F("</button></div><span class='msg' id='cb-s'></span>"
         "<div class='pp-ex'><div class='pp-paper' aria-hidden='true'>"
         "<div class='pp-flags'></div><div class='pp-ticks'></div>"
         "<span class='pp-n hit' style='left:2px'>8</span>"
         "<span class='pp-n' style='left:26px'>12</span>"
         "<span class='pp-n' style='left:50px'>16</span>"
         "<span class='pp-n' style='left:74px'>20</span>"
         "<span class='pp-n' style='left:98px'>24</span>"
         "<div class='pp-fr'></div></div>"
         "<div class='pp-go' aria-hidden='true'>&rarr;<b>8</b></div>"
         "<div class='pp-txt'><span>");
  h += T(STR_W_P_CAL_HINT);
  h += F("</span><span class='hint'>");
  h += T(STR_W_P_CAL_HINT2);
  // pp-txt, pp-ex, the field, the card, and the grid the page opened.
  h += F("</span></div></div></div></div></div>");

  // Every handler is bound here rather than written into an onclick
  // attribute: a page body is JavaScript inside a C++ string literal, and an
  // attribute is the one place where the two levels of quoting collide.
  // $, flash, post, postFlash and getJson come from /app.js.
  h += F("<script>");
  h += webShellJsStrings();
  h += F("const P={none:");
  h += jsStr(T(STR_PRN_NONE));
  h += F(",unnamed:");
  h += jsStr(T(STR_BT_UNNAMED));
  h += F(",asPrinter:");
  h += jsStr(T(STR_BT_CARD_USE_PRINTER));
  h += F(",printer:");
  h += jsStr(T(STR_PRN_TITLE));
  h += F(",scanning:");
  h += jsStr(T(STR_BT_SCANNING));
  h += F(",notYet:");
  h += jsStr(T(STR_BT_DEVICES_NONE_YET));
  h += F(",noneFound:");
  h += jsStr(T(STR_BT_NONE_FOUND));
  h += F(",off:");
  h += jsStr(T(STR_PRN_ERR_BLE_OFF));
  h += F(",stuck:");
  h += jsStr(T(STR_PRN_ERR_STUCK));
  h += F(",restarting:");
  h += jsStr(T(STR_W_RESTARTING));
  h += F("};"
         "let timer=0;"
         // Dots to the millimetre of the model in use and the offset's range,
         // from the state.
         "let K=8,R={min:0,max:0};"
         // The device rows, from the JSON: createElement and textContent,
         // never markup, because a name is whatever the device advertised.
         "function rows(d){"
         "const box=$('dv');box.textContent='';"
         "if(!d.ble){box.textContent=P.off;return;}"
         "if(d.stuck){box.textContent=P.stuck;return;}"
         "if(d.scanning){box.textContent=P.scanning;return;}"
         "if(!d.scanned){box.textContent=P.notYet;return;}"
         "if(!d.devices.length){box.textContent=P.noneFound;return;}"
         "d.devices.forEach(function(x){"
         "const r=document.createElement('div');r.className='row';"
         "const k=document.createElement('span');k.className='k';"
         "k.textContent=(x.name||P.unnamed)+'  '+x.address+'  '+x.rssi+' dBm';"
         "r.appendChild(k);"
         "const v=document.createElement('span');v.className='v';"
         "if(x.printer){const p=document.createElement('span');p.className='pill ok';"
         "p.textContent=P.printer;v.appendChild(p);}"
         "else{const b=document.createElement('button');b.className='quiet';"
         "b.textContent=P.asPrinter;"
         "b.addEventListener('click',function(){"
         "postFlash('/api/printer/device',x.address,'dv-s',4000).then(load);});"
         "v.appendChild(b);}"
         "r.appendChild(v);box.appendChild(r);});}"
         "function paint(d){"
         "$('bl').checked=d.ble;"
         "$('pd').textContent=d.printer.configured?((d.printer.name||P.unnamed)+'  '+d.printer.address):P.none;"
         "$('fb').style.display=d.printer.configured?'':'none';"
         "$('pc').style.display=d.printer.configured?'':'none';"
         "$('pm').value=String(d.printer.model);"
         "$('ps').value=d.printer.w+'x'+d.printer.h;"
         "$('lt').textContent=d.lastTest||'';"
         "$('ltr').style.display=d.lastTest?'':'none';"
         "$('br').style.display=(d.ble&&!d.stack)?'':'none';"
         "$('sc').disabled=!d.ble||!d.stack||d.stuck||d.scanning;"
         "$('tb').disabled=!d.ble||!d.stack||d.stuck||!d.printer.configured;"
         "$('cb').disabled=$('tb').disabled;"
         "pos(d);"
         "rows(d);"
         // While the scale scans, ask again in two seconds; the scan itself
         // takes five.
         "clearTimeout(timer);if(d.scanning)timer=setTimeout(load,2000);}"
         // The strip in percent of the row; the buttons light up for the
         // edge or the middle the offset stands at.
         // A tenth of a millimetre only where it is one: 203 dpi is not quite
         // 8 dots to the millimetre, and the M220's 72 mm head came out 72.1.
         "function mm(v){const m=v/K,r=Math.round(m);"
         "return String(Math.abs(m-r)<0.1?r:Math.round(m*10)/10);}"
         "function pos(d){const p=d.pos,row=p.row||1,l=$('pl');K=(p.dpi||203)/25.4;R=p;"
         "l.style.left=(p.cx*100/row)+'%';l.style.width=(p.cw*100/row)+'%';"
         "l.textContent=d.printer.w+' mm';$('pr').textContent=mm(p.row)+' mm';"
         // The offset is kept in dots and shown in millimetres, the unit
         // the calibration page's ruler counts in.
         "const x=$('xo');x.min=Math.ceil(p.min/K);x.max=Math.floor(p.max/K);"
         "if(document.activeElement!==x)x.value=Math.round(p.off/K);"
         "const fixed=p.min===p.max;$('pf').style.display=fixed?'':'none';"
         "document.querySelectorAll('#pa .btab').forEach(function(b){"
         "const a=b.dataset.a;"
         "b.classList.toggle('on',!fixed&&(a==='left'?p.off===p.min:a==='right'?p.off===p.max:p.off===0));"
         "b.disabled=fixed;});"
         "x.disabled=fixed;$('xm').disabled=fixed||p.off<=p.min;$('xp').disabled=fixed||p.off>=p.max;}"
         // Millimetres to dots, onto the edge or the middle when it is under
         // half a millimetre away: 4 mm on the M2 are 47 dots, its edge 48,
         // and the edge's button would light up only a click later.
         "function dots(m){const v=Math.round(m*K);"
         "for(const s of [R.min,R.max,0])if(Math.abs(v-s)<K/2)return s;return v;}"
         "function setOff(v){postFlash('/api/printer/offset',String(v),'xo-s',3000).then(load);}"
         "function load(){getJson('/api/printer').then(function(d){if(d)paint(d);});}"
         // The box already shows what was asked for, so a failure has to put
         // it back. Same shape as every switch on the settings page.
         "$('bl').addEventListener('change',function(){"
         "const want=$('bl').checked;"
         "post('/api/ble',want?'1':'0').then(function(r){"
         "if(!r.ok)$('bl').checked=!want;"
         "flash('bl-s',r.ok?WS.ok:WS.err,!r.ok,4000);load();});});"
         "$('sc').addEventListener('click',function(){"
         "postFlash('/api/printer/scan','','dv-s',4000).then(function(){setTimeout(load,500);});});"
         "$('pm').addEventListener('change',function(){"
         "postFlash('/api/printer/model',$('pm').value,'pm-s',4000).then(load);});"
         "$('ps').addEventListener('change',function(){"
         "postFlash('/api/printer/media',$('ps').value,'ps-s',4000).then(load);});"
         // The print takes about ten seconds on the scale; the verdict is
         // fetched after that and shown on the last line.
         "$('tb').addEventListener('click',function(){"
         "postFlash('/api/printer/test','','tb-s',4000).then(function(){setTimeout(load,12000);});});"
         "document.querySelectorAll('#pa .btab').forEach(function(b){"
         "b.addEventListener('click',function(){setOff(b.dataset.a);});});"
         "$('xm').addEventListener('click',function(){setOff(dots((+$('xo').value||0)-1));});"
         "$('xp').addEventListener('click',function(){setOff(dots((+$('xo').value||0)+1));});"
         "$('xo').addEventListener('change',function(){setOff(dots(+$('xo').value||0));});"
         "$('cb').addEventListener('click',function(){"
         "postFlash('/api/printer/calib','','cb-s',4000).then(function(){setTimeout(load,12000);});});"
         "$('fb').addEventListener('click',function(){"
         "postFlash('/api/printer/forget','','pd-s',4000).then(load);});"
         // The restart route sits behind the maintenance gate; a shut one
         // answers 403 as text, which is shown as it is.
         "$('rb').addEventListener('click',function(){"
         "post('/api/restart','').then(function(r){"
         "if(!r.ok){flash('rb-s',r.text||WS.err,true,5000);return;}"
         "flash('rb-s',P.restarting,false);"
         "setTimeout(function(){location.reload();},9000);});});"
         "load();"
         "</script>");
  return h;
}

static void routes(WebServer &srv) {
  srv.on("/api/printer", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_PRINTER))) return;
    srv.send(200, "application/json", stateJson());
  });

  // State, not a toggle: the browser sends what it wants to be, like every
  // other switch. The header chip and an open Bluetooth screen follow through
  // the same flag the touchscreen switch raises.
  srv.on("/api/ble", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_PRINTER))) return;
    const bool on = (srv.arg("plain").toInt() != 0);
    bleSetEnabled(on);
    if (!on) bleDevicesForget();
    bluetooth_rebuild_pending = true;
    logSDf("Web: Bluetooth -> %s", on ? "ON" : "OFF");
    srv.send(200, "application/json", on ? "{\"ok\":true,\"v\":1}"
                                         : "{\"ok\":true,\"v\":0}");
  });

  // Parks the scan; the loop runs it under the overlay, the page polls.
  srv.on("/api/printer/scan", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_PRINTER))) return;
    if (!bleEnabled()) { srv.send(409, "text/plain", T(STR_PRN_ERR_BLE_OFF)); return; }
    if (bleStackStuck()) { srv.send(409, "text/plain", T(STR_PRN_ERR_STUCK)); return; }
    ble_scan_pending = true;
    logSD("Web: BLE scan requested");
    srv.send(200, "text/plain", T(STR_W_P_QUEUED));
  });

  // The address of a device the last scan saw becomes the printer. Only
  // those: an address typed by hand has no name and was never seen.
  srv.on("/api/printer/device", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_PRINTER))) return;
    const String want = srv.arg("plain");
    for (int i = 0; i < bleDevicesCount(); i++) {
      const BleDevice* d = bleDevicesAt(i);
      if (!d || want != d->address) continue;
      LabelPrinterConfig c = labelPrinterLoadConfig();
      snprintf(c.name, sizeof(c.name), "%s", d->name);
      snprintf(c.address, sizeof(c.address), "%s", d->address);
      const bool ok = labelPrinterSaveConfig(c);
      logSDf("Web: printer is %s", d->address);
      srv.send(ok ? 200 : 500, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
      return;
    }
    srv.send(404, "text/plain", T(STR_BT_NONE_FOUND));
  });

  srv.on("/api/printer/model", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_PRINTER))) return;
    const int m = srv.arg("plain").toInt();
    if (m < 1 || m > 255 || labelPrinterProfile((LabelPrinterModel)m).model == LP_MODEL_NONE) {
      srv.send(400, "text/plain", "unknown model");
      return;
    }
    LabelPrinterConfig c = labelPrinterLoadConfig();
    c.model = (LabelPrinterModel)m;
    const bool ok = labelPrinterSaveConfig(c);
    logSDf("Web: printer model -> %s", labelPrinterProfile(c.model).name);
    srv.send(ok ? 200 : 500, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
  });

  // "WxH" in millimetres, checked against what the model takes.
  srv.on("/api/printer/media", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_PRINTER))) return;
    const String v = srv.arg("plain");
    const int x = v.indexOf('x');
    const long w = x > 0 ? strtol(v.c_str(), nullptr, 10) : 0;
    const long l = x > 0 ? strtol(v.c_str() + x + 1, nullptr, 10) : 0;
    LabelPrinterConfig c = labelPrinterLoadConfig();
    const LabelPrinterProfile& p = labelPrinterProfile(c.model);
    if (w < p.min_width_mm || w > p.max_width_mm || l < p.min_length_mm || l > p.max_length_mm) {
      srv.send(400, "text/plain", T(STR_PRN_ERR_MEDIA));
      return;
    }
    c.media_width_mm = (uint16_t)w;
    c.media_length_mm = (uint16_t)l;
    const bool ok = labelPrinterSaveConfig(c);
    logSDf("Web: label stock -> %ldx%ld mm", w, l);
    srv.send(ok ? 200 : 500, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
  });

  // Parks the test print; the loop renders and prints it under the overlay
  // and shows the verdict on the device. The page fetches it afterwards.
  srv.on("/api/printer/test", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_PRINTER))) return;
    if (!labelPrinterConfigured(labelPrinterLoadConfig())) { srv.send(409, "text/plain", T(STR_PRN_ERR_NO_PRINTER)); return; }
    if (!bleEnabled()) { srv.send(409, "text/plain", T(STR_PRN_ERR_BLE_OFF)); return; }
    if (bleStackStuck()) { srv.send(409, "text/plain", T(STR_PRN_ERR_STUCK)); return; }
    printer_test_pending = true;
    logSD("Web: test print requested");
    srv.send(200, "text/plain", T(STR_W_P_QUEUED));
  });

  // A number of dots, or "left" and "right" for a roll against a wall: those
  // are stored beyond the head and clamped when used, so they hold for every
  // label width.
  srv.on("/api/printer/offset", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_PRINTER))) return;
    const String v = srv.arg("plain");
    LabelPrinterConfig c = labelPrinterLoadConfig();
    // Not stored without a printer (its address is the key), so not "ok".
    if (!labelPrinterConfigured(c)) { srv.send(409, "text/plain", T(STR_PRN_ERR_NO_PRINTER)); return; }
    if (v == "left")       c.x_offset = LP_OFFSET_LEFT;
    else if (v == "right") c.x_offset = LP_OFFSET_RIGHT;
    else {
      // Clamped here too, so the stored number is the one the page shows.
      int16_t lo, hi;
      labelPrinterOffsetRange(c, &lo, &hi);
      const long n = strtol(v.c_str(), nullptr, 10);
      c.x_offset = (int16_t)(n < lo ? lo : n > hi ? hi : n);
    }
    const bool ok = labelPrinterSaveConfig(c);
    logSDf("Web: label offset -> %s (%d dots)", v.c_str(), (int)labelPrinterOffset(c));
    srv.send(ok ? 200 : 500, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
  });

  // Parks the calibration page, the same way as the test print.
  srv.on("/api/printer/calib", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_PRINTER))) return;
    if (!labelPrinterConfigured(labelPrinterLoadConfig())) { srv.send(409, "text/plain", T(STR_PRN_ERR_NO_PRINTER)); return; }
    if (!bleEnabled()) { srv.send(409, "text/plain", T(STR_PRN_ERR_BLE_OFF)); return; }
    if (bleStackStuck()) { srv.send(409, "text/plain", T(STR_PRN_ERR_STUCK)); return; }
    printer_calib_pending = true;
    logSD("Web: calibration page requested");
    srv.send(200, "text/plain", T(STR_W_P_QUEUED));
  });

  srv.on("/api/printer/forget", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_PRINTER))) return;
    const bool ok = labelPrinterForget();
    logSD("Web: printer forgotten");
    srv.send(ok ? 200 : 500, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
  });
}

extern const WebPage PAGE_PRINTER;
const WebPage PAGE_PRINTER = {
  "/printer", label, GATE_CONFIG, nullptr,
  body, routes
};
