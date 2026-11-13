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

#include "app_config.h"
#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "services/ble_service.h"
#include "services/label_printer.h"
#include "ui/ble_devices_screen.h"
#include "ui/printer_screen.h"
#include "web/web_access.h"
#include "web/web_printer_cards.h"
#include "web/web_printer_select.h"
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

// The line under the stock, worded for the printer at hand: none yet,
// another model, or one of ours, the M220 without a ribbon and the M2 with
// one. The script switches them as the printer changes; the numbers are its
// data-v.
enum RecVariant { REC_NONE = 0, REC_OTHER = 1, REC_LABELS = 2, REC_RIBBON = 3 };
struct RecText { int text, button; const char* anchor; };
static const RecText REC_TEXTS[] = {
  { STR_W_P_REC_NONE_TEXT,  STR_W_P_REC_NONE_BTN,   "" },
  { STR_W_P_REC_OTHER_TEXT, STR_W_P_REC_OTHER_BTN,  "" },
  { STR_W_P_REC_M220_TEXT,  STR_W_P_REC_LABELS_BTN, DOCS_ANCHOR_M220 },
  { STR_W_P_REC_M2_TEXT,    STR_W_P_REC_RIBBON_BTN, DOCS_ANCHOR_M2 },
};

// The two pictures of the page, in the stroke of the shared look.
static const char ICON_BLUETOOTH[] PROGMEM =
  "<svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' "
  "stroke-width='2' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>"
  "<path d='M7 7l10 10-5 5V2l5 5L7 17'/></svg>";
static const char ICON_PRINTER[] PROGMEM =
  "<svg width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='currentColor' "
  "stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>"
  "<path d='M6 9V3h12v6'/><rect x='3' y='9' width='18' height='8' rx='2'/>"
  "<path d='M7 14h10v7H7z'/></svg>";

static RecVariant recVariant(const LabelPrinterConfig& c) {
  if (!labelPrinterConfigured(c)) return REC_NONE;
  if (!labelPrinterRecommended(c.model)) return REC_OTHER;
  return labelPrinterProfile(c.model).direct_thermal ? REC_LABELS : REC_RIBBON;
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
  j += F(",\"thermal\":");
  j += labelPrinterProfile(c.model).direct_thermal ? F("true") : F("false");
  j += F(",\"rec\":");
  j += String((int)recVariant(c));
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

// The way to the manual's page of recommended printers and their labels,
// where the shop links live: never in the firmware (Nikolai, 21.10.2026).
static void recommendRow(String& h) {
  const RecVariant shown = recVariant(labelPrinterLoadConfig());
  for (int v = 0; v < (int)(sizeof(REC_TEXTS) / sizeof(REC_TEXTS[0])); v++) {
    const RecText& r = REC_TEXTS[v];
    h += F("<div class='reclink pr-rec' data-v='");
    h += String(v);
    h += v == shown ? F("'>") : F("' style='display:none'>");
    h += F("<span>");
    h += T(r.text);
    h += F("</span><a href='");
    h += webPrinterDocsUrl();
    h += r.anchor;
    h += F("' target='_blank' rel='noopener'>");
    h += T(r.button);
    h += F(" &rarr;</a></div>");
  }
}

// Under the models: more to come, the one limit no driver can lift, and the
// wish list for a printer or size that is missing. The
// scale's ESP32-S3 has no Classic Bluetooth radio, so a printer that only
// speaks Classic (every Brother P-touch) can never be among the cards.
static void supportedHint(String& h) {
  h += F("<span class='hint pr-foot'>");
  h += T(STR_W_P_SUPPORTED_HINT);
  h += ' ';
  h += T(STR_W_P_BLE_ONLY);
  h += F(" <a href='");
  h += webPrinterDocsUrl();
  h += F("#printer-needs' target='_blank' rel='noopener'>");
  h += T(STR_W_P_NEEDS_LINK);
  h += F(" &rarr;</a> &middot; ");
  webPrinterWishLink(h);
  h += F("</span>");
}

// The master switch as a bar across the page. While the switch is on and the
// stack cannot start, the bar turns to a warning and offers the restart: the
// touchscreen asks for it in a popup, the page asks here.
static void bluetoothBar(String& h) {
  const bool on = bleEnabled();
  const bool need = on && !bleStackAvailable();
  h += F("<div class='btbar");
  if (on) h += F(" live");
  if (need) h += F(" need");
  h += F("' id='bb'><div class='ic'>");
  h += FPSTR(ICON_BLUETOOTH);
  h += F("</div><div class='tx'><strong>");
  h += T(STR_BT_TITLE);
  h += F("</strong><span id='bbt'");
  if (need) h += F(" style='display:none'");
  h += '>';
  h += T(STR_W_P_BLE_HINT);
  h += F("</span><span id='bbr'");
  if (!need) h += F(" style='display:none'");
  h += '>';
  h += T(STR_W_P_RESTART_HINT);
  h += F("</span><span class='msg' id='bl-s'></span><span class='msg' id='rb-s'></span></div>"
         "<div class='end'><span class='pill wr' id='bbp'");
  if (!need) h += F(" style='display:none'");
  h += '>';
  h += T(STR_W_P_RESTART_NEEDED);
  h += F("</span><button id='rb' class='quiet'");
  if (!need) h += F(" style='display:none'");
  h += '>';
  h += T(STR_W_RESTART);
  h += F("</button><label class='switch'><input id='bl' type='checkbox' aria-label=\"");
  h += T(STR_BT_SWITCH);
  h += '"';
  if (on) h += F(" checked");
  h += F("><i></i></label></div></div>");
}

// The printer as a tile, its name and address filled in by the script (a
// name is whatever the device advertised, so it never lands in markup), and
// under it the panel the scan fills.
static void deviceTile(String& h, const LabelPrinterConfig& c) {
  const bool have = labelPrinterConfigured(c);
  h += F("<div class='dev");
  if (!have) h += F(" empty");
  h += F("' id='dt'><div class='ic'>");
  h += FPSTR(ICON_PRINTER);
  h += F("</div><div class='tx'><span class='nm' id='pd'></span><span class='sub' id='pds'></span>"
         "</div><div class='end'><button id='sc'");
  if (have) h += F(" class='quiet'");
  h += '>';
  h += T(have ? STR_W_P_CHANGE : STR_BT_SCAN_WEB);
  h += F("</button><button id='fb' class='ghost'");
  if (!have) h += F(" style='display:none'");
  h += '>';
  h += T(STR_PRN_FORGET);
  h += F("</button></div></div><span class='msg' id='pd-s'></span>"
         "<div class='scan' id='sp' style='display:none'><div class='scan-h' id='sph'></div>"
         "<div class='scan-bar' id='spb'></div><div id='dv'></div></div>"
         "<span class='msg' id='dv-s'></span>");
}

// The model picker, what the model prints with, the limits of the list,
// the label stock as cards, and the way to rolls that fit.
static void pickers(String& h, const LabelPrinterConfig& c) {
  const bool thermal = labelPrinterProfile(c.model).direct_thermal;
  h += F("<div class='sect'><h3>");
  h += T(STR_PRN_MODEL);
  h += F("</h3></div>");
  webPrinterModelPicker(h, c);
  h += F("<span class='msg' id='pm-s'></span><div class='method");
  // Heat-sensitive paper says what a dryer does to it; the script follows
  // the model picked.
  if (thermal) h += F(" warm");
  h += F("' id='pmx'><span id='pmd'");
  if (!thermal) h += F(" style='display:none'");
  h += '>';
  h += T(STR_W_P_METHOD_DIRECT);
  h += ' ';
  h += T(STR_PRN_HEAT_SHORT);
  h += F("</span><span id='pmr'");
  if (thermal) h += F(" style='display:none'");
  h += '>';
  h += T(STR_W_P_METHOD_RIBBON);
  h += F("</span></div>");
  supportedHint(h);
  h += F("<div class='sect'><h3>");
  h += T(STR_PRN_MEDIA);
  h += F("</h3><span class='hint'>");
  h += T(STR_W_P_MEDIA_HINT);
  h += F("</span></div><div class='pick stock' id='ps'>");
  webPrinterStockCards(h, c);
  h += F("</div><span class='msg' id='ps-s'></span>");
  recommendRow(h);
}

static void testRow(String& h) {
  h += F("<div class='testrow'><button id='tb'>");
  h += T(STR_PRN_TEST);
  h += F("</button><span class='hint'>");
  h += T(STR_W_P_TEST_HINT);
  h += F("</span></div><span class='msg' id='tb-s'></span>"
         "<div class='row' id='ltr'><span class='k'>");
  h += T(STR_W_P_LAST_TEST);
  h += F("</span><span class='v' id='lt'></span></div>");
}

// ---- where the label runs under the head ---------------------------------
// The strip is the print row, the block on it the label: it moves with every
// change, so the setting reads without words. Its look sits with the rest of
// the page's in web_printer_cards.cpp.
static void calibrationCard(String& h, const LabelPrinterConfig& c) {
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
  // pp-txt, pp-ex, the field and the card.
  h += F("</span></div></div></div></div>");
}

// The texts the script writes, in the page's language.
static void scriptStrings(String& h) {
  h += webShellJsStrings();
  h += F("const P={none:");
  h += jsStr(T(STR_PRN_NONE));
  h += F(",unnamed:");
  h += jsStr(T(STR_BT_UNNAMED));
  h += F(",showAll:");
  h += jsStr(T(STR_BT_SHOW_ALL_FMT));
  h += F(",named:");
  h += jsStr(T(STR_BT_SHOW_NAMED));
  h += F(",asPrinter:");
  h += jsStr(T(STR_BT_CARD_USE_PRINTER));
  h += F(",printer:");
  h += jsStr(T(STR_PRN_TITLE));
  h += F(",scanning:");
  h += jsStr(T(STR_BT_SCANNING));
  h += F(",devices:");
  h += jsStr(T(STR_W_P_DEVICES));
  h += F(",noneFound:");
  h += jsStr(T(STR_BT_NONE_FOUND));
  h += F(",off:");
  h += jsStr(T(STR_PRN_ERR_BLE_OFF));
  h += F(",stuck:");
  h += jsStr(T(STR_PRN_ERR_STUCK));
  h += F(",restarting:");
  h += jsStr(T(STR_W_RESTARTING));
  h += F(",scan:");
  h += jsStr(T(STR_BT_SCAN_WEB));
  h += F(",change:");
  h += jsStr(T(STR_W_P_CHANGE));
  h += F(",pick:");
  h += jsStr(T(STR_W_P_PICK_HINT));
  h += F(",changeModel:");
  h += jsStr(T(STR_W_P_CHANGE_MODEL));
  h += F(",done:");
  h += jsStr(T(STR_W_P_MODEL_DONE));
  // Without a printer the tile says what to do and what the scan costs.
  String empty = T(STR_W_P_EMPTY_HINT);
  empty += ' ';
  empty += T(STR_W_P_SCAN_HINT);
  h += F(",empty:");
  h += jsStr(empty.c_str());
  h += F("};");
}

// The bar and the tile from the state.
static void scriptDevice(String& h) {
  h += F("let timer=0,allOpen=false,wasScanning=false;"
         // Four bars on the status page's ladder, green from three up.
         "const SIG_DBM=[");
  h += String(SIGNAL_BARS_4_DBM); h += ',';
  h += String(SIGNAL_BARS_3_DBM); h += ',';
  h += String(SIGNAL_BARS_2_DBM);
  h += F("];"
         "function sig(r){const n=r>=SIG_DBM[0]?4:r>=SIG_DBM[1]?3:r>=SIG_DBM[2]?2:1;"
         "const s=document.createElement('span');s.className='sig';s.title=r+' dBm';"
         "for(let i=1;i<=4;i++){const b=document.createElement('i');"
         "if(i<=n)b.style.background=n>=3?'var(--accent)':'var(--warn)';s.appendChild(b);}"
         "return s;}"
         "function bar(d){const need=d.ble&&!d.stack;"
         "$('bb').className='btbar'+(d.ble?' live':'')+(need?' need':'');"
         "$('bl').checked=d.ble;$('bbt').style.display=need?'none':'';"
         "['bbr','bbp','rb'].forEach(function(i){$(i).style.display=need?'':'none';});}"
         // The model's brand and name come from its card, so the tile and
         // the picker never disagree.
         "function tile(d){const on=d.printer.configured,m=document.querySelector('#pm .pc.on'),s=$('pds');"
         "$('dt').className='dev'+(on?'':' empty');"
         "$('pd').textContent=on?(d.printer.name||P.unnamed):P.none;"
         "if(on){s.textContent=d.printer.address+(m?'  \\u00b7  '+m.dataset.b+' '+m.dataset.n:'');"
         "const seen=d.devices.filter(function(x){return x.printer;})[0];if(seen)s.appendChild(sig(seen.rssi));}"
         "else s.textContent=!d.ble?P.off:d.stuck?P.stuck:(d.scanned&&d.devices.length)?P.pick:P.empty;"
         "$('sc').textContent=on?P.change:P.scan;$('sc').className=on?'quiet':'';"
         "$('fb').style.display=on?'':'none';}");
}

// The scan panel and its rows.
static void scriptRows(String& h) {
  h += F(// The device rows, from the JSON: createElement and textContent,
         // never markup, because a name is whatever the device advertised.
         // Named devices and the printer stand open; the nameless ones (phones,
         // beacons, most of what a scan sees) fold away under one line, as the
         // display's list does (ui/ble_devices_screen.cpp).
         "function rows(d){const p=$('sp'),box=$('dv'),b=$('spb');"
         "const show=d.ble&&(d.stuck||d.scanning||d.scanned);p.style.display=show?'':'none';"
         "if(!show){wasScanning=false;return;}"
         "$('sph').textContent=d.scanning?P.scanning:P.devices;b.style.display=d.scanning?'':'none';"
         // The bar fills once over the scan's five seconds, from its start.
         "if(d.scanning&&!wasScanning){b.textContent='';b.appendChild(document.createElement('i'));}"
         "wasScanning=d.scanning;box.textContent='';"
         "const say=function(t){const e=document.createElement('div');e.className='emp';e.textContent=t;box.appendChild(e);};"
         "if(d.stuck){say(P.stuck);return;}"
         "if(d.scanning)return;"
         "if(!d.devices.length){say(P.noneFound);return;}"
         "const rest=d.devices.filter(function(x){return !x.name&&!x.printer;});"
         "d.devices.filter(function(x){return x.name||x.printer;}).forEach(function(x){box.appendChild(row(x));});"
         "if(!rest.length)return;"
         "const m=document.createElement('details');m.className='more';m.open=allOpen;"
         "const s=document.createElement('summary');"
         "const tell=function(){s.textContent=m.open?P.named:P.showAll.replace('%d',rest.length);};tell();"
         "m.appendChild(s);m.addEventListener('toggle',function(){allOpen=m.open;tell();});"
         "rest.forEach(function(x){m.appendChild(row(x));});box.appendChild(m);}"
         "function row(x){"
         "const r=document.createElement('div');r.className='drow'+(x.printer?' mine':'');"
         "const n=document.createElement('span');n.className='nm';n.textContent=x.name||P.unnamed;"
         "const a=document.createElement('small');a.textContent=x.address;n.appendChild(a);"
         "r.appendChild(n);r.appendChild(sig(x.rssi));"
         "if(x.printer){const p=document.createElement('span');p.className='pill ok';"
         "p.textContent=P.printer;r.appendChild(p);}"
         "else{const b=document.createElement('button');b.className='quiet';"
         "b.textContent=P.asPrinter;"
         "b.addEventListener('click',function(){"
         "postFlash('/api/printer/device',x.address,'dv-s',4000).then(load);});"
         "r.appendChild(b);}"
         "return r;}");
}

// The model picker: with a printer only the row naming its model, the cards
// behind "Change model"; without one the cards alone. The state says which,
// so a scan or "Remove printer" switches it without a reload.
static void scriptPicker(String& h) {
  h += F("let editing=false,has=$('pm').classList.contains('has');"
         // The row copies the marked card's name, tag and spec.
         "function curRow(){const m=document.querySelector('#pm .pc.on'),l=$('pcn');if(!m)return;"
         "$('pcb').textContent=m.dataset.b;$('pcs').textContent=m.querySelector('.sp').textContent;"
         "l.textContent='';l.appendChild(m.querySelector('.mn').cloneNode(true));"
         "const t=m.querySelector('.tg');if(t)l.appendChild(t.cloneNode(true));}"
         "function view(){if(!has)editing=false;"
         "$('pm').classList.toggle('has',has);$('pmc').style.display=has?'':'none';"
         "$('pmp').style.display=!has||editing?'':'none';"
         "const b=$('pmb');b.textContent=editing?P.done:P.changeModel;"
         "b.setAttribute('aria-expanded',editing);curRow();}"
         // A pick closes the picker and hands the focus back to its button.
         "function closePicker(){if(!editing)return;editing=false;view();$('pmb').focus();}");
}

// The cards and the rest of the state onto the page.
static void scriptPaint(String& h) {
  h += F(// Only the sizes the picked model takes; the save puts a size it
         // cannot take back to the model's default, and the next state shows it.
         "function cards(d){const v=d.printer.w+'x'+d.printer.h,m=String(d.printer.model);"
         "document.querySelectorAll('#pm .pc').forEach(function(b){const on=b.dataset.m===m;"
         "b.classList.toggle('on',on);b.setAttribute('aria-pressed',on);});"
         "has=d.printer.configured;view();"
         "document.querySelectorAll('#ps .pc').forEach(function(b){"
         "b.style.display=b.dataset.fit.split(' ').indexOf(m)>=0?'':'none';"
         "b.classList.toggle('on',b.dataset.v===v);});"
         "$('pmx').classList.toggle('warm',d.printer.thermal);"
         "$('pmd').style.display=d.printer.thermal?'':'none';"
         "$('pmr').style.display=d.printer.thermal?'none':'';}"
         "function paint(d){"
         "bar(d);cards(d);tile(d);"
         "$('pc').style.display=d.printer.configured?'':'none';"
         "document.querySelectorAll('.pr-rec').forEach(function(e){"
         "e.style.display=+e.dataset.v===d.printer.rec?'':'none';});"
         "$('lt').textContent=d.lastTest||'';"
         "$('ltr').style.display=d.lastTest?'':'none';"
         "$('sc').disabled=!d.ble||!d.stack||d.stuck||d.scanning;"
         "$('tb').disabled=!d.ble||!d.stack||d.stuck||!d.printer.configured;"
         "$('cb').disabled=$('tb').disabled;"
         "pos(d);"
         "rows(d);"
         // While the scale scans, ask again in two seconds; the scan itself
         // takes five.
         "clearTimeout(timer);if(d.scanning)timer=setTimeout(load,2000);}");
}

// The strip and the offset field.
static void scriptPosition(String& h) {
  h += F(// Dots to the millimetre of the model in use and the offset's range,
         // from the state.
         "let K=8,R={min:0,max:0};"
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
         // Millimetres to dots, onto the middle or the edge when it is under
         // half a millimetre away: 4 mm on the M2 are 47 dots, its edge 48,
         // and the edge's button would light up only a click later. The middle
         // first: with under a millimetre of play, 0 would land on an edge.
         "function dots(m){const v=Math.round(m*K);"
         "for(const s of [0,R.min,R.max])if(Math.abs(v-s)<K/2)return s;return v;}"
         "function setOff(v){postFlash('/api/printer/offset',String(v),'xo-s',3000).then(load);}");
}

// Every handler is bound here rather than written into an onclick
// attribute: a page body is JavaScript inside a C++ string literal, and an
// attribute is the one place where the two levels of quoting collide.
// $, flash, post, postFlash and getJson come from /app.js.
static void scriptHandlers(String& h) {
  h += F("function load(){getJson('/api/printer').then(function(d){if(d)paint(d);});}"
         // The box already shows what was asked for, so a failure has to put
         // it back. Same shape as every switch on the settings page.
         "$('bl').addEventListener('change',function(){"
         "const want=$('bl').checked;"
         "post('/api/ble',want?'1':'0').then(function(r){"
         "if(!r.ok)$('bl').checked=!want;"
         "flash('bl-s',r.ok?WS.ok:WS.err,!r.ok,4000);load();});});"
         "$('sc').addEventListener('click',function(){"
         "postFlash('/api/printer/scan','','dv-s',4000).then(function(){setTimeout(load,500);});});"
         // Opening shows the fold too when the current model is in it.
         "$('pmb').addEventListener('click',function(){editing=!editing;"
         "const m=document.querySelector('#pm .pc.on');"
         "if(editing&&m&&$('pmf').contains(m))$('pmf').open=true;view();});"
         // A card posts what it stands for; the one already picked only
         // closes the picker.
         "document.querySelectorAll('#pm .pc').forEach(function(b){"
         "b.addEventListener('click',function(){closePicker();if(b.classList.contains('on'))return;"
         "postFlash('/api/printer/model',b.dataset.m,'pm-s',4000).then(load);});});"
         "document.querySelectorAll('#ps .pc').forEach(function(b){"
         "b.addEventListener('click',function(){if(b.classList.contains('on'))return;"
         "postFlash('/api/printer/media',b.dataset.v,'ps-s',4000).then(load);});});"
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
         "curRow();load();");
}

static void pageScript(String& h) {
  h += F("<script>");
  scriptStrings(h);
  scriptDevice(h);
  scriptRows(h);
  scriptPosition(h);
  scriptPicker(h);
  scriptPaint(h);
  scriptHandlers(h);
  h += F("</script>");
}

static String body() {
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  String h;
  // Measured 23.8 KB in English (v0.8.3-beta.85); French runs longer.
  h.reserve(26000);
  webPrinterPageStyle(h);
  h += F("<div class='grid'>");
  bluetoothBar(h);
  h += F("<div class='card wide'><h2>");
  h += T(STR_PRN_TITLE);
  h += F("</h2>");
  deviceTile(h, c);
  pickers(h, c);
  testRow(h);
  h += F("</div>");
  calibrationCard(h, c);
  h += F("</div>");
  pageScript(h);
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
