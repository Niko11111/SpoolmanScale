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
  j += F("},\"lastTest\":");
  const int last = printerLastTestResult();
  if (last < 0) j += F("null");
  else { j += '"'; j += jsonText(T(last)); j += '"'; }
  j += '}';
  return j;
}

static String body() {
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  String h;
  h.reserve(6000);

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
  h += F("</span><span class='msg' id='bl-s'></span></div></div>");

  // ---- which printers the scale can drive --------------------------------
  h += F("<div class='card'><h2>");
  h += T(STR_W_P_SUPPORTED);
  h += F("</h2><div class='row'><span class='k'>Phomemo M220</span><span class='v'>");
  h += T(STR_W_P_TESTED);
  h += F("</span></div><div class='row'><span class='k'>Phomemo M110</span><span class='v'>");
  h += T(STR_PRN_EXPERIMENTAL);
  h += F("</span></div><span class='hint'>");
  h += T(STR_W_P_SUPPORTED_HINT);
  h += F("</span></div>");

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
    const LabelPrinterModel models[] = { LP_MODEL_M220, LP_MODEL_M110 };
    for (const LabelPrinterModel m : models) {
      const LabelPrinterProfile& p = labelPrinterProfile(m);
      h += F("<option value='");
      h += String((int)m);
      h += F("'");
      if (c.model == m) h += F(" selected");
      h += F(">Phomemo ");
      h += p.name;
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
         "<div class='row'><span class='k'>");
  h += T(STR_W_P_LAST_TEST);
  h += F("</span><span class='v' id='lt'></span></div></div></div></div>");

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
  h += F("};"
         "let timer=0;"
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
         "$('pm').value=String(d.printer.model);"
         "$('ps').value=d.printer.w+'x'+d.printer.h;"
         "$('lt').textContent=d.lastTest||'';"
         "$('sc').disabled=!d.ble||d.stuck||d.scanning;"
         "$('tb').disabled=!d.ble||d.stuck||!d.printer.configured;"
         "rows(d);"
         // While the scale scans, ask again in two seconds; the scan itself
         // takes five.
         "clearTimeout(timer);if(d.scanning)timer=setTimeout(load,2000);}"
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
         "$('fb').addEventListener('click',function(){"
         "postFlash('/api/printer/forget','','pd-s',4000).then(load);});"
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
    if (m != LP_MODEL_M220 && m != LP_MODEL_M110) { srv.send(400, "text/plain", "unknown model"); return; }
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
