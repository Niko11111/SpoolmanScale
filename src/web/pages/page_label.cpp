// Labels: the template the scale prints a spool's label with. An
// arrangement, the fields to print and a few options on the left, the label
// as the printer would get it on the right, drawn by the scale itself from
// the last spool it found.
//
// The preview is the print raster, cut to the label and sent as a 1-bit BMP:
// the renderer runs on the loop task, which is where this handler runs too,
// and it makes no request. The dates a label carries are the one thing the
// scan does not hold; the state route parks a request for them and the page
// asks again until they are there.
//
// One template for every label size for now. The layout's bits are appended
// to, never renumbered, so the page can grow without losing what was saved.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>
#include <esp_heap_caps.h>

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "app/label_spool.h"
#include "hardware/sd_logger.h"
#include "services/ble_service.h"
#include "services/label_bmp.h"
#include "services/label_layout.h"
#include "services/label_printer.h"
#include "services/label_render.h"
#include "ui/printer_screen.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

static const char* label() { return T(STR_W_NAV_LABEL); }

// The fields in the order the page lists them, with their captions.
struct FieldRow { LabelField field; int caption; };
static const FieldRow FIELD_ROWS[] = {
  { LF_VENDOR,   STR_LBL_VENDOR },
  { LF_MATERIAL, STR_LBL_MATERIAL },
  { LF_NAME,     STR_W_L_F_NAME },
  { LF_SPOOL_ID, STR_W_TAG_SPOOLID },
  { LF_COLOR,    STR_LBL_L_COLOR },
  { LF_ARTICLE,  STR_LBL_ARTICLE_NO_SHORT },
  { LF_DATE,     STR_W_L_F_DATE },
  { LF_QR,       STR_W_L_F_QR },
  { LF_BRAND,    STR_W_L_F_BRAND },
};
static const int FIELD_ROW_COUNT = sizeof(FIELD_ROWS) / sizeof(FIELD_ROWS[0]);

struct OptionRow { LabelOption option; int caption; };
static const OptionRow OPTION_ROWS[] = {
  { LO_MATERIAL_PLAIN, STR_W_L_O_PLAIN },
  { LO_DATE_ADDED,     STR_W_L_O_ADDED },
};
static const int OPTION_ROW_COUNT = sizeof(OPTION_ROWS) / sizeof(OPTION_ROWS[0]);

static const int PRESET_CAPTIONS[LABEL_PRESET_COUNT] = {
  STR_W_L_P_STANDARD, STR_W_L_P_COMPACT, STR_W_L_P_BIG_QR,
};

// What the preview shows until a spool has been found since boot: a spool
// as a Bambu tag would bring it, so every field has something to show.
static void sampleSpool(SpoolLabelData* d) {
  *d = SpoolLabelData{};
  d->id = 42;
  snprintf(d->vendor, sizeof(d->vendor), "Bambu Lab");
  snprintf(d->material, sizeof(d->material), "PLA");
  snprintf(d->name, sizeof(d->name), "PLA Basic Jade White");
  snprintf(d->color, sizeof(d->color), "F2F2E8");
  snprintf(d->article, sizeof(d->article), "10100");
  snprintf(d->first_used, sizeof(d->first_used), "03.03.2026");
  snprintf(d->added, sizeof(d->added), "01.03.2026");
}

static String stateJson() {
  const LabelLayout l = labelLayoutLoad();
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  SpoolLabelData s{};
  const bool have = labelSpoolLast(&s);
  // The preview waits for these; the loop asks the backend, once per spool.
  if (have && !labelSpoolDatesKnown()) label_dates_pending = true;
  String j;
  j.reserve(700);
  j += F("{\"preset\":");   j += String((unsigned)l.preset);
  j += F(",\"fields\":");   j += String((unsigned long)l.fields);
  j += F(",\"options\":");  j += String((unsigned long)l.options);
  j += F(",\"spool\":");
  if (have) {
    j += F("{\"id\":");      j += String(s.id);
    j += F(",\"text\":\"");
    j += jsonEsc(s.vendor); j += ' '; j += jsonEsc(s.name);
    j += F("\",\"on\":");
    // The display keeps a spool after it left; the tag says whether it is there.
    j += (tag_present && sm_found && sm_id == s.id) ? F("true") : F("false");
    j += '}';
  } else {
    j += F("null");
  }
  j += F(",\"dates\":");
  j += (!have || labelSpoolDatesKnown()) ? F("true") : F("false");
  j += F(",\"media\":\"");
  j += String((unsigned)c.media_width_mm); j += F(" x ");
  j += String((unsigned)c.media_length_mm); j += F(" mm\",\"model\":\"");
  j += jsonEsc(labelPrinterProfile(c.model).brand); j += ' ';
  j += jsonEsc(labelPrinterProfile(c.model).name);
  j += F("\",\"configured\":");
  j += labelPrinterConfigured(c) ? F("true") : F("false");
  j += F(",\"canPrint\":");
  const bool can = labelPrinterConfigured(c) && bleEnabled() && bleStackAvailable() &&
                   !bleStackStuck();
  j += can ? F("true") : F("false");
  j += F(",\"lastPrint\":");
  const int last = printerLastLabelResult();
  if (last < 0) j += F("null");
  else { j += '"'; j += jsonEsc(T(last)); j += '"'; }
  j += '}';
  return j;
}

// The left card: the arrangement as tabs, the fields and options as switches.
// The values are set by the script from the state, so the markup is static.
static void templateCard(String& h) {
  h += F("<div class='card'><h2>");
  h += T(STR_W_L_TEMPLATE);
  h += F("</h2><div class='field'><label>");
  h += T(STR_W_L_ARRANGE);
  h += F("</label><div class='btabs' id='lpre'>");
  for (int i = 0; i < LABEL_PRESET_COUNT; i++) {
    h += F("<button class='btab' data-p='");
    h += String(i);
    h += F("'>");
    h += T(PRESET_CAPTIONS[i]);
    h += F("</button>");
  }
  h += F("</div><span class='hint'>");
  h += T(STR_W_L_ARRANGE_HINT);
  h += F("</span></div><div class='field'><label>");
  h += T(STR_W_L_FIELDS);
  h += F("</label><div id='lf' class='lb-sw'>");
  for (int i = 0; i < FIELD_ROW_COUNT; i++) {
    h += F("<label class='check'><span class='switch'><input type='checkbox' data-b='");
    h += String((int)FIELD_ROWS[i].field);
    h += F("'><i></i></span>");
    h += T(FIELD_ROWS[i].caption);
    h += F("</label>");
  }
  h += F("</div></div><div class='field'><label>");
  h += T(STR_W_L_OPTIONS);
  h += F("</label><div id='lo'>");
  for (int i = 0; i < OPTION_ROW_COUNT; i++) {
    h += F("<label class='check'><span class='switch'><input type='checkbox' data-b='");
    h += String((int)OPTION_ROWS[i].option);
    h += F("'><i></i></span>");
    h += T(OPTION_ROWS[i].caption);
    h += F("</label>");
  }
  h += F("</div><span class='hint'>");
  h += T(STR_W_L_DATE_HINT);
  h += F("</span></div><div class='field'><div class='inrow'><button id='lr' class='quiet'>");
  h += T(STR_W_DEFAULTS);
  h += F("</button><span class='msg' id='ls-s'></span></div></div></div>");
}

// The right card: the label as the scale draws it, what it was drawn for,
// and a print of it.
static void previewCard(String& h) {
  h += F("<div class='card lb-prev'><h2>");
  h += T(STR_W_TAG_PREVIEW);
  h += F("</h2><div class='lb-paper'><img id='lp' alt=''></div>"
         "<span class='msg bad' id='lp-s'></span>"
         "<div class='row'><span class='k'>");
  h += T(STR_W_L_SPOOL);
  h += F("</span><span class='v' id='lsp'></span></div><div class='row'><span class='k'>");
  h += T(STR_PRN_MEDIA);
  h += F("</span><span class='v' id='lme'></span></div>"
         "<div class='hint lb-note' id='lsa' style='display:none'>");
  h += T(STR_W_L_SAMPLE);
  h += F("</div><div class='hint lb-note' id='lnp' style='display:none'>");
  h += T(STR_W_L_NO_PRINTER);
  h += F(" <a href='/printer'>");
  h += T(STR_W_NAV_PRINTER);
  h += F("</a></div><div class='field lb-print'><div class='inrow'><button id='lpb'>");
  h += T(STR_W_L_PRINT);
  h += F("</button><span class='hint' style='flex:1'>");
  h += T(STR_W_L_PRINT_HINT);
  h += F("</span></div><span class='msg' id='lpb-s'></span>"
         "<div class='row' id='llr' style='display:none'><span class='k'>");
  h += T(STR_W_L_LAST_PRINT);
  h += F("</span><span class='v' id='ll'></span></div></div></div>");
}

// The page's own look: the label as paper, the switches in two columns.
static void styles(String& h) {
  h += F("<style>"
         // One print dot per CSS pixel, never stretched: scaled by an
         // uneven factor the dots came out blurred and blocky. A label wider
         // than the card shrinks to it.
         ".lb-paper{background:#fff;border:1px solid var(--line);border-radius:8px;"
         "padding:6px;margin:0 auto 12px;line-height:0;width:fit-content;max-width:100%;"
         "box-sizing:border-box}"
         ".lb-paper img{max-width:100%;height:auto;display:block;image-rendering:pixelated}"
         ".lb-paper img:not([src]){visibility:hidden}"
         ".lb-sw{display:grid;grid-template-columns:1fr 1fr;gap:10px 16px}"
         ".lb-sw .check+.check{margin-top:0}"
         ".lb-note{margin-top:12px}"
         ".lb-print{margin-top:16px}"
         "#lpre{flex-wrap:wrap}"
         // One column on a phone: the preview first, so a switch shows its
         // effect without scrolling.
         "@media(max-width:700px){.lb-prev{order:-1}}"
         "@media(max-width:420px){.lb-sw{grid-template-columns:1fr}}"
         "</style>");
}

// The state, the preview and the saving; the handlers are bound below.
// $, flash, post, postFlash and getJson come from /app.js.
static void scriptFunctions(String& h) {
  h += F("<script>");
  h += webShellJsStrings();
  h += F("const L={fail:");
  h += jsStr(T(STR_W_L_PREVIEW_FAIL));
  h += F(",offPad:");
  h += jsStr(T(STR_W_L_OFF_PAD));
  h += F("};"
         "let S=null,shown='',timer=0;"
         "function mask(box){let m=0;"
         "document.querySelectorAll('#'+box+' input').forEach(function(i){"
         "if(i.checked)m|=1<<(+i.dataset.b);});return m;}"
         "function setMask(box,m){document.querySelectorAll('#'+box+' input').forEach(function(i){"
         "i.checked=!!(m&(1<<(+i.dataset.b)));});}"
         // The picture is drawn anew only when something it shows changed.
         "function pic(d){const k=[d.preset,d.fields,d.options,d.spool?d.spool.id:0,"
         "d.dates,d.media,d.model].join('|');if(k===shown)return;shown=k;"
         "$('lp-s').textContent='';$('lp').src='/api/label/preview.bmp?t='+Date.now();}"
         "function paint(d){S=d;"
         "document.querySelectorAll('#lpre .btab').forEach(function(b){"
         "b.classList.toggle('on',+b.dataset.p===d.preset);});"
         "setMask('lf',d.fields);setMask('lo',d.options);"
         "$('lsp').textContent=d.spool?(d.spool.text+' \u00b7 #'+d.spool.id+(d.spool.on?'':' '+L.offPad)):'-';"
         "$('lme').textContent=d.media+' \u00b7 '+d.model;"
         "$('lsa').style.display=d.spool?'none':'';"
         "$('lnp').style.display=d.configured?'none':'';"
         "$('lpb').disabled=!d.spool||!d.canPrint;"
         "$('ll').textContent=d.lastPrint||'';"
         "$('llr').style.display=d.lastPrint?'':'none';"
         "pic(d);"
         // The dates come from the server a moment later; a new spool on the
         // pad shows up on the next look.
         "clearTimeout(timer);timer=setTimeout(load,d.dates?5000:1500);}"
         "function load(){if(document.hidden)return;"
         "getJson('/api/label').then(function(d){if(d)paint(d);});}"
         "function save(p,f,o){"
         "postFlash('/api/label',p+','+f+','+o,'ls-s',2500).then(load);}");
}

// Every handler is bound here rather than written into an onclick
// attribute: a page body is JavaScript inside a C++ string literal, and an
// attribute is the one place where the two levels of quoting collide.
static void scriptBindings(String& h) {
  h += F("document.querySelectorAll('#lpre .btab').forEach(function(b){"
         "b.addEventListener('click',function(){if(S)save(+b.dataset.p,S.fields,S.options);});});"
         "document.querySelectorAll('#lf input,#lo input').forEach(function(i){"
         "i.addEventListener('change',function(){if(S)save(S.preset,mask('lf'),mask('lo'));});});"
         "$('lr').addEventListener('click',function(){postFlash('/api/label/reset','','ls-s',2500).then(load);});"
         "$('lp').addEventListener('error',function(){$('lp-s').textContent=L.fail;shown='';});"
         // Hard dot edges only where the dots are enlarged; shrunk, the
         // nearest dot would drop whole rows of them.
         "$('lp').addEventListener('load',function(){var i=$('lp');"
         "i.style.imageRendering=i.clientWidth*(window.devicePixelRatio||1)>=i.naturalWidth?'pixelated':'auto';});"
         // The print takes about ten seconds on the scale; the verdict is
         // fetched after that and shown on the last line.
         "$('lpb').addEventListener('click',function(){"
         "postFlash('/api/label/print','','lpb-s',4000).then(function(){setTimeout(load,12000);});});"
         "document.addEventListener('visibilitychange',load);"
         "load();"
         "</script>");
}

static String body() {
  String h;
  h.reserve(7000);
  styles(h);
  h += F("<div class='grid'>");
  templateCard(h);
  previewCard(h);
  h += F("</div>");
  scriptFunctions(h);
  scriptBindings(h);
  return h;
}

// The label as the printer would get it, cut to the label, as a 1-bit BMP.
static void sendPreview(WebServer& srv) {
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  SpoolLabelData spool{};
  if (!labelSpoolLast(&spool)) sampleSpool(&spool);
  LabelRaster r{};
  if (!labelRenderSpool(c, labelLayoutLoad(), spool, &r)) {
    labelRasterFree(&r);
    srv.send(409, "text/plain", T(STR_W_L_PREVIEW_FAIL));
    return;
  }
  const uint16_t w = r.content_width;
  const uint16_t x0 = labelPrinterContentX(c);
  const uint32_t row = labelBmpRowBytes(w);
  const uint32_t bytes = labelBmpFileBytes(w, r.height);
  uint8_t* bmp = (uint8_t*)heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM);
  if (!bmp) {
    labelRasterFree(&r);
    logSD("Web: no PSRAM for the label preview");
    srv.send(503, "text/plain", T(STR_W_L_PREVIEW_FAIL));
    return;
  }
  labelBmpHeader(w, r.height, bmp);
  for (uint16_t y = 0; y < r.height; y++)
    labelBmpRow(r, x0, w, y, bmp + LABEL_BMP_HEADER_BYTES + size_t(y) * row);
  labelRasterFree(&r);
  srv.sendHeader("Cache-Control", "no-store");
  srv.setContentLength(bytes);
  srv.send(200, "image/bmp", "");
  srv.sendContent((const char*)bmp, bytes);
  heap_caps_free(bmp);
}

// "preset,fields,options" as numbers; anything unknown in them is dropped.
static bool parseLayout(const String& v, LabelLayout* out) {
  const int a = v.indexOf(',');
  const int b = a < 0 ? -1 : v.indexOf(',', a + 1);
  if (a <= 0 || b <= a) return false;
  LabelLayout l{};
  l.preset = (uint8_t)strtoul(v.c_str(), nullptr, 10);
  l.fields = strtoul(v.c_str() + a + 1, nullptr, 10);
  l.options = strtoul(v.c_str() + b + 1, nullptr, 10);
  *out = labelLayoutSanitized(l);
  return true;
}

static void routes(WebServer &srv) {
  srv.on("/api/label", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LABEL))) return;
    srv.send(200, "application/json", stateJson());
  });

  srv.on("/api/label", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LABEL))) return;
    LabelLayout l{};
    if (!parseLayout(srv.arg("plain"), &l)) { srv.send(400, "text/plain", "bad layout"); return; }
    const bool ok = labelLayoutSave(l);
    srv.send(ok ? 200 : 500, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
  });

  srv.on("/api/label/reset", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LABEL))) return;
    const bool ok = labelLayoutSave(labelLayoutDefault());
    srv.send(ok ? 200 : 500, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
  });

  srv.on("/api/label/preview.bmp", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LABEL))) return;
    sendPreview(srv);
  });

  // Parks the print like the test print: the loop renders and prints the
  // last spool under the overlay, the page fetches the verdict afterwards.
  srv.on("/api/label/print", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LABEL))) return;
    SpoolLabelData s{};
    if (!labelSpoolLast(&s)) { srv.send(409, "text/plain", T(STR_PRN_ERR_NO_SPOOL)); return; }
    if (!labelPrinterConfigured(labelPrinterLoadConfig())) { srv.send(409, "text/plain", T(STR_PRN_ERR_NO_PRINTER)); return; }
    if (!bleEnabled()) { srv.send(409, "text/plain", T(STR_PRN_ERR_BLE_OFF)); return; }
    if (bleStackStuck()) { srv.send(409, "text/plain", T(STR_PRN_ERR_STUCK)); return; }
    print_last_label_pending = true;
    logSDf("Web: label print for spool #%d requested", s.id);
    srv.send(200, "text/plain", T(STR_W_P_QUEUED));
  });
}

extern const WebPage PAGE_LABEL;
const WebPage PAGE_LABEL = {
  "/label", label, GATE_CONFIG, nullptr,
  body, routes
};
