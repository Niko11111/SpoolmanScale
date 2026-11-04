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
//
// On a FilaMan with the label API the label can come from a preset laid out
// in FilaMan's designer instead (app/label_server.h). That one needs HTTP for
// the list and the preview, which these handlers must not make: the state
// route asks for them, a task fetches, and the page polls until they are in.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>
#include <esp_heap_caps.h>

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "app/label_server.h"
#include "app/label_spool.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/ble_service.h"
#include "services/label_bmp.h"
#include "services/label_fit.h"
#include "services/label_gaps.h"
#include "services/label_layout.h"
#include "services/label_printer.h"
#include "services/label_render.h"
#include "ui/date_display.h"
#include "ui/printer_screen.h"
#include "web/web_access.h"
#include "web/web_printer_select.h"
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
  { LF_SPOOL_WEIGHT, STR_W_L_F_SPOOL_W },
  { LF_NET_WEIGHT, STR_W_L_F_NET_W },
  { LF_TEMPS,    STR_W_L_F_TEMPS },
  { LF_DRYING,   STR_W_L_F_DRYING },
  { LF_LOCATION, STR_W_L_F_LOCATION },
  { LF_DRIED,    STR_W_L_F_DRIED },
  { LF_FREE_TEXT, STR_W_L_F_TEXT },
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
  STR_W_L_P_STANDARD, STR_W_L_P_COMPACT, STR_W_L_P_BIG_QR, STR_W_L_P_MATERIAL_BIG,
  STR_W_L_P_TEXT_ONLY, STR_W_L_P_BIG_ID, STR_W_L_P_BIG_ID_SIDE,
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
  isoToLabelDate("2026-03-03", d->first_used, sizeof(d->first_used));
  isoToLabelDate("2026-03-01", d->added, sizeof(d->added));
  d->filament_id = 21;
  d->spool_weight_g = 250;
  d->net_weight_g = 1000;
  snprintf(d->location, sizeof(d->location), "Regal 2");
  isoToLabelDate("2026-03-10", d->dried, sizeof(d->dried));
  d->nozzle_min = 190;
  d->nozzle_max = 230;
  d->bed_temp = 55;
  d->dry_temp_c = 55;
  d->dry_hours = 8;
}

// FilaMan's presets for the source row, and how the server's preview stands.
// "fm" is the list's state; the preview is asked for only while a preset is
// the source.
static void serverJson(String& j, const LabelPrinterConfig& c, int spool_id) {
  static const char* const LIST_STATES[] = { "unknown", "loading", "ready", "absent", "failed" };
  static const char* const PREVIEW_STATES[] = { "none", "loading", "ready", "failed" };
  const FilamanLabelPresetList* list = nullptr;
  const LabelServerListState st = labelServerList(&list);
  // A tape printer prints its own label, never a preset (labelServerInUse()):
  // the page shows the scale's preview for it, not the server's.
  j += F(",\"source\":");
  j += String(labelPrinterIsTape(c.model) ? 0 : labelServerPresetId());
  j += F(",\"fm\":\"");
  j += LIST_STATES[st];
  j += F("\",\"presets\":[");
  for (int i = 0; st == LS_READY && i < list->count; i++) {
    const FilamanLabelPreset& p = list->items[i];
    const LabelFit fit = labelPresetFit(p.width_mm, p.height_mm, c.media_width_mm, c.media_length_mm);
    if (i) j += ',';
    j += F("{\"id\":");      j += String(p.id);
    j += F(",\"name\":\"");  j += jsonEsc(p.name);
    j += F("\",\"size\":\""); j += String(p.width_mm); j += F(" x ");
    j += String(p.height_mm);
    j += F(" mm\",\"fit\":");
    j += fit != LABEL_FIT_NONE ? F("true") : F("false");
    j += F(",\"rotated\":");
    j += fit == LABEL_FIT_ROTATED ? F("true") : F("false");
    j += '}';
  }
  j += ']';
  if (!labelServerInUse()) return;
  const LabelRaster* r = nullptr;
  const char* reason = "";
  const LabelServerPreviewState ps = labelServerPreview(c, spool_id, &r, &reason);
  j += F(",\"prev\":\"");
  j += PREVIEW_STATES[ps];
  j += F("\",\"prevRev\":");
  j += String(labelServerPreviewRev());
  j += F(",\"prevReason\":\"");
  j += jsonEsc(reason);
  j += '"';
}

// Which label a request is about: ?kind=1 the filament's, else the spool's.
static LabelKind kindOf(WebServer& srv) {
  return srv.arg("kind") == "1" ? LABEL_KIND_FILAMENT : LABEL_KIND_SPOOL;
}

// The template of one kind of label, and what the page holds its switches
// to: how many fact lines this roll takes, which fields count, which the
// kind has at all. A filament with no page to open prints without a code.
static void layoutJson(String& j, LabelKind kind, const LabelPrinterConfig& c, bool fil_page) {
  LabelLayout l = labelLayoutLoad(kind);
  j += F("{\"kind\":");     j += String((unsigned)kind);
  j += F(",\"preset\":");   j += String((unsigned)l.preset);
  j += F(",\"fields\":");   j += String((unsigned long)l.fields);
  j += F(",\"options\":");  j += String((unsigned long)l.options);
  j += F(",\"idSet\":");    j += String((unsigned)l.id_share);
  j += F(",\"idShare\":");  j += String((unsigned)labelIdShareFor(l.id_share, l.preset));
  const bool code_possible = kind == LABEL_KIND_SPOOL || fil_page;
  if (!code_possible) l.fields &= ~(1u << LF_QR);
  j += F(",\"cap\":");
  j += String(labelFactCapacity(l, c.media_width_mm, c.media_length_mm));
  j += F(",\"factBits\":"); j += String((unsigned long)labelFactFields(l.preset));
  j += F(",\"kindFields\":"); j += String((unsigned long)labelKindFields(kind));
  j += F(",\"hasQr\":");
  j += labelPresetHasQr(l.preset) && code_possible ? F("true") : F("false");
  j += F(",\"filPage\":");
  j += fil_page ? F("true") : F("false");
}

static String stateJson(LabelKind kind) {
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  SpoolLabelData s{};
  const bool have = labelSpoolLast(&s);
  if (!have) sampleSpool(&s);
  // The preview waits for these; the loop asks the backend, once per spool.
  if (have && !labelSpoolDatesKnown()) label_dates_pending = true;
  char fil_qr[LABEL_QR_LEN];
  labelQrForFilament(s, fil_qr, sizeof(fil_qr));
  String j;
  j.reserve(1600);
  layoutJson(j, kind, c, fil_qr[0] != '\0');
  j += F(",\"text\":\"");  j += jsonEsc(labelLayoutFreeText()); j += '"';
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
  // The switches that would print nothing: once the backend has answered,
  // so a value still on its way is not called missing.
  const LabelLayout l = labelLayoutLoad(kind);
  j += F(",\"empty\":");
  j += String((unsigned long)(have && labelSpoolDatesKnown() ? labelEmptyFields(s, l.options) : 0));
  j += F(",\"lacks\":");
  j += String((unsigned long)labelBackendLacks(backendMode()));
  // The printer and stock as the two lists below the preview pick them.
  j += F(",\"modelId\":");  j += String((int)c.model);
  j += F(",\"mediaKey\":\""); j += String((unsigned)c.media_width_mm); j += 'x';
  j += String((unsigned)c.media_length_mm);
  j += F("\",\"dpi\":");    j += String((unsigned)labelPrinterProfile(c.model).dpi);
  // A tape printer's label is fixed: the template stays in view, out of use.
  j += F(",\"tape\":");
  j += labelPrinterIsTape(c.model) ? F("true") : F("false");
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
  j += F(",\"lastReason\":\"");
  if (last == STR_PRN_ERR_SERVER_LABEL) j += jsonEsc(labelServerLastReason());
  j += '"';
  // FilaMan's presets draw a spool's label; the filament's is the scale's own.
  if (kind == LABEL_KIND_SPOOL) serverJson(j, c, have ? s.id : 0);
  else j += F(",\"source\":0,\"fm\":\"absent\",\"presets\":[]");
  j += '}';
  return j;
}

// The source on top of the template: the scale's own or a FilaMan preset.
// Hidden until the server has a list; the options are built by the script,
// a list rather than tabs because the user decides how many presets there are.
static void sourceRow(String& h) {
  h += F("<div class='field' id='lsrcf' style='display:none'><label>");
  h += T(STR_W_L_SOURCE);
  h += F("</label><select id='lsrc'></select><span class='hint'>");
  h += T(STR_W_L_SRC_HINT);
  h += F("</span><span class='hint' id='lsrv' style='display:none'>");
  h += T(STR_W_L_SRC_SERVER);
  h += F("</span><span class='msg' id='lsrc-s'></span></div>");
}

// The left card: the arrangement as tabs, the fields and options as switches.
// The values are set by the script from the state, so the markup is static.
static void templateCard(String& h) {
  h += F("<div class='card'><h2>");
  h += T(STR_W_L_TEMPLATE);
  h += F("</h2><div class='field'><label>");
  // Which label: the spool's or its filament's, each with its own template.
  h += T(STR_W_L_KIND);
  h += F("</label><div class='btabs' id='lkind'><button class='btab' data-k='0'>");
  h += T(STR_W_L_KIND_SPOOL);
  h += F("</button><button class='btab' data-k='1'>");
  h += T(STR_W_L_KIND_FILAMENT);
  h += F("</button></div><span class='hint' id='lkh' style='display:none'>");
  h += T(STR_W_L_KIND_HINT);
  h += F("</span><span class='hint' id='lfq' style='display:none'>");
  h += T(STR_W_L_FIL_NO_PAGE);
  h += F("</span></div>");
  sourceRow(h);
  h += F("<div class='field' id='ltp' style='display:none'><span class='hint'>");
  h += T(STR_W_L_TAPE_FIXED);
  // A fieldset: disabling it switches off every control inside at once, and
  // leaves what each one holds for the other printers as it is.
  h += F("</span></div><fieldset id='ltpl'><div class='field'><label>");
  h += T(STR_W_L_ORIENT);
  h += F("</label><div class='btabs' id='lori'><button class='btab' data-o='0'>");
  h += T(STR_W_L_FLAT);
  h += F("</button><button class='btab' data-o='1'>");
  h += T(STR_W_L_UPRIGHT);
  h += F("</button></div></div><div class='field'><label>");
  h += T(STR_W_L_ARRANGE);
  // Each arrangement as a tile with a sketch of it; the script draws the
  // sketches, flat or upright as the label is.
  h += F("</label><div class='btabs' id='lpre'>");
  for (int i = 0; i < LABEL_PRESET_COUNT; i++) {
    h += F("<button class='btab lb-tile' data-p='");
    h += String(i);
    h += F("'><span class='lb-ic'></span>");
    h += T(PRESET_CAPTIONS[i]);
    h += F("</button>");
  }
  h += F("</div><span class='hint'>");
  h += T(STR_W_L_ARRANGE_HINT);
  // How far the big number and the text push against each other.
  h += F("</span></div><div class='field' id='lish' style='display:none'><label for='lis'>");
  h += T(STR_W_L_ID_SHARE);
  h += F("</label><div class='range'><input id='lis' type='range' min='");
  h += String(LABEL_ID_SHARE_MIN);
  h += F("' max='");
  h += String(LABEL_ID_SHARE_MAX);
  h += F("' step='5'><output id='lisv'></output></div></div><div class='field'><label>");
  h += T(STR_W_L_FIELDS);
  h += F("</label><div id='lf' class='lb-sw'>");
  for (int i = 0; i < FIELD_ROW_COUNT; i++) {
    h += F("<label class='check'><span class='switch'><input type='checkbox' data-b='");
    h += String((int)FIELD_ROWS[i].field);
    h += F("'><i></i></span><span>");
    h += T(FIELD_ROWS[i].caption);
    h += F("<small class='lb-gap'></small></span></label>");
  }
  h += F("</div><span class='hint' id='lcap'></span><span class='msg' id='lcap-s'></span>"
         "<input id='ltx' type='text' maxlength='");
  h += LABEL_FREE_TEXT_CHARS;
  h += F("' autocomplete='off'><span class='hint'>");
  h += T(STR_W_L_TEXT_HINT);
  h += ' ';
  h += T(STR_W_L_CHANGE_HINT);
  h += F("</span><span class='msg' id='ltx-s'></span></div><div class='field'><label>");
  h += T(STR_W_L_OPTIONS);
  h += F("</label><div id='lo'>");
  for (int i = 0; i < OPTION_ROW_COUNT; i++) {
    h += F("<label class='check'><span class='switch'><input type='checkbox' data-b='");
    h += String((int)OPTION_ROWS[i].option);
    h += F("'><i></i></span>");
    h += T(OPTION_ROWS[i].caption);
    h += F("</label>");
  }
  h += F("</div><span class='hint' id='ldh'>");
  h += T(STR_W_L_DATE_HINT);
  h += F("</span></div><div class='field'><div class='inrow'><button id='lr' class='quiet'>");
  h += T(STR_W_DEFAULTS);
  h += F("</button><span class='msg' id='ls-s'></span></div></div></fieldset></div>");
}

// The printer and the stock, to change right here: the same lists and the
// same routes as the printer page, so a roll swap needs no change of tab.
static void printerRows(String& h, const LabelPrinterConfig& c) {
  h += F("<div class='field lb-pick'><label>");
  h += T(STR_PRN_MODEL);
  h += F("</label><div class='inrow'><select id='lpm'>");
  webPrinterModelOptions(h, c);
  h += F("</select><span class='hint' id='ldpi'></span></div><span class='msg' id='lpm-s'></span>"
         "</div><div class='field lb-pick'><label>");
  h += T(STR_PRN_MEDIA);
  h += F("</label><div class='inrow'><select id='lps'>");
  webPrinterMediaOptions(h, c);
  h += F("</select><span class='hint' id='lme'></span></div><span class='msg' id='lps-s'></span></div>");
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
  h += F("</span><span class='v' id='lsp'></span></div>");
  printerRows(h, labelPrinterLoadConfig());
  h += F("<div class='hint lb-note' id='lsa' style='display:none'>");
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
         // The label as large as its millimetres, whatever the printer: the
         // script sets the width at 8 CSS pixels to the millimetre, which is
         // one dot per pixel at 203 dpi, so those stay as sharp as before and
         // a 300 dpi label shows its finer dots in the same size rather than
         // growing (Nikolai, 21.10.2026). A label wider than the card shrinks.
         ".lb-paper{background:#fff;border:1px solid var(--line);border-radius:8px;"
         "padding:6px;margin:0 auto 12px;line-height:0;width:fit-content;max-width:100%;"
         "box-sizing:border-box}"
         ".lb-paper img{max-width:100%;height:auto;display:block;image-rendering:pixelated}"
         ".lb-paper img:not([src]){visibility:hidden}"
         ".lb-sw{display:grid;grid-template-columns:1fr 1fr;gap:10px 16px}"
         ".lb-sw .check+.check{margin-top:0}"
         ".lb-note{margin-top:12px}"
         ".lb-print{margin-top:16px}"
         // Seven tiles, three to a row, all as wide as each other.
         "#lpre{display:grid;grid-template-columns:repeat(3,1fr)}"
         ".lb-tile{flex-direction:column;gap:6px;min-width:0;padding:8px 6px}"
         ".lb-ic{height:58px;display:flex;align-items:center;justify-content:center}"
         ".lb-ic svg{display:block}"
         ".lb-sw .check.off{opacity:.45}"
         "#ltp{margin-bottom:16px}"
         "#ltpl{border:0;margin:0;padding:0;min-width:0}"
         // Out of use as one block: the controls' own dimming would multiply
         // with it and leave them unreadable.
         "#ltpl:disabled{opacity:.55}"
         "#ltpl:disabled button:disabled,#ltpl:disabled .check.off{opacity:1}"
         ".lb-gap{display:block;color:var(--ink-soft);font-size:12px}.lb-gap:empty{display:none}"
         "#ltx{margin-top:10px;width:100%;box-sizing:border-box}"
         ".lb-pick{margin-top:12px}.lb-pick select{flex:1;min-width:0}"
         // One column on a phone: the preview first, so a switch shows its
         // effect without scrolling.
         "@media(max-width:700px){.lb-prev{order:-1}}"
         "@media(max-width:420px){.lb-sw{grid-template-columns:1fr}}"
         "</style>");
}

// The template's own parts: the sketches on the tiles, the orientation and
// the line budget. Part of the script scriptFunctions() opens.
static void scriptTemplate(String& h) {
  h += F(
         // The sketches: per arrangement flat and upright, each rectangle as
         // kind x,y,w,h in millimetres; b is black, q the code, l a line.
         "const IC=["
         "['l8,2,24,4 b2,8,36,4 l6,14,28,3 l2,19,16,2 l2,22.5,14,2 l2,26,17,2 q26,18,10,10',"
         "'l6,2,18,4 b2,8,26,4 l4,14,22,3 l2,19,16,2 l2,22.5,14,2 l2,26,17,2 q10,29,10,10'],"
         "['b2,2,36,4 l6,8,28,3 l2,14,14,2 l2,17.5,17,2 l2,21,13,2 l2,24.5,16,2 q23,13,14,14',"
         "'b2,2,26,4 l4,8,22,3 l2,13,12,2 l2,16.5,16,2 l2,20,13,2 l2,23.5,15,2 q9,27,12,12'],"
         "['l2,3,18,3 b2,8,18,3 l2,13,18,2 l2,18,14,1.5 l2,21,16,1.5 l2,24,12,1.5 q22,6,16,16',"
         "'q7,2,16,16 l6,20,18,3 b2,25,26,3 l4,30,22,2 l2,34,14,1.5 l2,37,10,1.5'],"
         "['b2,2,36,8 l10,12,20,2.5 l6,16,28,2.5 l2,21,16,2 l2,24.5,14,2 q28,19,9,9',"
         "'b2,2,26,8 l7,12,16,2.5 l4,16,22,2.5 l2,21,8,1.5 l2,23.5,14,3 l2,28,8,1.5 q11,31,8,8'],"
         "['l8,2,24,4 b2,8,36,4 l6,14,28,3 l2,19,8,1.5 l2,21.5,14,3 l22,19,8,1.5 l22,21.5,14,3 l2,26,8,1.5',"
         "'l6,2,18,4 b2,8,26,4 l4,14,22,3 l2,19,8,1.5 l2,21.5,14,3 l2,26,8,1.5 l2,28.5,14,3 l2,33,8,1.5 l2,35.5,14,3'],"
         // The big number: three digits as blocks, the lines under them.
         "['b4,2,9,15 b15.5,2,9,15 b27,2,9,15 l8,19,24,2.5 l4,23,32,2 l4,26,32,2',"
         "'b3,2,7,13 b11.5,2,7,13 b20,2,7,13 l6,18,18,3 b2,23,26,3 l4,28,22,2 l4,32,22,2 l4,36,22,2'],"
         // The same with the number on the right, the lines beside it.
         "['l3,4,17,3 b3,9,17,4 l3,15,17,2 l3,19,14,2 l3,23,16,2 b22,10,7,10 b30.5,10,7,10',"
         "'l3,6,11,3 b3,11,11,4 l3,17,11,2 l3,21,9,2 l3,25,10,2 l3,29,11,2 b16,15,5,10 b22.5,15,5,10']];"
         "function icon(p,up){const w=up?30:40,h=up?40:30;"
         "let s='<svg viewBox=\"0 0 '+w+' '+h+'\" width=\"'+w*1.4+'\" height=\"'+h*1.4+'\">'"
         "+'<rect x=\".5\" y=\".5\" width=\"'+(w-1)+'\" height=\"'+(h-1)+'\" rx=\"2\" fill=\"none\" stroke=\"currentColor\" stroke-opacity=\".4\"/>';"
         "IC[p][up?1:0].split(' ').forEach(function(t){const v=t.slice(1).split(',');"
         "s+='<rect x=\"'+v[0]+'\" y=\"'+v[1]+'\" width=\"'+v[2]+'\" height=\"'+v[3]+'\" fill=\"currentColor\"'"
         "+(t[0]==='l'?' fill-opacity=\".45\"':'')+'/>';});return s+'</svg>';}"
         "function tiles(d){const up=!!(d.options&PB);"
         "$('lish').style.display=bigId(d.preset)?'':'none';"
         "if(document.activeElement!==$('lis'))$('lis').value=d.idShare;"
         "$('lisv').textContent=d.idShare+' %';"
         "document.querySelectorAll('#lkind .btab').forEach(function(b){b.classList.toggle('on',+b.dataset.k===d.kind);});"
         "$('lkh').style.display=d.kind===1?'':'none';"
         "$('lfq').style.display=d.kind===1&&!d.filPage&&!d.tape?'':'none';"
         // A filament has no date: its option and the hint go with it.
         "$('ldh').style.display=d.kind===1?'none':'';"
         "document.querySelectorAll('#lo input').forEach(function(i){"
         "i.closest('label').style.display=d.kind===1&&+i.dataset.b===DB?'none':'';});"
         "document.querySelectorAll('#lori .btab').forEach(function(b){b.classList.toggle('on',+b.dataset.o===(up?1:0));});"
         "document.querySelectorAll('#lpre .btab').forEach(function(b){"
         "b.style.display=d.kind===1&&bigId(+b.dataset.p)?'none':'';"
         "b.classList.toggle('on',+b.dataset.p===d.preset);const k=up?'u':'f';if(b.dataset.k===k)return;"
         "b.dataset.k=k;b.querySelector('.lb-ic').innerHTML=icon(+b.dataset.p,up);});}"
         // The line budget: the fact switches that are off close once it is
         // full, and a template from before that holds more says so.
         "function capRow(d){const f=mask('lf')&d.factBits;let n=0;"
         "for(let b=0;b<32;b++)if(f&(1<<b))n++;"
         "$('lcap').textContent=L.cap.replace('%d',n).replace('%d',d.cap);"
         "const m=$('lcap-s');m.textContent=n>d.cap?L.capOver:(n===d.cap?L.capFull:'');"
         "m.classList.toggle('bad',n>d.cap);"
         "document.querySelectorAll('#lf input').forEach(function(i){const b=+i.dataset.b;"
         "i.closest('label').style.display=d.kindFields&(1<<b)?'':'none';"
         "i.disabled=(b===QRB&&!d.hasQr)||(b===IDB&&bigId(d.preset))||(!i.checked&&!!(d.factBits&(1<<b))&&n>=d.cap);"
         "i.closest('label').classList.toggle('off',i.disabled);"
         // Beside a switch that would print nothing, why.
         "i.closest('label').querySelector('.lb-gap').textContent="
         "d.lacks&(1<<b)?L.gapB:(d.empty&(1<<b)?L.gapS:'');});}"
         "function opts(){return mask('lo')|(S.options&PB);}");
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
  h += F(",scale:");
  h += jsStr(T(STR_W_L_SRC_SCALE));
  h += F(",srcLoading:");
  h += jsStr(T(STR_W_L_SRC_LOADING));
  h += F(",srcFailed:");
  h += jsStr(T(STR_W_L_SRC_FAILED));
  h += F(",loading:");
  h += jsStr(T(STR_W_L_PREVIEW_LOADING));
  h += F(",noSpool:");
  h += jsStr(T(STR_W_L_SRC_NO_SPOOL));
  h += F(",rotated:");
  h += jsStr(T(STR_W_L_SRC_ROTATED));
  h += F(",upright:");
  h += jsStr(T(STR_W_L_UPRIGHT));
  h += F(",cap:");
  h += jsStr(T(STR_W_L_CAP));
  h += F(",capFull:");
  h += jsStr(T(STR_W_L_CAP_FULL));
  h += F(",capOver:");
  h += jsStr(T(STR_W_L_CAP_OVER));
  h += F(",gapS:");
  h += jsStr(T(STR_W_L_GAP_SPOOL));
  char lacks[64];
  snprintf(lacks, sizeof(lacks), T(STR_W_L_GAP_BACKEND), backendName());
  h += F(",gapB:");
  h += jsStr(lacks);
  h += F("};const QRB=");
  h += String((int)LF_QR);
  h += F(",IDB=");
  h += String((int)LF_SPOOL_ID);
  h += F(",BI1=");
  h += String((int)LABEL_PRESET_BIG_ID);
  h += F(",BI2=");
  h += String((int)LABEL_PRESET_BIG_ID_SIDE);
  h += F(",PB=");
  h += String(1u << LO_PORTRAIT);
  h += F(",DB=");
  h += String((int)LO_DATE_ADDED);
  // CSS pixels per millimetre of label in the preview.
  h += F(",PPM=8");
  h += F(";let S=null,shown='',timer=0,srcKey='',K=0;"
         "function bigId(p){return p===BI1||p===BI2;}"
         // The kind last looked at, per browser: a convenience, not state.
         "try{K=localStorage.getItem('lbkind')==='1'?1:0;}catch(e){}"
         "function q(){return '?kind='+K;}");
  scriptTemplate(h);
  h += F("function mask(box){let m=0;"
         "document.querySelectorAll('#'+box+' input').forEach(function(i){"
         "if(i.checked)m|=1<<(+i.dataset.b);});return m;}"
         "function setMask(box,m){document.querySelectorAll('#'+box+' input').forEach(function(i){"
         "i.checked=!!(m&(1<<(+i.dataset.b)));});}"
         // A FilaMan preset: the server's picture once it is in, else why not.
         "function srv(d){return d.source>0&&d.fm!=='absent';}"
         "function picServer(d){const m=$('lp-s');"
         "$('lp').parentNode.style.display=d.prev==='ready'?'':'none';"
         "if(d.prev==='ready'){const k='s|'+d.prevRev;if(k===shown)return;shown=k;"
         "m.textContent='';$('lp').src='/api/label/preview.bmp'+q()+'&t='+Date.now();return;}"
         "shown='';$('lp').removeAttribute('src');m.classList.toggle('bad',d.prev!=='loading');"
         "m.textContent=d.prev==='loading'?L.loading:(d.prevReason||(d.spool?L.fail:L.noSpool));}"
         // The picture is drawn anew only when something it shows changed.
         "function pic(d){if(srv(d)){picServer(d);return;}"
         "$('lp').parentNode.style.display='';$('lp-s').classList.add('bad');"
         "const k=[d.kind,d.preset,d.fields,d.options,d.idShare,d.text,d.spool?d.spool.id:0,"
         "d.dates,d.media,d.model].join('|');if(k===shown)return;shown=k;"
         "$('lp-s').textContent='';$('lp').src='/api/label/preview.bmp'+q()+'&t='+Date.now();}"
         // The source list, built anew only when the presets or the choice
         // changed; a preset the loaded roll cannot take is listed, not offered.
         "function srcRow(d){const on=!d.tape&&d.fm!=='absent'&&d.fm!=='unknown';"
         "$('lsrcf').style.display=on?'':'none';"
         // Our own status line only: a "saved" flashed there stays until it fades.
         "const m=$('lsrc-s'),t=d.fm==='loading'?L.srcLoading:(d.fm==='failed'?L.srcFailed:'');"
         "if(t||m.dataset.st)m.textContent=t;m.dataset.st=t;"
         "$('ltpl').style.display=srv(d)?'none':'';$('lsrv').style.display=srv(d)?'':'none';"
         "$('ltpl').disabled=!!d.tape;$('ltp').style.display=d.tape?'':'none';"
         "const k=d.source+'|'+JSON.stringify(d.presets);if(k===srcKey)return;srcKey=k;"
         "const b=$('lsrc');b.textContent='';"
         "[{id:0,name:L.scale,fit:true}].concat(d.presets).forEach(function(p){"
         "const o=document.createElement('option');o.value=String(p.id);"
         "o.textContent=p.name+(p.rotated?' \u00b7 '+L.rotated:(p.fit?'':' \u00b7 '+p.size));"
         "o.disabled=!p.fit&&p.id!==d.source;"
         "b.appendChild(o);});b.value=String(d.source);}"
         "function paint(d){S=d;srcRow(d);tiles(d);"
         "setMask('lf',d.fields);setMask('lo',d.options);capRow(d);"
         "if(document.activeElement!==$('ltx'))$('ltx').value=d.text;"
         "$('lsp').textContent=d.spool?(d.spool.text+' \u00b7 #'+d.spool.id+(d.spool.on?'':' '+L.offPad)):'-';"
         "$('lme').textContent=d.options&PB&&!d.tape?L.upright:'';"
         "$('ldpi').textContent=d.dpi+' dpi';"
         "if(document.activeElement!==$('lpm'))$('lpm').value=String(d.modelId);"
         // Only the sizes the picked model takes; disabled as well, for the
         // browsers that ignore hidden on an option.
         "$('lps').querySelectorAll('option[data-fit]').forEach(function(o){"
         "o.hidden=o.disabled=o.dataset.fit.split(' ').indexOf(String(d.modelId))<0;});"
         "if(document.activeElement!==$('lps'))$('lps').value=d.mediaKey;"
         "$('lsa').style.display=d.spool||srv(d)?'none':'';"
         "$('lnp').style.display=d.configured?'none':'';"
         "$('lpb').disabled=!d.spool||!d.canPrint;"
         "$('ll').textContent=(d.lastPrint||'')+(d.lastReason?' ('+d.lastReason+')':'');"
         "$('llr').style.display=d.lastPrint?'':'none';"
         "pic(d);"
         // The dates come from the server a moment later; a new spool on the
         // pad shows up on the next look.
         "const busy=!d.dates||d.fm==='loading'||d.prev==='loading';"
         "clearTimeout(timer);timer=setTimeout(load,busy?1500:5000);}"
         "function load(){if(document.hidden)return;"
         "getJson('/api/label'+q()).then(function(d){if(d&&d.kind===K)paint(d);});}"
         "function save(p,f,o){"
         "postFlash('/api/label'+q(),p+','+f+','+o+','+S.idSet,'ls-s',2500).then(load);}");
}

// Every handler is bound here rather than written into an onclick
// attribute: a page body is JavaScript inside a C++ string literal, and an
// attribute is the one place where the two levels of quoting collide.
static void scriptBindings(String& h) {
  h += F("document.querySelectorAll('#lpre .btab').forEach(function(b){"
         "b.addEventListener('click',function(){if(S)save(+b.dataset.p,S.fields,S.options);});});"
         "document.querySelectorAll('#lkind .btab').forEach(function(b){"
         "b.addEventListener('click',function(){K=+b.dataset.k;"
         "try{localStorage.setItem('lbkind',String(K));}catch(e){}shown='';srcKey='';load();});});"
         "document.querySelectorAll('#lori .btab').forEach(function(b){"
         "b.addEventListener('click',function(){if(S)save(S.preset,S.fields,"
         "(S.options&~PB)|(+b.dataset.o?PB:0));});});"
         "document.querySelectorAll('#lf input,#lo input').forEach(function(i){"
         "i.addEventListener('change',function(){if(!S)return;capRow(S);save(S.preset,mask('lf'),opts());});});"
         "$('lis').addEventListener('input',function(){$('lisv').textContent=$('lis').value+' %';});"
         "$('lis').addEventListener('change',function(){if(!S)return;S.idSet=+$('lis').value;"
         "save(S.preset,S.fields,S.options);});"
         "$('lpm').addEventListener('change',function(){"
         "postFlash('/api/printer/model',$('lpm').value,'lpm-s',2500).then(load);});"
         "$('lps').addEventListener('change',function(){"
         "postFlash('/api/printer/media',$('lps').value,'lps-s',2500).then(load);});"
         "$('ltx').addEventListener('change',function(){"
         "postFlash('/api/label/text',$('ltx').value,'ltx-s',2500).then(load);});"
         "$('lr').addEventListener('click',function(){postFlash('/api/label/reset'+q(),'','ls-s',2500).then(load);});"
         "$('lsrc').addEventListener('change',function(){"
         "postFlash('/api/label/source',$('lsrc').value,'lsrc-s',2500).then(load);});"
         "$('lp').addEventListener('error',function(){$('lp-s').textContent=L.fail;shown='';});"
         "$('lp').addEventListener('load',function(){var i=$('lp');"
         "if(S&&S.dpi)i.style.width=Math.round(i.naturalWidth*PPM*25.4/S.dpi)+'px';"
         // Hard dot edges only where every dot becomes a whole number of
         // screen pixels; at any other factor they come out uneven.
         "var f=i.clientWidth*(window.devicePixelRatio||1)/i.naturalWidth;"
         "i.style.imageRendering=f>=1&&Math.abs(f-Math.round(f))<0.05?'pixelated':'auto';});"
         // The print takes about ten seconds on the scale; the verdict is
         // fetched after that and shown on the last line.
         "$('lpb').addEventListener('click',function(){"
         "postFlash('/api/label/print'+q(),'','lpb-s',4000).then(function(){setTimeout(load,12000);});});"
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

// A raster's label part, from dot x0 on, as a 1-bit BMP; an upright label
// turned back so it reads as it will on the spool.
static void sendRasterBmp(WebServer& srv, const LabelRaster& r, uint16_t x0, bool upright) {
  const uint16_t w = upright ? r.height : r.content_width;
  const uint16_t h = upright ? r.content_width : r.height;
  const uint32_t row = labelBmpRowBytes(w);
  const uint32_t bytes = labelBmpFileBytes(w, h);
  uint8_t* bmp = (uint8_t*)heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM);
  if (!bmp) {
    logSD("Web: no PSRAM for the label preview");
    srv.send(503, "text/plain", T(STR_W_L_PREVIEW_FAIL));
    return;
  }
  labelBmpHeader(w, h, bmp);
  for (uint16_t y = 0; y < h; y++) {
    uint8_t* out = bmp + LABEL_BMP_HEADER_BYTES + size_t(y) * row;
    if (upright) labelBmpRowUpright(r, x0, r.content_width, y, out);
    else labelBmpRow(r, x0, w, y, out);
  }
  srv.sendHeader("Cache-Control", "no-store");
  srv.setContentLength(bytes);
  srv.send(200, "image/bmp", "");
  srv.sendContent((const char*)bmp, bytes);
  heap_caps_free(bmp);
}

// The server's label for the last spool: in hand, on its way, or refused.
// The server draws it at the row's left edge.
static void sendServerPreview(WebServer& srv, const LabelPrinterConfig& c) {
  SpoolLabelData spool{};
  const int id = labelSpoolLast(&spool) ? spool.id : 0;
  // The picture the state route announced, even when it has just grown old
  // enough to be fetched again: the page asks for it right after.
  const LabelRaster* in_hand = labelServerPreviewInHand(c, id);
  if (in_hand) {
    sendRasterBmp(srv, *in_hand, 0, false);
    return;
  }
  const LabelRaster* r = nullptr;
  const char* reason = "";
  switch (labelServerPreview(c, id, &r, &reason)) {
    case LSP_READY:
      sendRasterBmp(srv, *r, 0, false);
      return;
    case LSP_LOADING:
      srv.send(202, "text/plain", T(STR_W_L_PREVIEW_LOADING));
      return;
    default:
      srv.send(409, "text/plain",
               reason[0] ? reason : T(id ? STR_W_L_PREVIEW_FAIL : STR_W_L_SRC_NO_SPOOL));
  }
}

// The label as the printer would get it, cut to the label, as a 1-bit BMP.
static void sendPreview(WebServer& srv, LabelKind kind) {
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  if (kind == LABEL_KIND_SPOOL && labelServerInUse()) {
    sendServerPreview(srv, c);
    return;
  }
  SpoolLabelData spool{};
  if (!labelSpoolLast(&spool)) sampleSpool(&spool);
  const LabelLayout layout = labelLayoutLoad(kind);
  LabelRaster r{};
  const bool ok = kind == LABEL_KIND_FILAMENT ? labelRenderFilament(c, layout, spool, &r)
                                              : labelRenderSpool(c, layout, spool, &r);
  if (!ok) {
    labelRasterFree(&r);
    srv.send(409, "text/plain", T(STR_W_L_PREVIEW_FAIL));
    return;
  }
  sendRasterBmp(srv, r, labelPrinterContentX(c),
                labelLayoutOption(layout, LO_PORTRAIT) || labelPrinterIsTape(c.model));
  labelRasterFree(&r);
}

// "preset,fields,options,id_share" as numbers; anything unknown in them is
// dropped, and without the last the arrangement's own share applies.
static bool parseLayout(const String& v, LabelLayout* out) {
  const int a = v.indexOf(',');
  const int b = a < 0 ? -1 : v.indexOf(',', a + 1);
  if (a <= 0 || b <= a) return false;
  LabelLayout l{};
  l.preset = (uint8_t)strtoul(v.c_str(), nullptr, 10);
  l.fields = strtoul(v.c_str() + a + 1, nullptr, 10);
  l.options = strtoul(v.c_str() + b + 1, nullptr, 10);
  const int c = v.indexOf(',', b + 1);
  if (c > b) l.id_share = (uint8_t)strtoul(v.c_str() + c + 1, nullptr, 10);
  *out = labelLayoutSanitized(l);
  return true;
}

static void routes(WebServer &srv) {
  srv.on("/api/label", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LABEL))) return;
    srv.send(200, "application/json", stateJson(kindOf(srv)));
  });

  srv.on("/api/label", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LABEL))) return;
    LabelLayout l{};
    if (!parseLayout(srv.arg("plain"), &l)) { srv.send(400, "text/plain", "bad layout"); return; }
    const bool ok = labelLayoutSave(l, kindOf(srv));
    srv.send(ok ? 200 : 500, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
  });

  srv.on("/api/label/reset", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LABEL))) return;
    const LabelKind kind = kindOf(srv);
    const bool ok = labelLayoutSave(labelLayoutDefault(kind), kind);
    srv.send(ok ? 200 : 500, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
  });

  // The own line, as typed; the store cuts it to its buffer.
  srv.on("/api/label/text", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LABEL))) return;
    const String v = srv.arg("plain");
    if (v.length() >= LABEL_FREE_TEXT_BYTES * 2) { srv.send(400, "text/plain", "text too long"); return; }
    const bool ok = labelLayoutSaveFreeText(v.c_str());
    srv.send(ok ? 200 : 500, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
  });

  // The source: 0 for the scale's own layout, else a FilaMan preset's id.
  srv.on("/api/label/source", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LABEL))) return;
    const String v = srv.arg("plain");
    char* end = nullptr;
    const long id = strtol(v.c_str(), &end, 10);
    if (v.isEmpty() || *end || id < 0 || id > INT32_MAX) {
      srv.send(400, "text/plain", "bad source");
      return;
    }
    const bool ok = labelServerSetPresetId((int)id);
    srv.send(ok ? 200 : 500, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
  });

  srv.on("/api/label/preview.bmp", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LABEL))) return;
    sendPreview(srv, kindOf(srv));
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
    const LabelKind kind = kindOf(srv);
    if (kind == LABEL_KIND_FILAMENT) print_last_filament_label_pending = true;
    else print_last_label_pending = true;
    logSDf("Web: %s label print for spool #%d requested",
           kind == LABEL_KIND_FILAMENT ? "filament" : "spool", s.id);
    srv.send(200, "text/plain", T(STR_W_P_QUEUED));
  });
}

extern const WebPage PAGE_LABEL;
const WebPage PAGE_LABEL = {
  "/label", label, GATE_CONFIG, nullptr,
  body, routes
};
