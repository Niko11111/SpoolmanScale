#include "web/web_printer_cards.h"

#include <string.h>

#include "app_config.h"
#include "services/printer_names.h"
#include "web/web_printer_select.h"

// Last on purpose: T() is a macro, see the pages.
#include "lang.h"

// A label outline on its card: the largest roll, 50 x 50 mm, comes out
// 75 px and still fits two cards side by side on a phone.
#define STOCK_SHAPE_PX_PER_MM 1.5f

// One literal in flash, like the shared stylesheet.
static const char PRINTER_CSS[] PROGMEM =
         "<style>"
         // The Bluetooth bar: a row across the page instead of a card that
         // stood as tall as the printer list beside it.
         ".btbar{grid-column:1/-1;display:flex;align-items:center;gap:14px;padding:12px 18px;"
         "border-radius:14px;background:var(--surface);border:1px solid var(--line-soft)}"
         ".btbar .ic{flex:0 0 34px;height:34px;border-radius:10px;display:grid;place-items:center;"
         "background:var(--surface-2);border:1px solid var(--line-soft);color:var(--ink-3)}"
         ".btbar.live .ic{color:var(--accent);background:var(--accent-dim);border-color:var(--accent-line)}"
         ".btbar.need{border-color:var(--warn-line);background:var(--warn-bg)}"
         ".btbar .tx{flex:1;min-width:0;display:flex;flex-direction:column}"
         ".btbar .tx strong{font-size:14px;font-weight:600;color:var(--ink)}"
         ".btbar .tx>span{font-size:12px;color:var(--ink-soft);line-height:1.45}"
         ".btbar .end{display:flex;align-items:center;gap:10px}"
         ".btbar .end button{padding:6px 12px;font-size:12.5px}"
         // The new message lines take no room until they say something; the
         // calibration card's keep theirs, its spacing counts on them.
         "#bl-s:empty,#rb-s:empty,#pd-s:empty,#dv-s:empty,#pm-s:empty,#ps-s:empty,#tb-s:empty{display:none}"
         // The device tile: the printer, or a dashed place for one.
         ".dev{display:flex;align-items:center;gap:14px;padding:14px 16px;border-radius:12px;"
         "background:var(--surface-2);border:1px solid var(--line-soft)}"
         ".dev .ic{flex:0 0 44px;height:44px;border-radius:11px;display:grid;place-items:center;"
         "background:var(--accent-dim);border:1px solid var(--accent-line);color:var(--accent)}"
         ".dev .tx{flex:1;min-width:0;display:flex;flex-direction:column;gap:2px}"
         ".dev .nm{font-size:15px;font-weight:600;color:var(--ink);overflow-wrap:anywhere}"
         ".dev .sub{font-family:var(--mono);font-size:12px;color:var(--ink-soft)}"
         ".dev .end{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}"
         ".dev.empty{border-style:dashed;border-color:var(--line);background:transparent}"
         ".dev.empty .ic{background:var(--surface-2);border-color:var(--line);color:var(--ink-3)}"
         ".dev.empty .nm{font-weight:500;color:var(--ink-2)}"
         ".dev.empty .sub{font-family:var(--sans)}"
         "button.ghost{background:transparent;color:var(--ink-soft);border-color:transparent;padding:9px 10px}"
         "button.ghost:hover{background:var(--quiet);color:var(--bad)}"
         // The scan: a panel under the tile while it runs and after.
         ".scan{margin-top:10px;border-radius:12px;border:1px solid var(--line-soft);overflow:hidden}"
         ".scan-h{padding:10px 14px;font-size:13px;color:var(--ink-2);background:var(--surface-2)}"
         ".scan-bar{height:3px;background:var(--line-soft)}"
         ".scan-bar i{display:block;height:100%;width:0;background:var(--accent);animation:scanfill 5s linear forwards}"
         "@keyframes scanfill{to{width:100%}}"
         ".scan .emp{padding:14px;font-size:13px;color:var(--ink-soft)}"
         ".drow{display:flex;align-items:center;gap:12px;padding:10px 14px;border-top:1px solid var(--line-soft)}"
         ".drow .nm{flex:1;min-width:0;font-size:14px;color:var(--ink-2);overflow-wrap:anywhere}"
         ".drow .nm small{display:block;font-family:var(--mono);font-size:11.5px;color:var(--ink-soft)}"
         ".drow.mine{background:var(--accent-dim)}"
         ".drow button{padding:6px 12px;font-size:12.5px}"
         ".scan details.more{border-top:1px solid var(--line-soft)}"
         ".scan details.more>summary{padding:8px 14px}"
         // The card pickers. A card is a button, so it undoes the button look.
         ".sect{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin:22px 0 10px}"
         ".sect h3{font-size:13px;font-weight:600;color:var(--ink-2)}"
         ".sect .hint{text-align:right}"
         ".pick{display:grid;gap:8px}"
         ".pc{position:relative;text-align:left;white-space:normal;font-weight:400;"
         "padding:9px 12px 10px;border-radius:11px;background:var(--surface-2);"
         "border:1px solid var(--line-soft);color:var(--ink-2)}"
         ".pc:hover{background:var(--quiet-hover);border-color:var(--line)}"
         ".pc.on{background:var(--accent-dim);border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}"
         ".pc.on .mn{color:var(--accent)}"
         ".pc:disabled{opacity:.42}"
         ".pc:disabled:hover{background:var(--surface-2);border-color:var(--line-soft)}"
         ".pc.on:after{content:'\\2713';width:18px;height:18px;border-radius:50%;display:grid;place-items:center;"
         "background:var(--accent);color:var(--ground);font-size:11px;font-weight:700}"
         ".pc .mn{font-size:15px;font-weight:600;color:var(--ink)}"
         ".pill.ex{color:var(--ink-soft);border-color:var(--line);background:var(--surface)}"
         // Models: the chosen one as a row, the recommended as cards, the
         // rest as compact rows under a fold, two columns of them on a desk.
         ".models{display:flex;flex-direction:column;gap:16px}"
         ".models .br,.models .gh{font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-soft)}"
         ".models .gh{font-size:11px}"
         ".models .sp{font-family:var(--mono);font-size:11.5px;color:var(--ink-soft)}"
         ".models .tg{font-size:10.5px;padding:1px 7px;gap:5px}"
         ".models .tg:before{width:5px;height:5px}"
         ".mcur{display:flex;align-items:center;gap:14px;padding:12px 14px;border-radius:12px;"
         "background:var(--surface-2);border:1px solid var(--line-soft)}"
         ".mcur .tx{flex:1;min-width:0;display:flex;flex-direction:column;gap:2px}"
         ".mcur .nl{display:flex;align-items:center;flex-wrap:wrap;gap:8px}"
         ".mcur .mn{font-size:16px;font-weight:600;color:var(--ink)}"
         "#pmp{display:flex;flex-direction:column;gap:16px}"
         ".recs{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:8px 16px}"
         ".rc{display:flex;flex-direction:column;gap:4px}"
         // A card is a button, so the link to the shop sits under it.
         ".rcd{display:grid;grid-template-columns:1fr auto;grid-template-areas:'br tg' 'mn ck' 'wy wy' 'sp sp';"
         "row-gap:3px;column-gap:8px;align-items:center;padding:10px 12px 12px}"
         ".rcd .br{grid-area:br;line-height:17px}.rcd .tg{grid-area:tg}.rcd .sp{grid-area:sp}"
         ".rcd .mn{grid-area:mn;font-size:16px}"
         ".rcd .wy{grid-area:wy;font-size:13px;color:var(--ink-2)}"
         ".rcd.on:after{grid-area:ck;justify-self:end}"
         ".buy{align-self:flex-start;display:inline-flex;align-items:center;min-height:36px;padding:0 4px;"
         "font-size:13px;color:var(--accent);text-decoration:none}"
         ".buy:hover{text-decoration:underline}"
         // Shop links are for someone still choosing a printer.
         ".models.has .buy{display:none}"
         // The fold's line with a chevron of its own: as a flex box the
         // summary loses the browser's triangle.
         "#pmf>summary{display:flex;align-items:center;gap:10px;min-height:40px;padding:0;list-style:none}"
         "#pmf>summary::-webkit-details-marker{display:none}"
         "#pmf>summary:before{content:'';width:6px;height:6px;margin-left:2px;"
         "border-right:2px solid var(--ink-3);border-bottom:2px solid var(--ink-3);transform:rotate(-45deg)}"
         "#pmf[open]>summary:before{transform:rotate(45deg)}"
         ".grp{display:flex;flex-direction:column;gap:6px;margin-top:12px}"
         ".mrows{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px 8px}"
         // The tag right after the name, the spec against the right edge, so
         // the specs line up whether a row is tagged or not.
         ".mrow{display:grid;grid-template-columns:minmax(0,auto) auto 1fr 18px;grid-template-areas:'mn tg sp ck';"
         "column-gap:10px;align-items:center;min-height:44px;padding:6px 12px}"
         ".mrow .mn{grid-area:mn}.mrow .tg{grid-area:tg}"
         ".mrow .sp{grid-area:sp;white-space:nowrap;justify-self:end}"
         // The tick's place is kept, so the row does not shift when picked.
         ".mrow:after{content:'';grid-area:ck;width:18px;height:18px}"
         // A model in a name that nobody has printed on yet: quieter, and
         // marked with a short tag right after it.
         ".ux{color:var(--ink-soft);font-weight:500}"
         ".pill.xs{font-size:10px;padding:0 5px;margin-left:5px;vertical-align:1px}"
         ".pill.xs:before{display:none}"
         // Stock: the outline to scale over its size.
         ".stock{grid-template-columns:repeat(auto-fill,minmax(150px,1fr))}"
         ".stock .pc{display:flex;flex-direction:column;align-items:center;gap:8px;padding:14px 10px 12px}"
         ".stock .shape{border:1.5px solid var(--ink-3);border-radius:4px;background:var(--surface)}"
         ".stock .pc.on .shape{border-color:var(--accent);background:var(--btn)}"
         ".stock .pc .mn{font-size:14px}"
         ".stock .nb{font-size:11.5px;color:var(--ink-soft)}"
         ".stock .pc.on:after{position:absolute;right:10px;top:10px}"
         // What the model prints with, warm where heat colours the label.
         ".method{margin-top:10px;padding:10px 12px;border-radius:10px;background:var(--surface-2);"
         "font-size:12.5px;color:var(--ink-soft);line-height:1.5}"
         ".method.warm{background:var(--warn-bg);border:1px solid var(--warn-line)}"
         ".pr-foot{display:block;margin-top:10px}.pr-foot a{color:var(--accent)}"
         ".reclink{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:10px;"
         "padding:10px 14px;border-radius:10px;border:1px solid var(--accent-line);background:var(--accent-dim);"
         "font-size:13px;color:var(--ink-2)}"
         ".reclink a{color:var(--accent);font-weight:600;text-decoration:none;white-space:nowrap}"
         ".testrow{display:flex;align-items:center;gap:14px;margin-top:22px;padding-top:18px;"
         "border-top:1px solid var(--line-soft)}"
         ".testrow .hint{flex:1}"
         // The print position card: the strip, the stepper, and the example.
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
         "@media(max-width:620px){"
         ".btbar{flex-wrap:wrap}.btbar .end{width:100%;justify-content:flex-end}"
         ".dev{flex-wrap:wrap}.dev .end{width:100%}"
         ".sect{flex-direction:column;align-items:flex-start;gap:2px}.sect .hint{text-align:left}"
         ".stock{grid-template-columns:1fr 1fr}"
         ".mrows{grid-template-columns:1fr}"
         ".mrow{grid-template-columns:minmax(0,1fr) auto 18px;grid-template-areas:'mn tg ck' 'sp tg ck';"
         "row-gap:2px;min-height:56px}"
         ".mrow .sp{justify-self:start}"
         ".buy{min-height:44px}"
         ".reclink{flex-direction:column;align-items:flex-start;gap:4px}"
         ".testrow{flex-direction:column;align-items:stretch}}"
         "</style>";

void webPrinterPageStyle(String& h) { h += FPSTR(PRINTER_CSS); }

const __FlashStringHelper* webPrinterDocsUrl() {
  return g_lang == LANG_DE ? F(DOCS_URL "de/use/printers/") : F(DOCS_URL "use/printers/");
}

// Why a recommended model, and where in the manual it is sold.
struct RecommendedCard { LabelPrinterModel model; int why; const char* anchor; };
static const RecommendedCard RECOMMENDED_CARDS[] = {
  { LP_MODEL_M220,       STR_W_P_WHY_M220, DOCS_ANCHOR_M220 },
  { LP_MODEL_NIIMBOT_M2, STR_W_P_WHY_M2,   DOCS_ANCHOR_M2 },
};

static const RecommendedCard* recommendedCard(LabelPrinterModel m) {
  for (const RecommendedCard& r : RECOMMENDED_CARDS)
    if (r.model == m) return &r;
  return nullptr;
}

// The table holds a dozen models; the fold's lists are sized for more.
#define PICKER_MODELS_MAX 32
// Room for one model out of a profile's name, "PM245-BT" and longer.
#define PICKER_MODEL_NAME_LEN 32

struct NameOut { String* h; int count; };

static void appendModel(const char* model, size_t len, bool untried, void* ctx) {
  NameOut& o = *static_cast<NameOut*>(ctx);
  char one[PICKER_MODEL_NAME_LEN];
  snprintf(one, sizeof(one), "%.*s", (int)len, model);
  if (o.count++) *o.h += F(PRINTER_NAME_SEPARATOR);
  if (!untried) { *o.h += one; return; }
  *o.h += F("<span class='ux'>");
  *o.h += one;
  *o.h += F("</span><span class='pill ex xs' title='");
  *o.h += T(STR_PRN_TAG_EXPERIMENTAL);
  *o.h += F("'>");
  *o.h += T(STR_PRN_TAG_UNTRIED_SHORT);
  *o.h += F("</span>");
}

// The name, each model in it that nobody has printed on yet marked apart.
static void modelName(String& h, const LabelPrinterProfile& p) {
  NameOut o = { &h, 0 };
  h += F("<span class='mn'>");
  printerNameEach(p.name, p.untried, appendModel, &o);
  h += F("</span>");
}

static void modelSpec(String& h, const LabelPrinterProfile& p) {
  h += F("<span class='sp'>");
  if (p.min_width_mm != p.max_width_mm) { h += String(p.min_width_mm); h += '-'; }
  h += String(p.max_width_mm);
  h += F(" mm &middot; ");
  h += String(p.dpi);
  h += F(" dpi");
  if (!p.direct_thermal) { h += F(" &middot; "); h += T(STR_W_P_SPEC_RIBBON); }
  h += F("</span>");
}

static void modelButton(String& h, const LabelPrinterProfile& p, const LabelPrinterConfig& c,
                        const __FlashStringHelper* look) {
  const bool on = p.model == c.model;
  h += F("<button type='button' class='pc ");
  h += look;
  if (on) h += F(" on");
  h += F("' aria-pressed='");
  h += on ? F("true") : F("false");
  h += F("' data-m='");
  h += String((int)p.model);
  h += F("' data-b='");
  h += p.brand;
  h += F("' data-n='");
  h += p.name;
  h += F("'>");
}

static void recommendedModel(String& h, const LabelPrinterProfile& p, const LabelPrinterConfig& c) {
  const RecommendedCard* r = recommendedCard(p.model);
  h += F("<div class='rc'>");
  modelButton(h, p, c, F("rcd"));
  h += F("<span class='br'>");
  h += p.brand;
  h += F("</span><span class='pill ok tg'>");
  h += T(STR_PRN_TAG_RECOMMENDED);
  h += F("</span>");
  modelName(h, p);
  if (r) { h += F("<span class='wy'>"); h += T(r->why); h += F("</span>"); }
  modelSpec(h, p);
  h += F("</button>");
  if (r) {
    h += F("<a class='buy' href='");
    h += webPrinterDocsUrl();
    h += r->anchor;
    h += F("' target='_blank' rel='noopener'>");
    h += T(STR_W_P_BUY_LINK);
    h += F(" &rarr;</a>");
  }
  h += F("</div>");
}

static void foldedModel(String& h, const LabelPrinterProfile& p, const LabelPrinterConfig& c) {
  modelButton(h, p, c, F("mrow"));
  modelName(h, p);
  modelSpec(h, p);
  if (p.experimental) {
    h += F("<span class='pill ex tg'>");
    h += T(STR_PRN_TAG_EXPERIMENTAL);
    h += F("</span>");
  }
  h += F("</button>");
}

// The models that are not recommended, by brand and then by name: the
// table's own order is the display's and mixes the brands.
static int restSorted(const LabelPrinterProfile** out) {
  const char* brands[PICKER_MODELS_MAX];
  const char* names[PICKER_MODELS_MAX];
  const LabelPrinterProfile* rest[PICKER_MODELS_MAX];
  int n = 0;
  for (int i = 0; i < LABEL_PRINTER_MODEL_COUNT && n < PICKER_MODELS_MAX; i++) {
    const LabelPrinterProfile& p = labelPrinterProfile(LABEL_PRINTER_MODELS[i]);
    if (labelPrinterRecommended(p.model)) continue;
    rest[n] = &p;
    brands[n] = p.brand;
    names[n] = p.name;
    n++;
  }
  int order[PICKER_MODELS_MAX];
  printerSortByBrand(brands, names, order, n);
  for (int i = 0; i < n; i++) out[i] = rest[order[i]];
  return n;
}

// Starts open when the current model is in it, so the mark is in sight.
static void moreModels(String& h, const LabelPrinterConfig& c) {
  const LabelPrinterProfile* rest[PICKER_MODELS_MAX];
  const int n = restSorted(rest);
  h += F("<details class='more' id='pmf'");
  if (!labelPrinterRecommended(c.model)) h += F(" open");
  h += F("><summary>");
  char line[64];
  snprintf(line, sizeof(line), T(STR_W_P_MORE_MODELS_FMT), n);
  h += line;
  h += F("</summary>");
  const char* brand = nullptr;
  for (int i = 0; i < n; i++) {
    if (!brand || strcmp(brand, rest[i]->brand) != 0) {
      if (brand) h += F("</div></div>");
      brand = rest[i]->brand;
      h += F("<div class='grp'><span class='gh'>");
      h += brand;
      h += F("</span><div class='mrows'>");
    }
    foldedModel(h, *rest[i], c);
  }
  if (brand) h += F("</div></div>");
  h += F("</details>");
}

// Filled by the page's script from the marked card, so the two never
// disagree.
static void currentModel(String& h, bool have) {
  h += F("<div class='mcur' id='pmc'");
  if (!have) h += F(" style='display:none'");
  h += F("><div class='tx'><span class='br' id='pcb'></span><span class='nl' id='pcn'></span>"
         "<span class='sp' id='pcs'></span></div>"
         "<button type='button' class='quiet' id='pmb' aria-expanded='false' aria-controls='pmp'>");
  h += T(STR_W_P_CHANGE_MODEL);
  h += F("</button></div>");
}

void webPrinterModelPicker(String& h, const LabelPrinterConfig& c) {
  const bool have = labelPrinterConfigured(c);
  h += F("<div class='models");
  if (have) h += F(" has");
  h += F("' id='pm'>");
  currentModel(h, have);
  h += F("<div id='pmp'");
  if (have) h += F(" style='display:none'");
  h += F("><div class='recs'>");
  for (int i = 0; i < LABEL_PRINTER_MODEL_COUNT; i++) {
    const LabelPrinterProfile& p = labelPrinterProfile(LABEL_PRINTER_MODELS[i]);
    if (labelPrinterRecommended(p.model)) recommendedModel(h, p, c);
  }
  h += F("</div>");
  moreModels(h, c);
  h += F("</div></div>");
}

// How a size stands in the list: one to pick, one on sale that no layout
// fits yet (greyed, with its reason), or one kept from elsewhere and not in
// the table (marked, not offered again).
enum StockKind { STOCK_OFFERED, STOCK_PLANNED, STOCK_KEPT };

// A size the picked model cannot take starts hidden; the script shows the
// fitting ones whenever the model changes.
static void stockCard(String& h, const LabelMediaSize& s, const LabelPrinterConfig& c, StockKind kind) {
  const bool on = s.width_mm == c.media_width_mm && s.length_mm == c.media_length_mm;
  h += F("<button type='button' class='pc");
  if (on) h += F(" on");
  h += F("' data-v='");
  h += String(s.width_mm); h += 'x'; h += String(s.length_mm);
  h += F("' data-fit='");
  webPrinterFitList(h, s.width_mm, s.length_mm);
  h += F("'");
  if (!labelPrinterTakesMedia(c.model, s.width_mm, s.length_mm)) h += F(" style='display:none'");
  if (kind != STOCK_OFFERED) h += F(" disabled");
  h += F("><span class='shape' style='width:");
  h += String((int)(s.width_mm * STOCK_SHAPE_PX_PER_MM));
  h += F("px;height:");
  h += String((int)(s.length_mm * STOCK_SHAPE_PX_PER_MM));
  h += F("px'></span><span class='mn'>");
  char size[24];
  snprintf(size, sizeof(size), T(STR_PRN_MEDIA_FMT), (unsigned)s.width_mm, (unsigned)s.length_mm);
  h += size;
  h += F("</span>");
  if (kind == STOCK_PLANNED) {
    h += F("<span class='nb'>");
    h += T(STR_PRN_MEDIA_NO_LAYOUT);
    h += F("</span>");
  }
  h += F("</button>");
}

void webPrinterStockCards(String& h, const LabelPrinterConfig& c) {
  bool listed = false;
  for (int i = 0; i < LABEL_MEDIA_SIZE_COUNT; i++) {
    const LabelMediaSize& s = LABEL_MEDIA_SIZES[i];
    listed = listed || (s.width_mm == c.media_width_mm && s.length_mm == c.media_length_mm);
    stockCard(h, s, c, STOCK_OFFERED);
  }
  if (!listed) {
    const LabelMediaSize kept = { (uint8_t)c.media_width_mm, (uint8_t)c.media_length_mm };
    stockCard(h, kept, c, STOCK_KEPT);
  }
  for (int i = 0; i < LABEL_MEDIA_PLANNED_COUNT; i++)
    stockCard(h, LABEL_MEDIA_SIZES_PLANNED[i], c, STOCK_PLANNED);
}
