#include "services/label_render.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>

#include "app_config.h"
#include "app/label_link.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/backend.h"
#include "services/accent_fold.h"
#include "services/label_big_id.h"
#include "services/label_draw.h"
#include "services/label_facts.h"
#include "services/label_logo.h"
#include "services/label_tape.h"
#include "services/text_util.h"

using namespace labeldraw;


// The label's geometry in dots at 203 dpi, 8 dots to the millimetre, and its
// fonts at that resolution. A finer head prints the same millimetres: every
// length goes through dots() and every font through sized() (label_draw.h).
#define LR_MARGIN_PX       8    // 1 mm: the stock is never cut exactly
#define LR_GAP_PX          4    // between the blocks
#define LR_COLUMN_GAP_PX  12    // between two columns of facts
// The blocks grow with the roll. 40 x 30 is the base; from LR_TALL_PX in
// both directions the band, the fonts and the fact lines take the larger sizes.
#define LR_TALL_PX       300
#define LR_BAND_H_PX      32    // the material band on the base size, 24 px in it
#define LR_BAND_FONT      (&lv_font_montserrat_ext_24)
#define LR_BAND_THICK_X    1    // extra dots of white across, on the black band
#define LR_BAND_THICK_Y    1    // and down
#define LR_BAND_H_TALL_PX 40
#define LR_BAND_H_BIG_PX  60    // the material-first band, a quarter of 30 mm
#define LR_BAND_INSET_PX   3    // the band's line, from its left end
#define LR_LOGO_BOX_H_PX  40    // the maker's mark, 5 mm across the top
#define LR_LOGO_BOX_TALL_PX 48
#define LR_FACT_LINE_PX   22    // one fact line in the 16 px font
#define LR_FACT_LINE_TALL_PX 28 // one in the 20 px font
#define LR_FACT_LINE_SMALL_PX 19 // one in the 14 px font, next to a big code
#define LR_FACTS_MIN_W   130    // the facts keep this much next to a code
#define LR_QR_MAX_MM      25    // 200 dots at 203 dpi: larger reads no better
#define LR_QR_SMALL_MM    13    // the material-first code: a spool URL at 3 dots
#define LR_QR_MIN_PX      64
#define LR_WRAP_ROWS       4    // what a wrapped paragraph is sized for
#define LR_QR_GOOD_PX     96    // under this, smaller fact lines buy code size
// The calibration page's ruler, in dots from the top of the label.
#define LC_NUM_Y          12    // the numbers' row, and the top of their ticks
#define LC_NUM_EVERY       4    // a number every 4 mm
#define LC_NUM_GAP         2    // from a tick to its number
#define LC_NUM_W          28    // "-12" in 16 px: the rest of the 4 mm to the next
#define LC_NUM_EXTRA       3    // numbers past where the edge can be, each side
#define LC_BASE_Y         44    // the ruler's line; the ticks stand on it
#define LC_BASE_PX         2
#define LC_TICK_PX         2
#define LC_TICK_MM         6    // every millimetre
#define LC_TICK_2MM       12    // every second one
#define LC_BOX_GAP        12    // from the ruler to the frame
#define LC_FRAME_PX        3
#define LC_TEXT_GAP       14    // from the frame's top to the first line

void labelRasterFree(LabelRaster* image) {
  if (!image) return;
  free(image->pixels);
  *image = LabelRaster{};
}

// What one label carries besides its layout: the header from `d`, under it
// `lines` in small type next to the code, or, with `wrap`, lines[0] as one
// paragraph wrapped into that column. No code without `qr`. `what` names the
// label in the log. With `facts`, the same n lines as caption and value, so
// the body can set them in two lines where the room allows.
struct LabelContent {
  const SpoolLabelData* d;
  const char* const* lines;
  int n;
  bool wrap;
  const char* qr;
  const char* what;
  const LabelFact* facts;
};

// The part of the canvas the blocks are laid into, in dots, and how the code
// shares it: its largest edge, and whether the text next to it keeps the
// width of its widest line. The standard arrangement gives the code all it
// can (and a long date line a cut); the others keep the text whole.
struct LabelArea {
  lv_coord_t x, y, w, bottom;
  lv_coord_t qr_max;
  bool keep_text;
  const lv_font_t* facts_font;   // null: by the label's size
  bool columns;                  // the facts may stand in two columns
  // A name one line would cut goes on two in this font; null: it is cut.
  const lv_font_t* wrap_font;
  // A name too long for two lines in the wrap font keeps two all the same,
  // the second cut, rather than one line cut sooner.
  bool wrap_cuts;
  // The header sets its text from the left, as the logo arrangement does.
  bool left;
};

// One of two columns side by side.
static lv_coord_t columnWidth(const LabelArea& a) { return (a.w - dots(LR_COLUMN_GAP_PX)) / 2; }

// Where the body put the code and how it set the facts, for the log.
struct LabelBody { lv_coord_t qr; bool beside; const char* facts; };

// The name as the area sets it on two lines: one line would cut it even in
// the wrap font, and it breaks into two that fit, or the area takes a cut
// second line. False: one line.
static bool nameOnTwoLines(const LabelArea& a, const char* name, char* first, char* second) {
  if (!a.wrap_font || fitsLine(name, a.wrap_font, a.w)) return false;
  if (splitTwoLines(name, a.wrap_font, a.w, first, second)) return true;
  if (!a.wrap_cuts) return false;
  const char* rest = takeLine(name, a.wrap_font, a.w, first);
  if (!rest) return false;
  snprintf(second, LABEL_NAME_BYTES, "%s", rest);
  return true;
}

// The filament's name: one line in `f`, as large as it fit; where the area
// has a wrap font and `f` would cut it, one line in the wrap font if that
// holds it, else two. Returns the y under it.
static lv_coord_t drawName(lv_obj_t* canvas, const LabelArea& a, lv_coord_t y,
                           const lv_font_t* f, const char* name) {
  const lv_color_t black = lv_color_black();
  const lv_coord_t gap = dots(LR_GAP_PX);
  const lv_text_align_t align = a.left ? LV_TEXT_ALIGN_LEFT : LV_TEXT_ALIGN_CENTER;
  char first[LABEL_NAME_BYTES], second[LABEL_NAME_BYTES];
  const lv_font_t* w = a.wrap_font;
  if (!fitsLine(name, f, a.w) && nameOnTwoLines(a, name, first, second)) {
    drawLine(canvas, a.x, y, a.w, w, black, align, first);
    drawLine(canvas, a.x, y + lineHeight(w), a.w, w, black, align, second);
    return y + 2 * lineHeight(w) + gap;
  }
  if (w && !fitsLine(name, f, a.w) && fitsLine(name, w, a.w)) f = w;
  drawLine(canvas, a.x, y, a.w, f, black, align, name);
  return y + lineHeight(f) + gap;
}

// The filament's name as the header sets it: one of the sizes that fit the
// width, the larger ones on a tall label first.
static const lv_font_t* headerNameFont(const LabelArea& a, bool tall, const SpoolLabelData& d) {
  static const lv_font_t* const base[] = { &lv_font_montserrat_ext_28, &lv_font_montserrat_ext_24, &lv_font_montserrat_ext_20 };
  static const lv_font_t* const big[]  = { &lv_font_montserrat_ext_36, &lv_font_montserrat_ext_28, &lv_font_montserrat_ext_24, &lv_font_montserrat_ext_20 };
  return tall ? fitFont(d.name, a.w, big, 4) : fitFont(d.name, a.w, base, 3);
}

// The header, each block where the layout keeps it: the maker as large as
// the width carries, the material white on a black band, the filament's name
// as the title. Returns the y under it.
static lv_coord_t drawHeader(lv_obj_t* canvas, const LabelArea& a, bool tall,
                             const SpoolLabelData& d, const LabelLayout& layout) {
  const lv_color_t black = lv_color_black();
  lv_coord_t y = a.y;
  // The compact arrangement puts the maker among the facts instead.
  if (d.vendor[0] && labelLayoutHas(layout, LF_VENDOR) &&
      layout.preset != LABEL_PRESET_COMPACT) {
    static const lv_font_t* const base[] = { &lv_font_montserrat_ext_36, &lv_font_montserrat_ext_28, &lv_font_montserrat_ext_24 };
    // No 44 px on the larger sizes: that one line cost 85 KB of flash. A
    // name on two lines takes the room of the largest size.
    char l1[LABEL_NAME_BYTES], l2[LABEL_NAME_BYTES];
    const lv_font_t* f = nameOnTwoLines(a, d.name, l1, l2) ? fitFont(d.vendor, a.w, base + 1, 2)
                                                           : fitFont(d.vendor, a.w, base, 3);
    drawLine(canvas, a.x, y, a.w, f, black, LV_TEXT_ALIGN_CENTER, d.vendor);
    y += lineHeight(f) + dots(LR_GAP_PX);
  }
  if (d.material[0] && labelLayoutHas(layout, LF_MATERIAL)) {
    const lv_coord_t band_h = dots(tall ? LR_BAND_H_TALL_PX : LR_BAND_H_PX);
    // Plain: the same line in black on white, for a roll that smears a band.
    const bool plain = labelLayoutOption(layout, LO_MATERIAL_PLAIN);
    if (!plain) fillRect(canvas, a.x, y, a.w, band_h, black);
    const lv_font_t* f = tall ? &lv_font_montserrat_ext_28 : LR_BAND_FONT;
    const lv_coord_t ty = y + (band_h - lineHeight(f)) / 2;
    // White on black is drawn heavier still: the black around it bleeds into
    // the strokes on a thermal head, and the base size's 22 px came out thin.
    const lv_coord_t thick_x = plain ? 0 : dots(LR_BAND_THICK_X), thick_y = plain ? 0 : dots(LR_BAND_THICK_Y);
    for (lv_coord_t dy = 0; dy <= thick_y; dy++)
      for (lv_coord_t dx = 0; dx <= thick_x; dx++)
        drawLine(canvas, a.x + dx, ty + dy, a.w, f, plain ? black : lv_color_white(),
                 LV_TEXT_ALIGN_CENTER, d.material);
    y += band_h + dots(LR_GAP_PX);
  }
  if (d.name[0] && labelLayoutHas(layout, LF_NAME))
    y = drawName(canvas, a, y, headerNameFont(a, tall, d), d.name);
  return y;
}

// The material-first header: the material on a band across a quarter of the
// label, as large as it fits, the maker and the filament's name in one size
// under it. Returns the y under it.
static lv_coord_t drawMaterialHeader(lv_obj_t* canvas, const LabelArea& a,
                                     const SpoolLabelData& d, const LabelLayout& layout) {
  const lv_color_t black = lv_color_black();
  const lv_coord_t gap = dots(LR_GAP_PX);
  lv_coord_t y = a.y;
  if (d.material[0] && labelLayoutHas(layout, LF_MATERIAL)) {
    static const lv_font_t* const big[] = { &lv_font_montserrat_ext_36, &lv_font_montserrat_ext_28, &lv_font_montserrat_ext_24 };
    const lv_coord_t band_h = dots(LR_BAND_H_BIG_PX);
    const bool plain = labelLayoutOption(layout, LO_MATERIAL_PLAIN);
    if (!plain) fillRect(canvas, a.x, y, a.w, band_h, black);
    const lv_font_t* f = fitFont(d.material, a.w - 2 * gap, big, 3);
    drawLine(canvas, a.x, y + (band_h - lineHeight(f)) / 2, a.w, f,
             plain ? black : lv_color_white(), LV_TEXT_ALIGN_CENTER, d.material);
    y += band_h + gap;
  }
  static const lv_font_t* const line[] = { &lv_font_montserrat_ext_20, &lv_font_montserrat_ext_16 };
  const char* const under[] = { labelLayoutHas(layout, LF_VENDOR) ? d.vendor : "",
                                labelLayoutHas(layout, LF_NAME) ? d.name : "" };
  for (const char* text : under) {
    if (!text[0]) continue;
    const lv_font_t* f = fitFont(text, a.w, line, 2);
    if (text == d.name) { y = drawName(canvas, a, y, f, text); continue; }
    drawLine(canvas, a.x, y, a.w, f, black, LV_TEXT_ALIGN_CENTER, text);
    y += lineHeight(f) + gap;
  }
  return y;
}

// The logo header: the maker's mark across the top, the material band with
// the colour's hex beside it, the filament's name under it, all from the
// left. A maker without a stored logo prints its name in the mark's place.
// Returns the y under it.
static lv_coord_t drawLogoHeader(lv_obj_t* canvas, const LabelArea& a, bool tall,
                                 const SpoolLabelData& d, const LabelLayout& layout) {
  const lv_color_t black = lv_color_black();
  const lv_coord_t gap = dots(LR_GAP_PX);
  lv_coord_t y = a.y;
  if (d.vendor[0] && labelLayoutHas(layout, LF_VENDOR)) {
    const lv_coord_t box_h = dots(tall ? LR_LOGO_BOX_TALL_PX : LR_LOGO_BOX_H_PX);
    const LabelLogo* mark = labelLogoFor(d.vendor);
    if (mark) {
      const LabelBitmap src{ mark->bits, mark->w, mark->h };
      const BitmapDots size = bitmapDots(src, a.w, box_h);
      drawBitmap1bit(canvas, a.x, y + (box_h - size.h) / 2, src, size);
    } else {
      static const lv_font_t* const fonts[] = { &lv_font_montserrat_ext_36, &lv_font_montserrat_ext_28,
                                                &lv_font_montserrat_ext_24, &lv_font_montserrat_ext_20 };
      const lv_font_t* f = fitFontUnder(d.vendor, a.w, box_h, fonts, 4);
      drawLine(canvas, a.x, y + (box_h - lineHeight(f)) / 2, a.w, f, black,
               LV_TEXT_ALIGN_LEFT, d.vendor);
    }
    y += box_h + gap;
  }
  char hex[sizeof(d.color) + 1];
  const bool have_hex = labelColorInBand(layout, d) && labelColorText(d, hex, sizeof(hex));
  if (d.material[0] && labelLayoutHas(layout, LF_MATERIAL)) {
    const lv_coord_t band_h = dots(tall ? LR_BAND_H_TALL_PX : LR_BAND_H_PX);
    const lv_font_t* f = tall ? &lv_font_montserrat_ext_28 : LR_BAND_FONT;
    const lv_font_t* hf = tall ? &lv_font_montserrat_ext_20 : &lv_font_montserrat_ext_16;
    const lv_coord_t inset = dots(LR_BAND_INSET_PX);
    // drawLine() adds the font's bold stroke to the text it measures, so the
    // column keeps that dot as well; without it the last hex digit is cut.
    const lv_coord_t hex_w = have_hex ? textWidth(hex, hf) + boldFor(hf) + gap : 0;
    const lv_coord_t band_w = a.w - hex_w;
    const bool plain = labelLayoutOption(layout, LO_MATERIAL_PLAIN);
    if (!plain) fillRect(canvas, a.x, y, band_w, band_h, black);
    const lv_coord_t ty = y + (band_h - lineHeight(f)) / 2;
    const lv_coord_t thick_x = plain ? 0 : dots(LR_BAND_THICK_X);
    const lv_coord_t thick_y = plain ? 0 : dots(LR_BAND_THICK_Y);
    for (lv_coord_t dy = 0; dy <= thick_y; dy++)
      for (lv_coord_t dx = 0; dx <= thick_x; dx++)
        drawLine(canvas, a.x + inset + dx, ty + dy, band_w - inset, f,
                 plain ? black : lv_color_white(), LV_TEXT_ALIGN_LEFT, d.material);
    if (have_hex)
      drawLine(canvas, a.x + band_w + gap, y + (band_h - lineHeight(hf)) / 2, hex_w - gap,
               hf, black, LV_TEXT_ALIGN_RIGHT, hex);
    y += band_h + gap;
  }
  if (d.name[0] && labelLayoutHas(layout, LF_NAME))
    y = drawName(canvas, a, y, headerNameFont(a, tall, d), d.name);
  return y;
}

// Either header, as the arrangement has it. With no canvas it only measures.
static lv_coord_t drawHead(lv_obj_t* canvas, const LabelArea& a, bool tall,
                           const SpoolLabelData& d, const LabelLayout& layout) {
  if (layout.preset == LABEL_PRESET_MATERIAL_BIG) return drawMaterialHeader(canvas, a, d, layout);
  if (layout.preset == LABEL_PRESET_LOGO) return drawLogoHeader(canvas, a, tall, d, layout);
  return drawHeader(canvas, a, tall, d, layout);
}

// The width the text keeps next to the code: the fixed minimum, or, where the
// arrangement keeps the text whole, its widest line, as long as the code
// still comes out at a good size.
static lv_coord_t textKeep(const LabelArea& a, const LabelContent& c, const lv_font_t* f) {
  const lv_coord_t least = dots(LR_FACTS_MIN_W);
  if (!a.keep_text || c.wrap) return least;
  lv_coord_t widest = least;
  for (int i = 0; i < c.n; i++) {
    const lv_coord_t w = textWidth(c.lines[i], f) + boldFor(f);
    if (w > widest) widest = w;
  }
  const lv_coord_t most = a.w - dots(LR_QR_GOOD_PX) - dots(LR_GAP_PX);
  return widest > most ? (most > least ? most : least) : widest;
}

// How the body sets the facts in one line each: their font and line, where
// the code goes and how large it comes out (0: no code).
struct BodyPlan {
  const lv_font_t* font;
  lv_coord_t line;
  lv_coord_t qr;      // the code's box
  lv_coord_t code;    // the code as drawn, whole dots per module
  bool beside;
};

// The facts and the code under the header. The code goes where it comes out
// larger: next to the facts on a wide label, under them on a tall one, and it
// takes all the height it gets. When that leaves it small, the fact lines
// step down a size first.
static BodyPlan planOneLine(const LabelArea& a, bool tall, const LabelContent& c) {
  const lv_coord_t avail_h = a.bottom - a.y;
  const int rows = c.wrap ? LR_WRAP_ROWS : c.n;
  BodyPlan p{ tall ? &lv_font_montserrat_ext_20 : &lv_font_montserrat_ext_16,
              dots(tall ? LR_FACT_LINE_TALL_PX : LR_FACT_LINE_PX), 0, 0, true };
  if (a.facts_font) { p.font = a.facts_font; p.line = dots(LR_FACT_LINE_SMALL_PX); }
  for (int pass = 0; pass < 2; pass++) {
    lv_coord_t qr_beside = a.w - textKeep(a, c, p.font) - dots(LR_GAP_PX);
    if (qr_beside > avail_h) qr_beside = avail_h;
    lv_coord_t qr_below = avail_h - rows * p.line - dots(LR_GAP_PX);
    if (qr_below > a.w) qr_below = a.w;
    p.beside = qr_beside >= qr_below;
    p.qr = p.beside ? qr_beside : qr_below;
    if (p.qr > a.qr_max) p.qr = a.qr_max;
    if (p.qr >= dots(LR_QR_GOOD_PX) || p.font != &lv_font_montserrat_ext_20) break;
    p.font = &lv_font_montserrat_ext_16;
    p.line = dots(LR_FACT_LINE_PX);
  }
  // The code comes out in whole dots per module and is mostly smaller than its
  // box: the text column reaches to the code, not to the box, which gave a
  // date line on 40 x 30 the room it was cut short of.
  if (p.qr >= dots(LR_QR_MIN_PX) && c.qr && c.qr[0]) p.code = drawQr(nullptr, 0, 0, p.qr, c.qr, true);
  return p;
}

static void drawOneLine(lv_obj_t* canvas, const LabelArea& a, const LabelContent& c,
                        const BodyPlan& p) {
  const lv_coord_t facts_top = a.y;
  const lv_coord_t avail_h = a.bottom - facts_top;
  const int rows = c.wrap ? LR_WRAP_ROWS : c.n;
  const lv_font_t* fact_font = p.font;
  const lv_coord_t facts_w = (p.beside && p.code) ? a.w - p.code - dots(LR_GAP_PX) : a.w;
  lv_coord_t text_h = rows * p.line;
  if (c.wrap && c.n > 0) {
    // One size down when the paragraph does not fit the height next to the code.
    text_h = paragraphHeight(c.lines[0], fact_font, facts_w);
    if (text_h > avail_h) {
      fact_font = &lv_font_montserrat_ext_14;
      text_h = paragraphHeight(c.lines[0], fact_font, facts_w);
    }
    const lv_coord_t py = p.beside && text_h < avail_h ? facts_top + (avail_h - text_h) / 2 : facts_top;
    drawParagraph(canvas, a.x, py, facts_w, fact_font, c.lines[0]);
  } else {
    // Next to the code the lines stand in the middle of the height they share.
    const lv_coord_t block = c.n * p.line;
    const lv_coord_t fy = p.beside && block < avail_h ? facts_top + (avail_h - block) / 2 : facts_top;
    for (int i = 0; i < c.n; i++)
      drawLine(canvas, a.x, fy + i * p.line, facts_w, fact_font,
               lv_color_black(), LV_TEXT_ALIGN_LEFT, c.lines[i]);
  }
  if (p.code) {
    const lv_coord_t qx = p.beside ? a.x + a.w - p.code : a.x + (a.w - p.code) / 2;
    const lv_coord_t qy = p.beside ? facts_top + (avail_h - p.code) / 2 : facts_top + text_h + dots(LR_GAP_PX);
    drawQr(canvas, qx, qy, p.code, c.qr);
  }
}

// The larger sizes for the facts, tried in this order: two lines each (the
// caption small, the value large under it), then one line in a larger font.
// A fact with no value, the project name, stays in the small font. The
// largest is for the tall sizes only; on the base size no fact outgrows the
// filament's name.
struct FactStyle { const lv_font_t* value; const lv_font_t* caption; bool two_lines; };
static const FactStyle FACT_STYLES[] = {
  { &lv_font_montserrat_ext_28, &lv_font_montserrat_ext_16, true },
  { &lv_font_montserrat_ext_24, &lv_font_montserrat_ext_14, true },
  { &lv_font_montserrat_ext_20, &lv_font_montserrat_ext_14, true },
  { &lv_font_montserrat_ext_24, &lv_font_montserrat_ext_14, false },
  { &lv_font_montserrat_ext_20, &lv_font_montserrat_ext_14, false },
  // The small lines once more, for a label without a code only: in two
  // columns they hold what one column would push off the label.
  { &lv_font_montserrat_ext_16, &lv_font_montserrat_ext_14, false },
};
static const int FACT_STYLE_COUNT = sizeof(FACT_STYLES) / sizeof(FACT_STYLES[0]);
// The last one, which only a label without a code may take.
static const FactStyle* const FACT_STYLE_NO_CODE = &FACT_STYLES[FACT_STYLE_COUNT - 1];

// cols: 2 when the facts stand in two columns, the first half on the left.
struct FactsPlan { const FactStyle* style; lv_coord_t code; lv_coord_t text_h; int cols; };

static bool hasText(const char* s) { return s && s[0]; }

// What fact i draws in the value font: its value, or its whole line.
static const char* largeText(const LabelContent& c, int i, const FactStyle& s) {
  if (!hasText(c.facts[i].value)) return nullptr;
  return s.two_lines ? c.facts[i].value : c.lines[i];
}

// What fact i draws in the caption font.
static const char* smallText(const LabelContent& c, int i, const FactStyle& s) {
  const LabelFact& f = c.facts[i];
  if (!hasText(f.value)) return f.caption;
  return s.two_lines && hasText(f.caption) ? f.caption : nullptr;
}

// The height of facts from..to-1 stacked.
static lv_coord_t factsHeight(const LabelContent& c, const FactStyle& s, int from, int to) {
  lv_coord_t h = 0;
  for (int i = from; i < to; i++) {
    if (i > from) h += dots(LR_GAP_PX);
    if (smallText(c, i, s)) h += lineHeight(s.caption);
    if (largeText(c, i, s)) h += lineHeight(s.value);
  }
  return h;
}

// The widest of the lines; 0 when one has a letter the font cannot spell.
static lv_coord_t factsWidth(const LabelContent& c, const FactStyle& s) {
  lv_coord_t widest = 0;
  for (int i = 0; i < c.n; i++) {
    const char* small = smallText(c, i, s);
    const char* large = largeText(c, i, s);
    if (small) widest = LV_MAX(widest, textWidth(small, s.caption) + boldFor(s.caption));
    if (!large) continue;
    if (!canSpell(s.value, large)) return 0;
    widest = LV_MAX(widest, textWidth(large, s.value) + boldFor(s.value));
  }
  return widest;
}

// The facts larger, when the label has the room: the first style whose lines
// fit the height, whose lines fit the width whole, and that leaves the code
// no smaller than the small lines did. So a label with few fields reads
// larger, and one with all of them prints as before.
static bool planLarger(const LabelArea& a, bool tall, const LabelContent& c,
                       const BodyPlan& one, FactsPlan* out) {
  if (c.wrap || !c.facts || c.n == 0) return false;
  const lv_coord_t avail_h = a.bottom - a.y;
  for (int i = 0; i < FACT_STYLE_COUNT; i++) {
    const FactStyle& s = FACT_STYLES[i];
    if (&s == FACT_STYLE_NO_CODE ? !a.columns : s.value->line_height <= one.font->line_height)
      continue;
    if (!tall && s.value->line_height > lv_font_montserrat_ext_24.line_height) continue;
    const lv_coord_t w = factsWidth(c, s);
    if (w == 0) continue;
    const lv_coord_t h = factsHeight(c, s, 0, c.n);
    if (w > a.w || h > avail_h) {
      // Two columns where the arrangement has no code to share the width with.
      const int half = (c.n + 1) / 2;
      const lv_coord_t h2 = LV_MAX(factsHeight(c, s, 0, half), factsHeight(c, s, half, c.n));
      if (!a.columns || one.code || c.n < 2 || w > columnWidth(a) || h2 > avail_h) continue;
      *out = FactsPlan{ &s, 0, h2, 2 };
      return true;
    }
    lv_coord_t code = 0;
    if (one.code) {
      lv_coord_t box = one.beside ? a.w - w - dots(LR_GAP_PX) : avail_h - h - dots(LR_GAP_PX);
      box = LV_MIN(box, one.beside ? avail_h : a.w);
      box = LV_MIN(box, a.qr_max);
      code = box >= dots(LR_QR_MIN_PX) ? drawQr(nullptr, 0, 0, box, c.qr, true) : 0;
      if (code < one.code) continue;
    }
    *out = FactsPlan{ &s, code, h, 1 };
    return true;
  }
  return false;
}

// Facts from..to-1 one under the other from y, each cut to the width.
static void drawFactColumn(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y, lv_coord_t w,
                           const LabelContent& c, const FactStyle& s, int from, int to) {
  for (int i = from; i < to; i++) {
    if (i > from) y += dots(LR_GAP_PX);
    if (const char* small = smallText(c, i, s)) {
      drawLine(canvas, x, y, w, s.caption, lv_color_black(), LV_TEXT_ALIGN_LEFT, small);
      y += lineHeight(s.caption);
    }
    if (const char* large = largeText(c, i, s)) {
      drawLine(canvas, x, y, w, s.value, lv_color_black(), LV_TEXT_ALIGN_LEFT, large);
      y += lineHeight(s.value);
    }
  }
}

static void drawLarger(lv_obj_t* canvas, const LabelArea& a, const LabelContent& c,
                       const FactsPlan& p, bool beside) {
  const lv_coord_t avail_h = a.bottom - a.y;
  const lv_coord_t text_w = (beside && p.code) ? a.w - p.code - dots(LR_GAP_PX) : a.w;
  const lv_coord_t y = beside && p.text_h < avail_h ? a.y + (avail_h - p.text_h) / 2 : a.y;
  if (p.cols == 2) {
    const int half = (c.n + 1) / 2;
    const lv_coord_t col_w = columnWidth(a);
    drawFactColumn(canvas, a.x, y, col_w, c, *p.style, 0, half);
    drawFactColumn(canvas, a.x + a.w - col_w, y, col_w, c, *p.style, half, c.n);
  } else {
    drawFactColumn(canvas, a.x, y, text_w, c, *p.style, 0, c.n);
  }
  if (p.code) {
    const lv_coord_t qx = beside ? a.x + a.w - p.code : a.x + (a.w - p.code) / 2;
    const lv_coord_t qy = beside ? a.y + (avail_h - p.code) / 2 : a.y + p.text_h + dots(LR_GAP_PX);
    drawQr(canvas, qx, qy, p.code, c.qr);
  }
}

static LabelBody drawBody(lv_obj_t* canvas, const LabelArea& a, bool tall,
                          const LabelContent& c) {
  const BodyPlan one = planOneLine(a, tall, c);
  FactsPlan larger;
  if (planLarger(a, tall, c, one, &larger)) {
    drawLarger(canvas, a, c, larger, one.beside);
    return LabelBody{ larger.code, one.beside, larger.style->two_lines ? "two lines" : "large lines" };
  }
  drawOneLine(canvas, a, c, one);
  return LabelBody{ one.code ? one.qr : (lv_coord_t)0, one.beside, "small lines" };
}

// The big-code arrangement: the code at the right edge, as tall as the label
// allows while the text keeps its column. Narrows the area to that column
// and returns the code's edge, 0 when there is no code to draw.
static lv_coord_t drawSideQr(lv_obj_t* canvas, LabelArea* a, const LabelContent& c) {
  if (!c.qr || !c.qr[0]) return 0;
  // The facts set the column, in the smallest type: the code is the point here.
  a->facts_font = &lv_font_montserrat_ext_14;
  const lv_coord_t keep = textKeep(*a, c, a->facts_font);
  const lv_coord_t gap = dots(LR_GAP_PX);
  lv_coord_t box = a->bottom - a->y;
  if (box > a->w - keep - gap) box = a->w - keep - gap;
  if (box > a->qr_max) box = a->qr_max;
  if (box < dots(LR_QR_MIN_PX)) { a->facts_font = nullptr; return 0; }
  const lv_coord_t code = drawQr(nullptr, 0, 0, box, c.qr, true);
  if (!code) { a->facts_font = nullptr; return 0; }
  drawQr(canvas, a->x + a->w - code, a->y + (a->bottom - a->y - code) / 2, code, c.qr);
  a->w -= code + gap;
  return code;
}

// The big code on an upright label: across the top, at most half its height,
// the text under it. Moves the area's top below it and returns its edge.
static lv_coord_t drawTopQr(lv_obj_t* canvas, LabelArea* a, const LabelContent& c) {
  if (!c.qr || !c.qr[0]) return 0;
  a->facts_font = &lv_font_montserrat_ext_14;
  lv_coord_t box = LV_MIN(a->w, (a->bottom - a->y) / 2);
  box = LV_MIN(box, a->qr_max);
  const lv_coord_t code = box >= dots(LR_QR_MIN_PX) ? drawQr(nullptr, 0, 0, box, c.qr, true) : 0;
  if (!code) { a->facts_font = nullptr; return 0; }
  drawQr(canvas, a->x + (a->w - code) / 2, a->y, code, c.qr);
  a->y += code + dots(LR_GAP_PX);
  return code;
}

// The code the body draws once the header ends at a.y, 0 for none, and
// whether every fact line stays whole.
static lv_coord_t bodyCode(const LabelArea& a, bool tall, const LabelContent& c, bool* fits) {
  const BodyPlan one = planOneLine(a, tall, c);
  FactsPlan larger;
  *fits = true;
  if (planLarger(a, tall, c, one, &larger)) return larger.code;
  const lv_coord_t text = (c.wrap ? LR_WRAP_ROWS : c.n) * one.line;
  const lv_coord_t need = one.beside ? LV_MAX(text, one.code)
                                     : text + (one.code ? one.code + dots(LR_GAP_PX) : 0);
  *fits = need <= a.bottom - a.y;
  return one.code;
}

// The font a name one line would cut is set in instead, on one line or two;
// null to cut it as before. The largest of three that leaves every fact
// whole and the code as large as the cut line did; with none, the smallest
// with `cuts` set, if its two lines leave the same. Measured, nothing drawn.
static const lv_font_t* nameWrapFont(const LabelArea& a, bool tall, const LabelContent& c,
                                     const LabelLayout& layout, bool* cuts) {
  const SpoolLabelData& d = *c.d;
  if (!d.name[0] || !labelLayoutHas(layout, LF_NAME)) return nullptr;
  // The smallest size the header sets the name in on one line.
  const lv_font_t* smallest = layout.preset == LABEL_PRESET_MATERIAL_BIG
      ? &lv_font_montserrat_ext_16 : &lv_font_montserrat_ext_20;
  if (fitsLine(d.name, smallest, a.w)) return nullptr;
  LabelArea plain = a;
  plain.wrap_font = nullptr;
  plain.y = drawHead(nullptr, plain, tall, d, layout);
  bool fits = false;
  const lv_coord_t code = bodyCode(plain, tall, c, &fits);
  auto holds = [&](const lv_font_t* f, bool cut) {
    LabelArea trial = a;
    trial.wrap_font = f;
    trial.wrap_cuts = cut;
    trial.y = drawHead(nullptr, trial, tall, d, layout);
    if (trial.y == plain.y) return false;   // no break that fits two lines
    const lv_coord_t trial_code = bodyCode(trial, tall, c, &fits);
    return fits && trial_code >= code;
  };
  static const lv_font_t* const WRAP_FONTS[] = {
    &lv_font_montserrat_ext_20, &lv_font_montserrat_ext_16, &lv_font_montserrat_ext_14,
  };
  for (const lv_font_t* f : WRAP_FONTS)
    if (holds(f, false)) return f;
  const lv_font_t* smallest_wrap = &lv_font_montserrat_ext_14;
  *cuts = holds(smallest_wrap, true);
  return *cuts ? smallest_wrap : nullptr;
}

// Every label the scale prints, laid out as `layout` says.
// What the big number arrangements fill on a canvas of this size.
static BigIdBox bigIdBox(lv_coord_t canvas_w, lv_coord_t canvas_h) {
  const lv_coord_t M = dots(LR_MARGIN_PX);
  return BigIdBox{ M, M, (lv_coord_t)(canvas_w - 2 * M), (lv_coord_t)(canvas_h - 2 * M) };
}

static bool renderLabel(const LabelPrinterConfig& printer, const LabelLayout& layout,
                        const LabelContent& c, LabelRaster* out) {
  if (!out || !c.d) return false;
  *out = LabelRaster{};
  const uint16_t content_w = labelPrinterContentWidth(printer.model, printer.media_width_mm);
  const uint16_t h = labelPrinterDotsForMm(printer.model, printer.media_length_mm);
  const uint16_t row_w = labelPrinterRasterWidth(printer.model, printer.media_width_mm);
  if (!row_w || !h || content_w > row_w) return false;
  setDpi(labelPrinterProfile(printer.model).dpi);

  const bool turned = labelLayoutOption(layout, LO_PORTRAIT);
  setTurned(turned);
  // The canvas is the label as it reads: upright, the roll's length across.
  const uint16_t cw = turned ? h : content_w;
  const uint16_t ch = turned ? content_w : h;
  const size_t buf_bytes = LV_CANVAS_BUF_SIZE_TRUE_COLOR(cw, ch);
  void* buf = heap_caps_malloc(buf_bytes, MALLOC_CAP_SPIRAM);
  if (!buf) { logSD("Label: no PSRAM for the canvas"); return false; }

  // An unloaded screen as the parent: the canvas and the QR code exist only
  // to be read back; nothing draws them, and the delete at the end takes
  // both. lv_scr_load() is never called.
  lv_obj_t* parent = lv_obj_create(NULL);
  lv_obj_t* canvas = lv_canvas_create(parent);
  lv_canvas_set_buffer(canvas, buf, cw, ch, LV_IMG_CF_TRUE_COLOR);
  lv_canvas_fill_bg(canvas, lv_color_white(), LV_OPA_COVER);

  const lv_coord_t M = dots(LR_MARGIN_PX);
  const uint8_t preset = layout.preset;
  const bool standard = preset == LABEL_PRESET_STANDARD;
  const lv_coord_t qr_max = labelPrinterDotsForMm(printer.model,
      preset == LABEL_PRESET_MATERIAL_BIG ? LR_QR_SMALL_MM : LR_QR_MAX_MM);
  LabelArea area{ M, M, (lv_coord_t)(cw - 2 * M), (lv_coord_t)(ch - M), qr_max, !standard,
                  nullptr, !c.qr || !c.qr[0], nullptr, false, preset == LABEL_PRESET_LOGO };
  LabelContent body = c;
  lv_coord_t side_qr = 0;
  LabelBody placed{ 0, true, "lines under the number" };
  if (labelPresetIsBigId(preset)) {
    labelDrawBigId(canvas, bigIdBox(cw, ch), BigIdContent{ c.d, &layout, c.lines, c.facts, c.n });
  } else {
    if (preset == LABEL_PRESET_BIG_QR) {
      side_qr = turned ? drawTopQr(canvas, &area, c) : drawSideQr(canvas, &area, c);
      if (side_qr) body.qr = nullptr;
    }
    // The larger sizes need room both ways: a 30 x 40 is tall but narrow, and
    // there the header blocks would eat what the code needs.
    const bool tall = ch >= dots(LR_TALL_PX) && area.w + 2 * M >= dots(LR_TALL_PX);
    area.wrap_font = nameWrapFont(area, tall, body, layout, &area.wrap_cuts);
    area.y = drawHead(canvas, area, tall, *c.d, layout);
    placed = drawBody(canvas, area, tall, body);
  }

  const uint16_t x0 = labelPrinterContentX(printer);
  const bool ok = packCanvas(canvas, content_w, h, row_w, x0, out);
  lv_obj_del(parent);
  heap_caps_free(buf);
  logSDf("Label: %s %ux%u at dot %u of a %u dot row, qr=%d %s, facts in %s, %s", c.what,
         (unsigned)content_w, (unsigned)h, (unsigned)x0, (unsigned)row_w,
         side_qr ? (int)side_qr : (int)placed.qr,
         side_qr ? (turned ? "top" : "side") : placed.beside ? "beside" : "below",
         placed.facts, ok ? "ok" : "failed");
  return ok;
}

bool labelRenderTest(const LabelPrinterConfig& printer, LabelRaster* out) {
  // Says what it is at a glance: the project on top, "test print" in the
  // band, the printer, the stock and the build as the title, and next to the
  // code to Ko-fi one sentence about it (Nikolai, 25.09.2026).
  SpoolLabelData d{};
  snprintf(d.vendor, sizeof(d.vendor), "SpoolmanScale");
  copyT(d.material, sizeof(d.material), STR_LBL_TEST_BAND);
  // The build, as short as it can be said: "beta.79" of a pre-release, the
  // whole version of a release.
  const char* dash = strrchr(FW_VERSION, '-');
  snprintf(d.name, sizeof(d.name), "%s  %ux%u  %s", labelPrinterProfile(printer.model).name,
           (unsigned)printer.media_width_mm, (unsigned)printer.media_length_mm,
           dash ? dash + 1 : FW_VERSION);
  // The tape has no room for the sentence and the code: the three lines say
  // what it is, the size and the build in the name, the printer left out.
  if (labelPrinterIsTape(printer.model)) {
    snprintf(d.name, sizeof(d.name), "%ux%u  %s", (unsigned)printer.media_width_mm,
             (unsigned)printer.media_length_mm, dash ? dash + 1 : FW_VERSION);
    return labelRenderTape(printer, d, false, "test", out);
  }
  const char* lines[] = { T(STR_LBL_TEST_DONATE) };
  // Always the standard arrangement: the test print checks the printer, not
  // the template.
  const LabelContent c{ &d, lines, 1, true, "https://" DONATION_URL, "test" };
  return renderLabel(printer, labelLayoutDefault(), c, out);
}

// The dot of millimetre v on the calibration ruler, counted from the label's
// first dot at `centre`, negative to the left.
static lv_coord_t rulerDot(LabelPrinterModel model, lv_coord_t centre, int v) {
  const lv_coord_t d = labelPrinterDotsForMm(model, (uint16_t)(v < 0 ? -v : v));
  return v < 0 ? centre - d : centre + d;
}

bool labelRenderCalibration(const LabelPrinterConfig& printer, LabelRaster* out) {
  if (!out) return false;
  // A tape printer's head is as wide as the tape: there is no offset to
  // read off, and the test label shows where the print sits.
  if (labelPrinterIsTape(printer.model)) return labelRenderTest(printer, out);
  *out = LabelRaster{};
  const uint16_t content_w = labelPrinterContentWidth(printer.model, printer.media_width_mm);
  const uint16_t h = labelPrinterDotsForMm(printer.model, printer.media_length_mm);
  const uint16_t row_w = labelPrinterRasterWidth(printer.model, printer.media_width_mm);
  if (!row_w || !h || content_w > row_w) return false;
  setDpi(labelPrinterProfile(printer.model).dpi);
  setTurned(false);

  // The whole row, not just the label: the ruler has to run under the roll
  // wherever it sits.
  const size_t buf_bytes = LV_CANVAS_BUF_SIZE_TRUE_COLOR(row_w, h);
  void* buf = heap_caps_malloc(buf_bytes, MALLOC_CAP_SPIRAM);
  if (!buf) { logSD("Label: no PSRAM for the canvas"); return false; }
  lv_obj_t* parent = lv_obj_create(NULL);
  lv_obj_t* canvas = lv_canvas_create(parent);
  lv_canvas_set_buffer(canvas, buf, row_w, h, LV_IMG_CF_TRUE_COLOR);
  lv_canvas_fill_bg(canvas, lv_color_white(), LV_OPA_COVER);
  const lv_color_t black = lv_color_black();

  int16_t lo;
  labelPrinterOffsetRange(printer, &lo, nullptr);
  const lv_coord_t centre = -lo;          // the label's first dot at offset 0
  const lv_coord_t x = labelPrinterContentX(printer);
  const int16_t offset = labelPrinterOffset(printer);

  // The ruler across the row, in millimetres of offset, read like any
  // ruler: a tick every millimetre, a longer one every second, and every
  // fourth a number right of a tick that reaches up to it. So the number
  // at the label's left edge is still whole: that is the offset. Numbers
  // where the left edge can be and three more each side, in case a roll sits
  // further out than the head suggests (Nikolai, 30.09.2026); past that the
  // row has ticks alone, and "+48" would not fit the 4 mm anyway.
  int16_t lo_n, hi;
  labelPrinterOffsetRange(printer, &lo_n, &hi);
  const lv_coord_t per_mm = labelPrinterDotsForMm(printer.model, 1);
  const lv_coord_t extra = LC_NUM_EXTRA * LC_NUM_EVERY * per_mm;
  const lv_font_t* num_font = &lv_font_montserrat_ext_16;
  const lv_coord_t num_y = dots(LC_NUM_Y);
  const lv_coord_t base_y = dots(LC_BASE_Y);
  const lv_coord_t tick_w = dots(LC_TICK_PX);
  fillRect(canvas, 0, base_y, row_w, dots(LC_BASE_PX), black);
  // Each tick at its own millimetre's dot rather than per_mm on from the
  // last: at 300 dpi a millimetre is 11.81 dots, and steps of 12 would drift
  // a millimetre across the head.
  for (int v = -(int)((centre + per_mm - 1) / per_mm); ; v++) {
    const lv_coord_t d = rulerDot(printer.model, centre, v);
    if (d >= row_w) break;
    if (d < 0) continue;
    if (v % LC_NUM_EVERY || d - centre > hi + extra || d - centre < lo_n - extra) {
      const lv_coord_t len = dots(v % 2 ? LC_TICK_MM : LC_TICK_2MM);
      fillRect(canvas, d, base_y - len, tick_w, len, black);
      continue;
    }
    fillRect(canvas, d, num_y, tick_w, base_y - num_y, black);
    // No plus sign, as on any ruler: "+20" did not fit the 4 mm in 16 px.
    char num[8];
    snprintf(num, sizeof(num), "%d", v);
    drawLine(canvas, d + tick_w + dots(LC_NUM_GAP), num_y, dots(LC_NUM_W), num_font, black,
             LV_TEXT_ALIGN_LEFT, num);
  }

  // The frame, under the ruler and 1 mm inside where the scale takes the
  // label to be: with the offset right, the same white shows left and right.
  const lv_coord_t M = dots(LR_MARGIN_PX);
  const lv_coord_t F = dots(LC_FRAME_PX);
  const lv_coord_t box_y = base_y + dots(LC_BASE_PX) + dots(LC_BOX_GAP);
  const lv_coord_t box_h = h - M - box_y;
  if (box_h > 2 * F) {
    fillRect(canvas, x + M, box_y, content_w - 2 * M, F, black);
    fillRect(canvas, x + M, h - M - F, content_w - 2 * M, F, black);
    fillRect(canvas, x + M, box_y, F, box_h, black);
    fillRect(canvas, x + content_w - M - F, box_y, F, box_h, black);
  }

  // What to read off, and what was set when this was printed: the photo of
  // a calibration page says both.
  const lv_coord_t gap = dots(LR_GAP_PX);
  const lv_coord_t tx = x + M + F + gap;
  const lv_coord_t tw = content_w - 2 * (M + F + gap);
  const lv_coord_t ty = box_y + F + dots(LC_TEXT_GAP);
  const lv_font_t* big = &lv_font_montserrat_ext_16;
  const lv_font_t* small = &lv_font_montserrat_ext_14;
  const int off_mm = (offset + (offset < 0 ? -per_mm / 2 : per_mm / 2)) / per_mm;
  // Each line only where it fits, so a flatter label keeps ruler and frame.
  const lv_coord_t bottom = h - M - F;
  lv_coord_t ly = ty;
  // Where the label fills the row there is no offset to read off, and the
  // line would ask for one (the M110S, issue #55).
  if (lo_n != hi && ly + lineHeight(big) < bottom) {
    drawLine(canvas, tx, ly, tw, big, black, LV_TEXT_ALIGN_CENTER, T(STR_LBL_CAL_EDGE));
    ly += lineHeight(big) + gap;
  }
  if (ly + lineHeight(small) < bottom) {
    drawLine(canvas, tx, ly, tw, small, black, LV_TEXT_ALIGN_CENTER, "SpoolmanScale");
    ly += lineHeight(small) + gap;
  }
  if (ly + lineHeight(small) < bottom) {
    const char* dash = strrchr(FW_VERSION, '-');
    char info[LABEL_LINE_LEN];
    snprintf(info, sizeof(info), "%s  %ux%u  %s %s%d mm  %s",
             labelPrinterProfile(printer.model).name, (unsigned)printer.media_width_mm,
             (unsigned)printer.media_length_mm, T(STR_W_P_CAL_OFFSET), off_mm > 0 ? "+" : "",
             off_mm, dash ? dash + 1 : FW_VERSION);
    drawLine(canvas, tx, ly, tw, small, black, LV_TEXT_ALIGN_CENTER, info);
  }

  const bool ok = packCanvas(canvas, row_w, h, row_w, 0, out);
  // The label's width, for the check against the loaded stock; the rest of
  // the row carries the ruler on purpose.
  out->content_width = content_w;
  lv_obj_del(parent);
  heap_caps_free(buf);
  logSDf("Label: calibration %ux%u, label at dot %u, offset %d, %s", (unsigned)row_w,
         (unsigned)h, (unsigned)x, (int)offset, ok ? "ok" : "failed");
  return ok;
}

void labelQrForSpool(int spool_id, char* out, size_t n) {
  if (!out || !n) return;
  out[0] = '\0';
  // FilaMan's label designer defaults its code to /spools/{id}; BamBuddy's
  // labels carry the inventory page. Spoolman's label dialog offers its tag
  // format or the spool page, and its scanner reads both; only the page
  // opens on a phone - "WEB+SPOOLMAN:S-239" left the iPhone with plain text
  // (Nikolai, 30.09.2026). The tag format stays for a scale with no address.
  // The address is the server's own for its labels where it has one.
  const char* base = labelLinkBase();
  const bool have_base = base[0] && strcmp(base, "http://") != 0;
  if (backendIsFilaMan()) {
    if (have_base) snprintf(out, n, "%s/spools/%d", base, spool_id);
  } else if (backendIsBamBuddy()) {
    if (have_base) snprintf(out, n, "%s/inventory?spool=%d", base, spool_id);
  } else if (have_base) {
    snprintf(out, n, "%s/spool/show/%d", base, spool_id);
  } else {
    snprintf(out, n, "WEB+SPOOLMAN:S-%d", spool_id);
  }
}

void labelQrForFilament(const SpoolLabelData& spool, char* out, size_t n) {
  if (!out || !n) return;
  out[0] = '\0';
  // A server that names its spools' pages itself may have no filament page at
  // all: Spooly has none, and a code that opens nothing is worse than no code.
  if (spool.page_url[0]) return;
  const char* base = labelLinkBase();
  const bool have_base = base[0] && strcmp(base, "http://") != 0;
  // BamBuddy keeps no filament object: brand, material and colour sit on the
  // spool. Its inventory is the one page that holds the spools of this
  // filament, and every other filament's too, so the code opens that.
  if (backendIsBamBuddy()) {
    if (have_base) snprintf(out, n, "%s/inventory", base);
    return;
  }
  // A Spoolman with no address has no page either.
  if (spool.filament_id <= 0 || !have_base) return;
  if (backendIsFilaMan()) snprintf(out, n, "%s/filaments/%d", base, spool.filament_id);
  else                    snprintf(out, n, "%s/filament/show/%d", base, spool.filament_id);
}

// The spool's texts as a label prints them: see labelDropMarks().
static SpoolLabelData withoutMarks(const SpoolLabelData& in) {
  SpoolLabelData d = in;
  labelDropMarks(d.vendor);
  labelDropMarks(d.material);
  labelDropMarks(d.name);
  labelDropMarks(d.location);
  return d;
}

bool labelRenderFilament(const LabelPrinterConfig& printer, const LabelLayout& layout,
                         const SpoolLabelData& in, LabelRaster* out) {
  const SpoolLabelData spool = withoutMarks(in);
  // The tape's own arrangement, without the spool's number: see label_tape.h.
  if (labelPrinterIsTape(printer.model)) return labelRenderTape(printer, spool, false, "filament", out);
  char qr[LABEL_QR_LEN];
  labelQrForFilament(spool, qr, sizeof(qr));
  // No page to open: the label is laid out as one without a code.
  LabelLayout l = layout;
  if (!qr[0]) l.fields &= ~(1u << LF_QR);
  const int capacity = labelFactCapacity(l, printer.media_width_mm, printer.media_length_mm);
  LabelFactList f;
  labelFilamentFacts(l, spool, capacity, &f);
  const LabelContent c{ &spool, f.line_ptrs, f.n, false,
                        labelLayoutHasCode(l) ? qr : nullptr, "filament", f.facts };
  return renderLabel(printer, l, c, out);
}

int labelIdShareLimit(const LabelPrinterConfig& printer, const LabelLayout& layout,
                      const SpoolLabelData& in) {
  if (!labelPresetIsBigId(layout.preset) || labelPrinterIsTape(printer.model)) return 0;
  const uint16_t content_w = labelPrinterContentWidth(printer.model, printer.media_width_mm);
  const uint16_t h = labelPrinterDotsForMm(printer.model, printer.media_length_mm);
  setDpi(labelPrinterProfile(printer.model).dpi);
  const bool turned = labelLayoutOption(layout, LO_PORTRAIT);
  setTurned(turned);
  const SpoolLabelData spool = withoutMarks(in);
  const int capacity = labelFactCapacity(layout, printer.media_width_mm, printer.media_length_mm);
  LabelFactList l;
  labelSpoolFacts(layout, spool, capacity, &l);
  return labelBigIdShareLimit(bigIdBox(turned ? h : content_w, turned ? content_w : h),
                              BigIdContent{ &spool, &layout, l.line_ptrs, l.facts, l.n });
}

bool labelRenderSpool(const LabelPrinterConfig& printer, const LabelLayout& layout,
                      const SpoolLabelData& in, LabelRaster* out) {
  const SpoolLabelData spool = withoutMarks(in);
  // The tape's own arrangement: maker, material, name and the number.
  if (labelPrinterIsTape(printer.model)) return labelRenderTape(printer, spool, true, "spool", out);
  char qr[LABEL_QR_LEN];
  if (spool.page_url[0]) {
    logSDf("Label: spool #%d carries its own link, the QR code uses it", spool.id);
    snprintf(qr, sizeof(qr), "%s", spool.page_url);
  }
  else labelQrForSpool(spool.id, qr, sizeof(qr));
  const int capacity = labelFactCapacity(layout, printer.media_width_mm, printer.media_length_mm);
  LabelFactList l;
  labelSpoolFacts(layout, spool, capacity, &l);
  const LabelContent c{ &spool, l.line_ptrs, l.n, false,
                        labelLayoutHasCode(layout) ? qr : nullptr, "spool", l.facts };
  return renderLabel(printer, layout, c, out);
}
