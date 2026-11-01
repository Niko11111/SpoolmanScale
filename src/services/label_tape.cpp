#include "services/label_tape.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <lvgl.h>
#include <stdio.h>

#include "hardware/sd_logger.h"
#include "services/label_draw.h"
#include "services/label_tape_name.h"

using namespace labeldraw;

// The geometry in dots at 203 dpi, the D110's resolution, through dots()
// like the other labels. The head is as wide as the tape is high, and the
// printer feeds a little loosely, so the text keeps off the edges.
#define LT_MARGIN_X_PX   8    // 1 mm at each end of the label
#define LT_MARGIN_Y_PX   4    // half a millimetre above and below
#define LT_GAP_PX        6    // from the text to the rule, the rule to the number
#define LT_RULE_PX       2
#define LT_ID_MAX_PCT   40    // the number never takes more of the length than this
#define LT_LINES_MAX     3    // maker, material, name
#define LT_ID_LEN       12    // an int in decimal, its sign and the terminator

// The text lines, largest first: three of them share 12 mm, one alone may
// be as large as the number.
static const lv_font_t* const LT_TEXT_FONTS[] = {
  &lv_font_montserrat_ext_36, &lv_font_montserrat_ext_32, &lv_font_montserrat_ext_28,
  &lv_font_montserrat_ext_24, &lv_font_montserrat_ext_22, &lv_font_montserrat_ext_20,
  &lv_font_montserrat_ext_16, &lv_font_montserrat_ext_14,
};
static const lv_font_t* const LT_ID_FONTS[] = {
  &lv_font_montserrat_ext_48, &lv_font_montserrat_ext_40, &lv_font_montserrat_ext_36,
  &lv_font_montserrat_ext_32, &lv_font_montserrat_ext_28, &lv_font_montserrat_ext_24,
};
#define LT_TEXT_FONT_COUNT (int)(sizeof(LT_TEXT_FONTS) / sizeof(LT_TEXT_FONTS[0]))
#define LT_ID_FONT_COUNT   (int)(sizeof(LT_ID_FONTS) / sizeof(LT_ID_FONTS[0]))

// Where the blocks go on the canvas, which is the label as it reads.
struct TapeArea { lv_coord_t left, right, top, height, canvas_h; };

// The largest font of the list the line fits whole in, no taller than
// `max_h`; the smallest one no taller than that when none holds it whole,
// and the line is cut to it.
static const lv_font_t* tapeFont(const char* text, lv_coord_t w, lv_coord_t max_h,
                                 const lv_font_t* const* fonts, int count) {
  const lv_font_t* last = fonts[count - 1];
  for (int i = 0; i < count; i++) {
    if (lineHeight(fonts[i]) > max_h) continue;
    last = fonts[i];
    if (fitsLine(text, fonts[i], w)) return fonts[i];
  }
  return last;
}

// The number at the right end and the rule before it; the area's right edge
// moves in past both. Nothing without a number. The number is never cut: a
// digit short is another spool. Where even the smallest font is wider than
// its share, the number takes what it needs and the text gets less.
static void drawTapeId(lv_obj_t* canvas, TapeArea* a, const char* id) {
  if (!id[0]) return;
  const lv_color_t black = lv_color_black();
  const lv_coord_t gap = dots(LT_GAP_PX), rule = dots(LT_RULE_PX);
  const lv_coord_t max_w = (a->right - a->left) * LT_ID_MAX_PCT / 100;
  const lv_font_t* f = tapeFont(id, max_w, a->height, LT_ID_FONTS, LT_ID_FONT_COUNT);
  const lv_coord_t w = textWidth(id, f) + boldFor(f);
  drawLine(canvas, a->right - w, (a->canvas_h - lineHeight(f)) / 2, w, f, black,
           LV_TEXT_ALIGN_RIGHT, id);
  a->right -= w + gap;
  fillRect(canvas, a->right - rule, a->top, rule, a->height, black);
  a->right -= rule + gap;
}

// The lines one above the other, each in the largest font its share of the
// height and the width allow; what the fonts leave of the height goes evenly
// above, between and under them. Returns how many were drawn.
static int drawTapeLines(lv_obj_t* canvas, const TapeArea& a, const char* const* lines, int n) {
  const lv_coord_t w = a.right - a.left;
  if (n <= 0 || w <= 0) return 0;
  const lv_font_t* fonts[LT_LINES_MAX] = {};
  lv_coord_t used = 0;
  for (int i = 0; i < n; i++) {
    fonts[i] = tapeFont(lines[i], w, a.height / n, LT_TEXT_FONTS, LT_TEXT_FONT_COUNT);
    used += lineHeight(fonts[i]);
  }
  const lv_coord_t spare = a.height > used ? (a.height - used) / (n + 1) : 0;
  lv_coord_t y = a.top + spare;
  for (int i = 0; i < n; i++) {
    drawLine(canvas, a.left, y, w, fonts[i], lv_color_black(), LV_TEXT_ALIGN_LEFT, lines[i]);
    y += lineHeight(fonts[i]) + spare;
  }
  return n;
}

// The non-empty ones of maker, material and name, in the order a spool is
// read by: who made it, what it is, what it is called. An empty one leaves
// its room to the rest. Returns how many.
static int tapeLines(const SpoolLabelData& d, const char* vendor, const char* lines[LT_LINES_MAX]) {
  const char* const wanted[LT_LINES_MAX] = { vendor, d.material, d.name };
  int n = 0;
  for (const char* t : wanted)
    if (t[0]) lines[n++] = t;
  return n;
}

bool labelRenderTape(const LabelPrinterConfig& printer, const SpoolLabelData& d, bool with_id,
                     const char* what, LabelRaster* out) {
  if (!out) return false;
  *out = LabelRaster{};
  // Across the head the tape's height, along the feed its length.
  const uint16_t content_w = labelPrinterContentWidth(printer.model, printer.media_width_mm);
  const uint16_t h = labelPrinterDotsForMm(printer.model, printer.media_length_mm);
  const uint16_t row_w = labelPrinterRasterWidth(printer.model, printer.media_width_mm);
  if (!row_w || !h || content_w > row_w) return false;
  setDpi(labelPrinterProfile(printer.model).dpi);
  // The canvas is the label as it reads: the tape's length across.
  void* buf = heap_caps_malloc(LV_CANVAS_BUF_SIZE_TRUE_COLOR(h, content_w), MALLOC_CAP_SPIRAM);
  if (!buf) { logSD("Label: no PSRAM for the canvas"); return false; }
  // An unloaded screen as the parent, as for the other labels: nothing ever
  // shows it, and the delete at the end takes the canvas with it.
  lv_obj_t* parent = lv_obj_create(NULL);
  lv_obj_t* canvas = lv_canvas_create(parent);
  lv_canvas_set_buffer(canvas, buf, h, content_w, LV_IMG_CF_TRUE_COLOR);
  lv_canvas_fill_bg(canvas, lv_color_white(), LV_OPA_COVER);

  const lv_coord_t mx = dots(LT_MARGIN_X_PX), my = dots(LT_MARGIN_Y_PX);
  TapeArea a{ mx, (lv_coord_t)(h - mx), my, (lv_coord_t)(content_w - 2 * my), (lv_coord_t)content_w };
  char id[LT_ID_LEN] = "";
  if (with_id && d.id > 0) snprintf(id, sizeof(id), "%d", d.id);
  drawTapeId(canvas, &a, id);
  char vendor[LABEL_LINE_LEN];
  labelTapeVendor(d.vendor, vendor, sizeof(vendor));
  const char* lines[LT_LINES_MAX];
  const int n = drawTapeLines(canvas, a, lines, tapeLines(d, vendor, lines));

  setTurned(true);
  const bool ok = packCanvas(canvas, content_w, h, row_w, 0, out);
  setTurned(false);
  lv_obj_del(parent);
  heap_caps_free(buf);
  logSDf("Label: tape %s %ux%u, %d line(s), id %s, %s", what, (unsigned)content_w, (unsigned)h,
         n, id[0] ? id : "-", ok ? "ok" : "failed");
  return ok;
}
