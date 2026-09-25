#include "services/label_render.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>

#include "app_config.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/backend.h"
#include "services/text_util.h"
#include "src/extra/libs/qrcode/qrcodegen.h"

// The fonts, from src/fonts/: the large ones are compiled in by their own
// guard and were unused until now. Only the sizes up to 24 have the French
// supplement behind them; a line the big ones cannot spell drops to 24.
LV_FONT_DECLARE(lv_font_montserrat_ext_36);
LV_FONT_DECLARE(lv_font_montserrat_ext_28);
LV_FONT_DECLARE(lv_font_montserrat_ext_24);
LV_FONT_DECLARE(lv_font_montserrat_ext_22);
LV_FONT_DECLARE(lv_font_montserrat_ext_20);
LV_FONT_DECLARE(lv_font_montserrat_ext_16);

// The label's geometry in dots (203 dpi, 8 dots to the millimetre).
#define LR_MARGIN_PX       8    // 1 mm: the stock is never cut exactly
#define LR_GAP_PX          4    // between the blocks
// The blocks grow with the roll. 40 x 30 is the base; from LR_TALL_PX in
// both directions the band, the fonts and the fact lines take the larger sizes.
#define LR_TALL_PX       300
#define LR_BAND_H_PX      30    // the material band on the base size
#define LR_BAND_H_TALL_PX 40
#define LR_FACT_LINE_PX   22    // one fact line in the 16 px font
#define LR_FACT_LINE_TALL_PX 28 // one in the 20 px font
#define LR_FACTS_MIN_W   130    // the facts keep this much next to a code
#define LR_QR_MAX_PX     200    // 25 mm: larger reads no better
#define LR_QR_MIN_PX      64
#define LR_BOLD_DOTS       1    // extra stroke width of every text line
// A thermal head bleeds each dot a little, so a module under 3 dots (0.375 mm)
// fills in. And a reader needs white around the code: the standard asks for
// 4 modules, 2 is what most phones still take. The first test labels had
// neither - the code sat next to the text with whatever the rounding left -
// and did not read (25.09.2026).
#define LR_QR_MODULE_MIN   3
#define LR_QR_QUIET        4
#define LR_QR_QUIET_TIGHT  2
#define LR_QR_MAX_VERSION 10    // 57 modules: far more than a spool URL needs
#define LR_QR_GOOD_PX     96    // under this, smaller fact lines buy code size
#define LR_BLACK_BELOW   128    // brightness under which a canvas pixel prints
#define LR_MAX_FACTS       4
#define LR_TEST_URL "https://github.com/Niko11111/SpoolmanScale"

void labelRasterFree(LabelRaster* image) {
  if (!image) return;
  free(image->pixels);
  *image = LabelRaster{};
}

// The canvas into the raster: black is anything darker than mid grey, and the
// content sits centred in the print row, where the stock runs: a ruler across
// the M220's 576 dots put a 40 mm label under dots 128 to 448 (24.09.2026).
static bool packCanvas(lv_obj_t* canvas, uint16_t content_w, uint16_t h,
                       uint16_t row_w, LabelRaster* out) {
  const uint16_t row_bytes = (row_w + 7) / 8;
  const size_t length = size_t(row_bytes) * h;
  uint8_t* px = (uint8_t*)heap_caps_calloc(length, 1, MALLOC_CAP_SPIRAM);
  if (!px) { logSD("Label: no PSRAM for the raster"); return false; }
  const uint16_t x0 = (row_w - content_w) / 2;
  for (uint16_t y = 0; y < h; y++) {
    uint8_t* row = px + size_t(y) * row_bytes;
    for (uint16_t x = 0; x < content_w; x++) {
      if (lv_color_brightness(lv_canvas_get_px(canvas, x, y)) < LR_BLACK_BELOW) {
        const uint16_t rx = x0 + x;
        row[rx / 8] |= 0x80 >> (rx % 8);
      }
    }
  }
  out->width = row_w;
  out->height = h;
  out->row_bytes = row_bytes;
  out->pixels = px;
  out->length = length;
  out->content_width = content_w;
  return labelRasterValid(*out);
}

// Whether the large fonts can spell a line: ASCII and the German letters they
// were generated with. Anything else has a glyph only in the sizes up to 24.
static bool bigFontCovers(const char* s) {
  for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
    if (*p < 0x80) continue;
    if (*p == 0xC3 && p[1]) {
      const unsigned char n = p[1];
      if (n == 0x84 || n == 0x96 || n == 0x9C || n == 0x9F || n == 0xA4 || n == 0xB6 || n == 0xBC) { p++; continue; }
    }
    return false;
  }
  return true;
}

static lv_coord_t textWidth(const char* s, const lv_font_t* font) {
  return lv_txt_get_width(s, strlen(s), font, 0, LV_TEXT_FLAG_NONE);
}

// The largest of the fonts that fits the line into the width, the last one
// when none does; the line is then cut to it.
static const lv_font_t* fitFont(const char* text, lv_coord_t w,
                                const lv_font_t* const* fonts, int count) {
  const bool big_ok = bigFontCovers(text);
  for (int i = 0; i < count; i++) {
    if (!big_ok && fonts[i]->line_height > lv_font_montserrat_ext_24.line_height) continue;
    if (textWidth(text, fonts[i]) <= w) return fonts[i];
  }
  return fonts[count - 1];
}

// One line, cut to what the font really fits into the width, on a character
// boundary. Cut, never wrapped: a wrapped line would run into the next block.
static void drawLine(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y, lv_coord_t w,
                     const lv_font_t* font, lv_color_t color, lv_text_align_t align,
                     const char* text) {
  if (!text || !text[0]) return;
  char line[LABEL_LINE_LEN * 2 + 4];
  size_t budget = strlen(text);
  for (;;) {
    utf8Cut(text, budget, line, sizeof(line));
    const lv_coord_t used = textWidth(line, font) + LR_BOLD_DOTS;
    if (used <= w || budget == 0) break;
    const size_t next = (size_t)((uint32_t)budget * w / used);
    budget = next < budget ? next : budget - 1;
  }
  lv_draw_label_dsc_t dsc;
  lv_draw_label_dsc_init(&dsc);
  dsc.color = color;
  dsc.font = font;
  dsc.align = align;
  // Drawn once more a dot to the right: every stroke one dot wider. The
  // thermal head printed Montserrat's regular weight thin, and white text on
  // the material band came out grey because the black around it bled into
  // its strokes (Nikolai, 25.09.2026). The same pass widens those too.
  for (lv_coord_t dx = 0; dx <= LR_BOLD_DOTS; dx++)
    lv_canvas_draw_text(canvas, x + dx, y, w - LR_BOLD_DOTS, &dsc, line);
}

static void fillRect(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y, lv_coord_t w,
                     lv_coord_t h, lv_color_t color) {
  lv_draw_rect_dsc_t dsc;
  lv_draw_rect_dsc_init(&dsc);
  dsc.bg_color = color;
  dsc.bg_opa = LV_OPA_COVER;
  dsc.border_width = 0;
  dsc.radius = 0;
  lv_canvas_draw_rect(canvas, x, y, w, h, &dsc);
}

// The code, drawn module by module into a box of box x box dots at x, y:
// whole dots per module, the quiet zone inside the box and white, the rest
// centred. Returns the edge length used, 0 when it does not fit readably.
static lv_coord_t drawQr(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y,
                         lv_coord_t box, const char* text) {
  uint8_t tmp[qrcodegen_BUFFER_LEN_FOR_VERSION(LR_QR_MAX_VERSION)];
  uint8_t qr[qrcodegen_BUFFER_LEN_FOR_VERSION(LR_QR_MAX_VERSION)];
  if (!qrcodegen_encodeText(text, tmp, qr, qrcodegen_Ecc_MEDIUM, 1,
                            LR_QR_MAX_VERSION, qrcodegen_Mask_AUTO, true)) {
    logSDf("Label: QR does not fit version %d: %s", LR_QR_MAX_VERSION, text);
    return 0;
  }
  const int size = qrcodegen_getSize(qr);
  int quiet = LR_QR_QUIET;
  int scale = box / (size + 2 * quiet);
  if (scale < LR_QR_MODULE_MIN) {
    quiet = LR_QR_QUIET_TIGHT;
    scale = box / (size + 2 * quiet);
  }
  if (scale < LR_QR_MODULE_MIN) {
    logSDf("Label: QR of %d modules does not fit %d dots", size, (int)box);
    return 0;
  }
  const lv_coord_t total = (size + 2 * quiet) * scale;
  const lv_coord_t ox = x + (box - total) / 2;
  const lv_coord_t oy = y + (box - total) / 2;
  fillRect(canvas, ox, oy, total, total, lv_color_white());
  const lv_coord_t mx = ox + quiet * scale;
  const lv_coord_t my = oy + quiet * scale;
  for (int r = 0; r < size; r++) {
    // A run of dark modules is one rectangle rather than one each.
    for (int c = 0; c < size; ) {
      if (!qrcodegen_getModule(qr, c, r)) { c++; continue; }
      int run = 1;
      while (c + run < size && qrcodegen_getModule(qr, c + run, r)) run++;
      fillRect(canvas, mx + c * scale, my + r * scale, run * scale, scale, lv_color_black());
      c += run;
    }
  }
  logSDf("Label: QR %d modules, %d dots each, quiet %d, %d dots", size, scale, quiet, (int)total);
  return total;
}

// The one layout every label uses. note, when given, takes the place of the
// location line: the test label says what it is there.
static bool renderLabel(const LabelPrinterConfig& printer, const SpoolLabelData& d,
                        const char* qr_text, const char* note, const char* what,
                        LabelRaster* out) {
  if (!out) return false;
  *out = LabelRaster{};
  const uint16_t content_w = labelPrinterDotsForMm(printer.media_width_mm);
  const uint16_t h = labelPrinterDotsForMm(printer.media_length_mm);
  const uint16_t row_w = labelPrinterRasterWidth(printer.model, printer.media_width_mm);
  if (!row_w || !h || content_w > row_w) return false;

  const size_t buf_bytes = LV_CANVAS_BUF_SIZE_TRUE_COLOR(content_w, h);
  void* buf = heap_caps_malloc(buf_bytes, MALLOC_CAP_SPIRAM);
  if (!buf) { logSD("Label: no PSRAM for the canvas"); return false; }

  // An unloaded screen as the parent: the canvas and the QR code exist only
  // to be read back; nothing draws them, and the delete at the end takes
  // both. lv_scr_load() is never called.
  lv_obj_t* parent = lv_obj_create(NULL);
  lv_obj_t* canvas = lv_canvas_create(parent);
  lv_canvas_set_buffer(canvas, buf, content_w, h, LV_IMG_CF_TRUE_COLOR);
  lv_canvas_fill_bg(canvas, lv_color_white(), LV_OPA_COVER);

  const lv_color_t black = lv_color_black();
  const lv_color_t white = lv_color_white();
  const lv_coord_t M = LR_MARGIN_PX;
  const lv_coord_t W = content_w - 2 * M;
  // The larger sizes need room both ways: a 30 x 40 is tall but narrow, and
  // there the header blocks would eat what the code needs.
  const bool tall = h >= LR_TALL_PX && content_w >= LR_TALL_PX;
  lv_coord_t y = M;

  // The maker, as large as the width carries.
  if (d.vendor[0]) {
    static const lv_font_t* const base[] = { &lv_font_montserrat_ext_36, &lv_font_montserrat_ext_28, &lv_font_montserrat_ext_24 };
    // No 44 px on the larger sizes: that one line cost 85 KB of flash.
    const lv_font_t* f = fitFont(d.vendor, W, base, 3);
    drawLine(canvas, M, y, W, f, black, LV_TEXT_ALIGN_CENTER, d.vendor);
    y += f->line_height + LR_GAP_PX;
  }

  // The material, white on a black band.
  if (d.material[0]) {
    const lv_coord_t band_h = tall ? LR_BAND_H_TALL_PX : LR_BAND_H_PX;
    fillRect(canvas, M, y, W, band_h, black);
    const lv_font_t* f = tall ? &lv_font_montserrat_ext_28 : &lv_font_montserrat_ext_22;
    drawLine(canvas, M, y + (band_h - f->line_height) / 2, W, f, white,
             LV_TEXT_ALIGN_CENTER, d.material);
    y += band_h + LR_GAP_PX;
  }

  // The filament's name, the title.
  if (d.name[0]) {
    static const lv_font_t* const base[] = { &lv_font_montserrat_ext_28, &lv_font_montserrat_ext_24, &lv_font_montserrat_ext_20 };
    static const lv_font_t* const big[]  = { &lv_font_montserrat_ext_36, &lv_font_montserrat_ext_28, &lv_font_montserrat_ext_24, &lv_font_montserrat_ext_20 };
    const lv_font_t* f = tall ? fitFont(d.name, W, big, 4) : fitFont(d.name, W, base, 3);
    drawLine(canvas, M, y, W, f, black, LV_TEXT_ALIGN_CENTER, d.name);
    y += f->line_height + LR_GAP_PX;
  }

  // The facts: id, weight left, colour, location or the note.
  char facts[LR_MAX_FACTS][LABEL_LINE_LEN + 16];
  int n = 0;
  snprintf(facts[n++], sizeof(facts[0]), "%s  #%d", T(STR_LBL_L_ID), d.id);
  if (d.remaining_g >= 0)
    snprintf(facts[n++], sizeof(facts[0]), "%s  %.0f g", T(STR_LBL_L_LEFT), (double)d.remaining_g);
  if (d.color[0])
    snprintf(facts[n++], sizeof(facts[0]), "%s  %s", T(STR_LBL_L_COLOR), d.color);
  if (note && note[0])
    snprintf(facts[n++], sizeof(facts[0]), "%s", note);
  else if (d.location[0])
    snprintf(facts[n++], sizeof(facts[0]), "%s  %s", T(STR_LBL_L_LOC), d.location);

  // The code goes where it comes out larger: next to the facts on a wide
  // label, under them on a tall one, and it takes all the height it gets.
  // When that leaves it small, the fact lines step down a size first.
  const lv_coord_t facts_top = y;
  const lv_coord_t avail_h = h - M - facts_top;
  const lv_font_t* fact_font = tall ? &lv_font_montserrat_ext_20 : &lv_font_montserrat_ext_16;
  lv_coord_t fact_line = tall ? LR_FACT_LINE_TALL_PX : LR_FACT_LINE_PX;
  lv_coord_t qr = 0;
  bool beside = true;
  for (int pass = 0; pass < 2; pass++) {
    lv_coord_t qr_beside = W - LR_FACTS_MIN_W - LR_GAP_PX;
    if (qr_beside > avail_h) qr_beside = avail_h;
    lv_coord_t qr_below = avail_h - n * fact_line - LR_GAP_PX;
    if (qr_below > W) qr_below = W;
    beside = qr_beside >= qr_below;
    qr = beside ? qr_beside : qr_below;
    if (qr > LR_QR_MAX_PX) qr = LR_QR_MAX_PX;
    if (qr >= LR_QR_GOOD_PX || fact_font == &lv_font_montserrat_ext_16) break;
    fact_font = &lv_font_montserrat_ext_16;
    fact_line = LR_FACT_LINE_PX;
  }
  const bool with_qr = qr >= LR_QR_MIN_PX && qr_text && qr_text[0];
  const lv_coord_t facts_w = (beside && with_qr) ? W - qr - LR_GAP_PX : W;
  for (int i = 0; i < n; i++)
    drawLine(canvas, M, facts_top + i * fact_line, facts_w, fact_font,
             black, LV_TEXT_ALIGN_LEFT, facts[i]);
  if (with_qr) {
    const lv_coord_t qx = beside ? content_w - M - qr : M + (W - qr) / 2;
    const lv_coord_t qy = beside ? facts_top + (avail_h - qr) / 2 : facts_top + n * fact_line + LR_GAP_PX;
    drawQr(canvas, qx, qy, qr, qr_text);
  }

  const bool ok = packCanvas(canvas, content_w, h, row_w, out);
  lv_obj_del(parent);
  heap_caps_free(buf);
  logSDf("Label: %s %ux%u in a %u dot row, qr=%d %s, %s", what, (unsigned)content_w,
         (unsigned)h, (unsigned)row_w, with_qr ? (int)qr : 0,
         beside ? "beside" : "below", ok ? "ok" : "failed");
  return ok;
}

bool labelRenderTest(const LabelPrinterConfig& printer, LabelRaster* out) {
  // Sample data, the shape a real spool has, so the test shows the design.
  SpoolLabelData d{};
  d.id = 2;
  snprintf(d.name, sizeof(d.name), "Tough+ White");
  snprintf(d.vendor, sizeof(d.vendor), "Bambu Lab");
  snprintf(d.material, sizeof(d.material), "PLA");
  snprintf(d.color, sizeof(d.color), "FFFFFF");
  d.remaining_g = 488;
  // The build, as short as it can be said: "beta.76" of a pre-release, the
  // whole version of a release. The full "v0.8.0-beta.76" did not fit the
  // fact column of a 40 mm label.
  const char* dash = strrchr(FW_VERSION, '-');
  char note[LABEL_LINE_LEN];
  snprintf(note, sizeof(note), "%s  %s", T(STR_PRN_TEST), dash ? dash + 1 : FW_VERSION);
  return renderLabel(printer, d, LR_TEST_URL, note, "test", out);
}

void labelQrForSpool(int spool_id, char* out, size_t n) {
  if (!out || !n) return;
  // FilaMan's label designer defaults its code to /spools/{id}; BamBuddy's
  // labels carry the inventory page; Spoolman's own labels carry its tag
  // format, which its scanner and the printer plugins read.
  if (backendIsFilaMan())       snprintf(out, n, "%s/spools/%d", backendBaseUrl(), spool_id);
  else if (backendIsBamBuddy()) snprintf(out, n, "%s/inventory?spool=%d", backendBaseUrl(), spool_id);
  else                          snprintf(out, n, "WEB+SPOOLMAN:S-%d", spool_id);
}

bool labelRenderSpool(const LabelPrinterConfig& printer, const SpoolLabelData& spool,
                      LabelRaster* out) {
  char qr[LABEL_QR_LEN];
  labelQrForSpool(spool.id, qr, sizeof(qr));
  return renderLabel(printer, spool, qr, nullptr, "spool", out);
}
