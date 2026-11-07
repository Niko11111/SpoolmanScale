#include "services/label_draw.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <stdio.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "services/accent_fold.h"
#include "services/label_digits.h"
#include "services/label_render.h"
#include "services/text_util.h"
#include "src/extra/libs/qrcode/qrcodegen.h"

#define LR_BASE_DPI      203
// Extra stroke width of the small lines and the band. The large ones, the
// maker and the title, print without it: with it everything read a touch
// heavy, without it the small lines came out thin (Nikolai, 25.09.2026).
#define LR_BOLD_DOTS       1
// A thermal head bleeds each dot a little, so a module under 3 dots (0.375 mm)
// fills in. And a reader needs white around the code: the standard asks for
// 4 modules, 2 is what most phones still take. The first test labels had
// neither - the code sat next to the text with whatever the rounding left -
// and did not read (25.09.2026).
#define LR_QR_MODULE_MIN   3
#define LR_QR_QUIET        4
#define LR_QR_QUIET_TIGHT  2
#define LR_QR_MAX_VERSION 10    // 57 modules: far more than a spool URL needs
#define LR_BLACK_BELOW   128    // brightness under which a canvas pixel prints
// Room for a line as drawLine() cuts or folds it: the longest text a block
// carries is a fact of two LABEL_LINE_LEN fields.
#define LR_SPELL_LEN     (LABEL_LINE_LEN * 2 + 4)

namespace labeldraw {

// The resolution of the label being drawn. Each entry point sets it before it
// draws; they all run on the loop task, one label at a time.
static uint16_t s_dpi = LR_BASE_DPI;
// Whether the canvas is the label upright: as wide as the roll is long, and
// turned a quarter left onto the raster, its top at the row's left end.
static bool s_turned = false;

// A length of the geometry above in dots of the head that prints it, rounded.
lv_coord_t dots(lv_coord_t base) {
  return (lv_coord_t)((int32_t(base) * s_dpi + LR_BASE_DPI / 2) / LR_BASE_DPI);
}

// The fonts on a finer head: the 203 dpi size times 1.48, as near as the even
// sizes in src/fonts/ go. The 36 would want 53; 48 is the largest there is.
struct FontStep { const lv_font_t* base; const lv_font_t* fine; };
static const FontStep FONTS_300[] = {
  { &lv_font_montserrat_ext_14, &lv_font_montserrat_ext_20 },
  { &lv_font_montserrat_ext_16, &lv_font_montserrat_ext_24 },
  { &lv_font_montserrat_ext_20, &lv_font_montserrat_ext_30 },
  { &lv_font_montserrat_ext_22, &lv_font_montserrat_ext_32 },
  { &lv_font_montserrat_ext_24, &lv_font_montserrat_ext_36 },
  { &lv_font_montserrat_ext_28, &lv_font_montserrat_ext_40 },
  { &lv_font_montserrat_ext_36, &lv_font_montserrat_ext_48 },
};

// The font a 203 dpi font prints in on this head. The layout chooses among
// the 203 dpi fonts and compares them; only measuring and drawing take this.
const lv_font_t* sized(const lv_font_t* base) {
  if (s_dpi <= LR_BASE_DPI) return base;
  for (const FontStep& s : FONTS_300)
    if (s.base == base) return s.fine;
  return base;
}

lv_coord_t lineHeight(const lv_font_t* base) { return sized(base)->line_height; }

// The canvas into the raster: black is anything darker than mid grey, and the
// canvas starts at dot x0 of the print row, where the stock runs.
bool packCanvas(lv_obj_t* canvas, uint16_t content_w, uint16_t h,
                       uint16_t row_w, uint16_t x0, LabelRaster* out) {
  const uint16_t row_bytes = (row_w + 7) / 8;
  const size_t length = size_t(row_bytes) * h;
  uint8_t* px = (uint8_t*)heap_caps_calloc(length, 1, MALLOC_CAP_SPIRAM);
  if (!px) { logSD("Label: no PSRAM for the raster"); return false; }
  for (uint16_t y = 0; y < h; y++) {
    uint8_t* row = px + size_t(y) * row_bytes;
    for (uint16_t x = 0; x < content_w; x++) {
      // Upright, raster dot (x, y) is canvas dot (h - 1 - y, x).
      const lv_color_t c = s_turned ? lv_canvas_get_px(canvas, h - 1 - y, x)
                                    : lv_canvas_get_px(canvas, x, y);
      if (lv_color_brightness(c) < LR_BLACK_BELOW) {
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

// Whether the large fonts can spell a line: ASCII, the degree sign of the
// temperatures and the German letters they were generated with. Anything
// else has a glyph only in the sizes up to 24.
static bool bigFontCovers(const char* s) {
  for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
    if (*p < 0x80) continue;
    if (*p == 0xC2 && p[1] == 0xB0) { p++; continue; }
    if (*p == 0xC3 && p[1]) {
      const unsigned char n = p[1];
      if (n == 0x84 || n == 0x96 || n == 0x9C || n == 0x9F || n == 0xA4 || n == 0xB6 || n == 0xBC) { p++; continue; }
    }
    return false;
  }
  return true;
}

// Whether a font, in the size this head prints it, can spell a line: one with
// the French supplement behind it can spell anything the labels carry.
bool canSpell(const lv_font_t* base, const char* s) {
  return sized(base)->fallback != nullptr || bigFontCovers(s);
}

// The line as this font spells it: itself where the font has every glyph,
// else with the accents folded onto their base letters (é to e, œ to oe) in
// `buf` of LR_SPELL_LEN bytes. A 300 dpi head prints the maker, the band and
// the material in the sizes 30 to 48, and those have no supplement behind
// them: a missing accent reads, a box does not (Nikolai, 22.10.2026).
static const char* spelled(const lv_font_t* base, const char* s, char* buf) {
  if (canSpell(base, s)) return s;
  accentFold(s, buf, LR_SPELL_LEN);
  return buf;
}

lv_coord_t boldFor(const lv_font_t* font) {
  return font->line_height > lv_font_montserrat_ext_24.line_height ? 0 : dots(LR_BOLD_DOTS);
}

lv_coord_t textWidth(const char* s, const lv_font_t* font) {
  return lv_txt_get_width(s, strlen(s), sized(font), 0, LV_TEXT_FLAG_NONE);
}

// The largest of the fonts that fits the line into the width as written,
// else the largest that fits it with the accents folded, else the last one;
// the line is then cut to it. So a line with an accent keeps it wherever a
// font with the supplement fits, and only loses it where none does.
const lv_font_t* fitFont(const char* text, lv_coord_t w,
                                const lv_font_t* const* fonts, int count) {
  for (int i = 0; i < count; i++) {
    if (!canSpell(fonts[i], text)) continue;
    if (textWidth(text, fonts[i]) <= w) return fonts[i];
  }
  char plain[LR_SPELL_LEN];
  for (int i = 0; i < count; i++) {
    const char* s = spelled(fonts[i], text, plain);
    if (s == text || !canSpell(fonts[i], s)) continue;
    if (textWidth(s, fonts[i]) <= w) return fonts[i];
  }
  return fonts[count - 1];
}

// One line, cut to what the font really fits into the width, on a character
// boundary. Cut, never wrapped: a wrapped line would run into the next block.
void drawLine(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y, lv_coord_t w,
                     const lv_font_t* font, lv_color_t color, lv_text_align_t align,
                     const char* text) {
  // No canvas: a header being measured, not drawn.
  if (!canvas || !text || !text[0]) return;
  const lv_coord_t bold = boldFor(font);
  char plain[LR_SPELL_LEN];
  text = spelled(font, text, plain);
  char line[LR_SPELL_LEN];
  size_t budget = strlen(text);
  for (;;) {
    utf8Cut(text, budget, line, sizeof(line));
    const lv_coord_t used = textWidth(line, font) + bold;
    if (used <= w || budget == 0) break;
    const size_t next = (size_t)((uint32_t)budget * w / used);
    budget = next < budget ? next : budget - 1;
  }
  lv_draw_label_dsc_t dsc;
  lv_draw_label_dsc_init(&dsc);
  dsc.color = color;
  dsc.font = sized(font);
  dsc.align = align;
  // Drawn once more a dot to the right: every stroke one dot wider. The
  // thermal head printed Montserrat's regular weight thin, and white text on
  // the material band came out grey because the black around it bled into
  // its strokes (Nikolai, 25.09.2026). The same pass widens those too.
  for (lv_coord_t dx = 0; dx <= bold; dx++)
    lv_canvas_draw_text(canvas, x + dx, y, w - bold, &dsc, line);
}

// A paragraph, wrapped by LVGL into the width. Returns its height.
lv_coord_t paragraphHeight(const char* text, const lv_font_t* font, lv_coord_t w) {
  lv_point_t size;
  lv_txt_get_size(&size, text, sized(font), 0, 0, w - boldFor(font), LV_TEXT_FLAG_NONE);
  return size.y;
}

void drawParagraph(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y, lv_coord_t w,
                          const lv_font_t* font, const char* text) {
  const lv_coord_t bold = boldFor(font);
  lv_draw_label_dsc_t dsc;
  lv_draw_label_dsc_init(&dsc);
  dsc.color = lv_color_black();
  dsc.font = sized(font);
  for (lv_coord_t dx = 0; dx <= bold; dx++)
    lv_canvas_draw_text(canvas, x + dx, y, w - bold, &dsc, text);
}

void fillRect(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y, lv_coord_t w,
                     lv_coord_t h, lv_color_t color) {
  if (!canvas) return;
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
// With no canvas it only measures; `silent` keeps a measurement that tries
// several boxes out of the log, the drawing call logs what it had to drop.
lv_coord_t drawQr(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y,
                         lv_coord_t box, const char* text, bool silent) {
  uint8_t tmp[qrcodegen_BUFFER_LEN_FOR_VERSION(LR_QR_MAX_VERSION)];
  uint8_t qr[qrcodegen_BUFFER_LEN_FOR_VERSION(LR_QR_MAX_VERSION)];
  if (!qrcodegen_encodeText(text, tmp, qr, qrcodegen_Ecc_MEDIUM, 1,
                            LR_QR_MAX_VERSION, qrcodegen_Mask_AUTO, true)) {
    if (!silent) logSDf("Label: QR does not fit version %d: %s", LR_QR_MAX_VERSION, text);
    return 0;
  }
  const int size = qrcodegen_getSize(qr);
  int quiet = LR_QR_QUIET;
  // At 300 dpi 3 dots would be a module of 0.25 mm: the minimum is a length.
  const int module_min = dots(LR_QR_MODULE_MIN);
  int scale = box / (size + 2 * quiet);
  if (scale < module_min) {
    quiet = LR_QR_QUIET_TIGHT;
    scale = box / (size + 2 * quiet);
  }
  if (scale < module_min) {
    if (!silent) logSDf("Label: QR of %d modules does not fit %d dots", size, (int)box);
    return 0;
  }
  const lv_coord_t total = (size + 2 * quiet) * scale;
  if (!canvas) return total;
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

const lv_font_t* fitFontUnder(const char* text, lv_coord_t w, lv_coord_t max_h,
                              const lv_font_t* const* fonts, int count) {
  const lv_font_t* last = fonts[count - 1];
  for (int i = 0; i < count; i++) {
    if (lineHeight(fonts[i]) > max_h) continue;
    last = fonts[i];
    if (fitsLine(text, fonts[i], w)) return fonts[i];
  }
  return last;
}

static void digitRun(int x, int y, int w, void* ctx) {
  lv_img_dsc_t* img = (lv_img_dsc_t*)ctx;
  if (y < 0 || y >= (int)img->header.h) return;
  for (int i = x < 0 ? 0 : x; i < x + w && i < (int)img->header.w; i++)
    lv_img_buf_set_px_color(img, i, y, lv_color_black());
}

void drawBigDigits(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y, lv_coord_t height, const char* digits) {
  if (!canvas) return;
  labelDigitsDraw(digits, LabelDigitsAt{ x, y, height }, digitRun, lv_canvas_get_img(canvas));
}

// Whether a line fits the width whole in this font, as the font spells it.
bool fitsLine(const char* text, const lv_font_t* f, lv_coord_t w) {
  char plain[LR_SPELL_LEN];
  const char* s = spelled(f, text, plain);
  return canSpell(f, s) && textWidth(s, f) + boldFor(f) <= w;
}

// The text as two lines that each fit the width in this font, broken where
// LVGL breaks a paragraph. False when it needs more than two.
bool splitTwoLines(const char* text, const lv_font_t* f, lv_coord_t w,
                          char* first, char* second) {
  char plain[LR_SPELL_LEN];
  text = spelled(f, text, plain);
  if (!canSpell(f, text)) return false;
  lv_coord_t used = 0;
  const uint32_t n = _lv_txt_get_next_line(text, sized(f), 0, w - boldFor(f), &used,
                                           LV_TEXT_FLAG_NONE);
  if (n == 0 || n >= strlen(text) || n >= LABEL_NAME_BYTES) return false;
  snprintf(first, LABEL_NAME_BYTES, "%.*s", (int)n, text);
  const char* rest = text + n;
  while (*rest == ' ') rest++;
  // Only spaces after the break: that is one line, not two.
  if (!*rest) return false;
  snprintf(second, LABEL_NAME_BYTES, "%s", rest);
  // The break leaves a space at the end of the first line.
  for (size_t k = strlen(first); k > 0 && first[k - 1] == ' '; k--) first[k - 1] = '\0';
  return fitsLine(first, f, w) && fitsLine(second, f, w);
}

const char* takeLine(const char* text, const lv_font_t* f, lv_coord_t w, char* first) {
  if (!canSpell(f, text)) return nullptr;
  lv_coord_t used = 0;
  const uint32_t n = _lv_txt_get_next_line(text, sized(f), 0, w - boldFor(f), &used,
                                           LV_TEXT_FLAG_NONE);
  if (n == 0 || n >= strlen(text) || n >= LABEL_NAME_BYTES) return nullptr;
  snprintf(first, LABEL_NAME_BYTES, "%.*s", (int)n, text);
  for (size_t k = strlen(first); k > 0 && first[k - 1] == ' '; k--) first[k - 1] = '\0';
  const char* rest = text + n;
  while (*rest == ' ') rest++;
  return *rest ? rest : nullptr;
}

void setDpi(uint16_t dpi) { s_dpi = dpi; }
void setTurned(bool turned) { s_turned = turned; }

}  // namespace labeldraw
