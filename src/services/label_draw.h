#pragma once

#include <lvgl.h>
#include <stdint.h>

#include "services/label_raster.h"

// ============================================================
//  DRAWING A LABEL AT THE HEAD'S RESOLUTION
//
//  The primitives the label renderer lays its blocks out with:
//  lengths in dots and fonts for the head that prints them, lines
//  cut to a width, rectangles, the QR code module by module, and
//  the canvas packed into the print raster. The layout itself -
//  which block goes where - is label_render.cpp's.
//
//  One label at a time, on the loop task: setDpi() and setTurned()
//  hold for everything drawn until the next label.
// ============================================================

// The fonts, from src/fonts/: the large ones are compiled in by their own
// guard. Only the sizes up to 24 have the French supplement behind them; a
// line the big ones cannot spell drops to 24 where the list has it, else it
// prints without its accents (services/accent_fold.h). 30 to 48 are what a
// 300 dpi head prints the others in.
LV_FONT_DECLARE(lv_font_montserrat_ext_48);
LV_FONT_DECLARE(lv_font_montserrat_ext_40);
LV_FONT_DECLARE(lv_font_montserrat_ext_36);
LV_FONT_DECLARE(lv_font_montserrat_ext_32);
LV_FONT_DECLARE(lv_font_montserrat_ext_30);
LV_FONT_DECLARE(lv_font_montserrat_ext_28);
LV_FONT_DECLARE(lv_font_montserrat_ext_24);
LV_FONT_DECLARE(lv_font_montserrat_ext_22);
LV_FONT_DECLARE(lv_font_montserrat_ext_20);
LV_FONT_DECLARE(lv_font_montserrat_ext_16);
LV_FONT_DECLARE(lv_font_montserrat_ext_14);

namespace labeldraw {

// The head's resolution for what is drawn next: 203 or 300.
void setDpi(uint16_t dpi);
// Whether the canvas is the label upright, turned onto the raster by packCanvas().
void setTurned(bool turned);

// A length given in dots at 203 dpi, in dots of this head, rounded.
lv_coord_t dots(lv_coord_t base);
// The font a 203 dpi font prints in on this head. The layout chooses among
// the 203 dpi fonts and compares them; only measuring and drawing take this.
const lv_font_t* sized(const lv_font_t* base);
lv_coord_t lineHeight(const lv_font_t* base);
// Whether a font, in the size this head prints it, can spell a line as written.
bool canSpell(const lv_font_t* base, const char* s);
// The extra stroke a font is drawn with: the small ones one dot wider.
lv_coord_t boldFor(const lv_font_t* font);
lv_coord_t textWidth(const char* s, const lv_font_t* font);
// The largest of the fonts that fits the line into the width, the last one
// when none does; the line is then cut to it.
const lv_font_t* fitFont(const char* text, lv_coord_t w, const lv_font_t* const* fonts, int count);
// The largest font of the list the line fits whole in, no taller than
// `max_h`; the smallest one no taller than that when none holds it whole,
// and the line is cut to it.
const lv_font_t* fitFontUnder(const char* text, lv_coord_t w, lv_coord_t max_h,
                              const lv_font_t* const* fonts, int count);
// Whether a line fits the width whole in this font, as the font spells it:
// a font without the supplement spells a line with its accents folded.
bool fitsLine(const char* text, const lv_font_t* f, lv_coord_t w);
// The text as two lines that each fit the width in this font, broken where
// LVGL breaks a paragraph; each buffer LABEL_LINE_LEN bytes. False when it
// needs more than two.
bool splitTwoLines(const char* text, const lv_font_t* f, lv_coord_t w, char* first, char* second);

// The first line of a text wrapped to the width, into `first` of LABEL_LINE_LEN
// bytes. Returns what is left after it, null when there is nothing to break.
const char* takeLine(const char* text, const lv_font_t* f, lv_coord_t w, char* first);
// One line, cut on a character boundary to the width. No canvas: nothing is
// drawn, for a block that is only being measured.
void drawLine(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y, lv_coord_t w,
              const lv_font_t* font, lv_color_t color, lv_text_align_t align, const char* text);
// A paragraph wrapped by LVGL into the width, and its height.
lv_coord_t paragraphHeight(const char* text, const lv_font_t* font, lv_coord_t w);
void drawParagraph(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y, lv_coord_t w,
                   const lv_font_t* font, const char* text);
void fillRect(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h,
              lv_color_t color);
// The code in a box of box x box dots at x, y: whole dots per module, the
// quiet zone inside the box. Returns the edge used, 0 when it does not fit
// readably. With no canvas it only measures; `silent` keeps a measurement
// out of the log.
lv_coord_t drawQr(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y, lv_coord_t box,
                  const char* text, bool silent = false);
// A number from its outlines (label_digits.h): the first ink at x, the top
// at y, `height` dots tall. Runs straight into the canvas's pixels: a number
// is thousands of runs, where a QR code is hundreds of rectangles.
void drawBigDigits(lv_obj_t* canvas, lv_coord_t x, lv_coord_t y, lv_coord_t height, const char* digits);
// The canvas into the raster, from dot x0 of a row_w print row.
bool packCanvas(lv_obj_t* canvas, uint16_t content_w, uint16_t h, uint16_t row_w,
                uint16_t x0, LabelRaster* out);

}  // namespace labeldraw
