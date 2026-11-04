#include "services/label_big_id.h"

#include <stdio.h>

#include "services/label_digits.h"
#include "services/label_draw.h"

using namespace labeldraw;

// In dots at 203 dpi, through dots() like the other labels.
#define LB_GAP_PX        4    // from the number to the lines, and the least between lines
#define LB_BAND_PAD_PX   4    // the black band above and below its text
#define LB_SPARE_MAX_PX 14    // the most between two lines: few of them stay together
#define LB_TEXT_MIN_W_PX 110   // the text beside a number keeps this: under it words fall apart
#define LB_ID_LEN       12    // an int in decimal, its sign and the terminator
#define LB_NAME_LINES    3    // a long name in a narrow column
// Maker, material, the name, the facts each as caption and value.
#define LB_LINES_MAX    (2 + LB_NAME_LINES + 2 * LABEL_MAX_FACTS)

// The lines' fonts, largest first, all with a size for a 300 dpi head.
static const lv_font_t* const LB_FONTS[] = {
  &lv_font_montserrat_ext_36, &lv_font_montserrat_ext_28, &lv_font_montserrat_ext_24,
  &lv_font_montserrat_ext_20, &lv_font_montserrat_ext_16, &lv_font_montserrat_ext_14,
};
#define LB_FONT_COUNT    (int)(sizeof(LB_FONTS) / sizeof(LB_FONTS[0]))
#define LB_SMALLEST_FONT (&lv_font_montserrat_ext_14)

// `small`: a piece of a longer text, which stays in the smallest font.
struct BigIdLine { const char* text; bool band; bool small; };

// The lines to print and the room for a name broken up.
struct BigIdLines {
  BigIdLine at[LB_LINES_MAX];
  int n;
  char name[LB_NAME_LINES - 1][LABEL_LINE_LEN];
};

static void addLine(BigIdLines* l, const char* text, bool band, bool small) {
  if (l->n < LB_LINES_MAX) l->at[l->n++] = BigIdLine{ text, band, small };
}

// A name that does not fit the width even in the smallest font is broken into
// lines where it can be; what still does not fit the last is cut.
static void addName(BigIdLines* l, const char* name, lv_coord_t w) {
  const char* rest = name;
  int broken = 0;
  while (broken < LB_NAME_LINES - 1 && !fitsLine(rest, LB_SMALLEST_FONT, w)) {
    const char* next = takeLine(rest, LB_SMALLEST_FONT, w, l->name[broken]);
    if (!next) break;
    addLine(l, l->name[broken++], false, true);
    rest = next;
  }
  addLine(l, rest, false, broken > 0);
}

// A fact that would lose the end of its value on one line goes on two, the
// caption above the value: "First used: 03.03." is a wrong date.
static void addFact(BigIdLines* l, const BigIdContent& c, int i, lv_coord_t w) {
  const LabelFact& f = c.facts[i];
  if (fitsLine(c.lines[i], LB_SMALLEST_FONT, w) || !f.caption || !f.value) {
    addLine(l, c.lines[i], false, false);
    return;
  }
  addLine(l, f.caption, false, true);
  addLine(l, f.value, false, true);
}

// The lines in the order a spool is read by; an empty one leaves its room.
static void collectLines(const BigIdContent& c, lv_coord_t w, BigIdLines* out) {
  const SpoolLabelData& d = *c.d;
  const LabelLayout& l = *c.layout;
  out->n = 0;
  if (d.vendor[0] && labelLayoutHas(l, LF_VENDOR)) addLine(out, d.vendor, false, false);
  if (d.material[0] && labelLayoutHas(l, LF_MATERIAL))
    addLine(out, d.material, !labelLayoutOption(l, LO_MATERIAL_PLAIN), false);
  if (d.name[0] && labelLayoutHas(l, LF_NAME)) addName(out, d.name, w);
  for (int i = 0; i < c.n; i++) addFact(out, c, i, w);
}

// The height the lines need at the least: the number gets all the rest.
static lv_coord_t linesLeastHeight(const BigIdLines& l) {
  lv_coord_t h = 0;
  for (int i = 0; i < l.n; i++) {
    h += lineHeight(LB_SMALLEST_FONT) + dots(LB_GAP_PX);
    if (l.at[i].band) h += 2 * dots(LB_BAND_PAD_PX);
  }
  return h;
}

static void drawBand(lv_obj_t* canvas, const BigIdBox& a, lv_coord_t y, const lv_font_t* f, const char* text) {
  const lv_coord_t pad = dots(LB_BAND_PAD_PX);
  fillRect(canvas, a.x, y, a.w, lineHeight(f) + 2 * pad, lv_color_black());
  drawLine(canvas, a.x, y + pad, a.w, f, lv_color_white(), LV_TEXT_ALIGN_CENTER, text);
}

// The lines one above the other in the box, each in the largest font its
// share of the height and the width allow, and none larger than the text line
// above it: a long name set small must not sit over a colour set large. What
// the fonts leave of the height goes between them, up to a limit, and the
// block stands in the middle of the rest.
static void drawLines(lv_obj_t* canvas, const BigIdBox& a, const BigIdLines& l) {
  if (l.n <= 0) return;
  const lv_coord_t pad = 2 * dots(LB_BAND_PAD_PX);
  const lv_font_t* fonts[LB_LINES_MAX] = {};
  lv_coord_t used = 0;
  lv_coord_t ceiling = a.h / l.n;
  for (int i = 0; i < l.n; i++) {
    const BigIdLine& line = l.at[i];
    const lv_coord_t extra = line.band ? pad : 0;
    fonts[i] = line.small ? LB_SMALLEST_FONT
                          : fitFontUnder(line.text, a.w, LV_MIN(ceiling, a.h / l.n - extra), LB_FONTS, LB_FONT_COUNT);
    used += lineHeight(fonts[i]) + extra;
    if (!line.band) ceiling = lineHeight(fonts[i]);
  }
  const lv_coord_t spare = a.h > used ? LV_MIN((a.h - used) / (l.n + 1), dots(LB_SPARE_MAX_PX)) : 0;
  const lv_coord_t block = used + (l.n - 1) * spare;
  lv_coord_t y = a.h > block ? a.y + (a.h - block) / 2 : a.y;
  for (int i = 0; i < l.n; i++) {
    const BigIdLine& line = l.at[i];
    if (line.band) drawBand(canvas, a, y, fonts[i], line.text);
    else drawLine(canvas, a.x, y, a.w, fonts[i], lv_color_black(), LV_TEXT_ALIGN_CENTER, line.text);
    y += lineHeight(fonts[i]) + (line.band ? pad : 0) + spare;
  }
}

// The number across the top, the lines under it. Alone it stands in the
// middle of the whole label.
static void drawOnTop(lv_obj_t* canvas, const BigIdBox& box, const BigIdContent& c, const char* id) {
  BigIdLines lines;
  collectLines(c, box.w, &lines);
  lv_coord_t room = box.h - linesLeastHeight(lines);
  if (lines.n) room = LV_MIN(room, box.h * labelIdShareFor(c.layout->id_share, c.layout->preset) / 100);
  const lv_coord_t height = labelDigitsFitHeight(id, box.w, room);
  const lv_coord_t top = lines.n ? box.y : box.y + (box.h - height) / 2;
  drawBigDigits(canvas, box.x + (box.w - labelDigitsWidth(id, height)) / 2, top, height, id);
  const lv_coord_t used = height ? height + dots(LB_GAP_PX) : 0;
  drawLines(canvas, BigIdBox{ box.x, (lv_coord_t)(box.y + used), box.w, (lv_coord_t)(box.h - used) }, lines);
}

// The number at the right edge, as wide as its share allows and no taller
// than the label; the lines to its left, in the full height.
static void drawOnSide(lv_obj_t* canvas, const BigIdBox& box, const BigIdContent& c, const char* id) {
  const lv_coord_t share = box.w * labelIdShareFor(c.layout->id_share, c.layout->preset) / 100;
  const lv_coord_t most = box.w - dots(LB_TEXT_MIN_W_PX) - 2 * dots(LB_GAP_PX);
  const lv_coord_t height = labelDigitsFitHeight(id, LV_MIN(share, most), box.h);
  const lv_coord_t width = labelDigitsWidth(id, height);
  drawBigDigits(canvas, box.x + box.w - width, box.y + (box.h - height) / 2, height, id);
  const lv_coord_t text_w = box.w - (width ? width + 2 * dots(LB_GAP_PX) : 0);
  BigIdLines lines;
  collectLines(c, text_w, &lines);
  drawLines(canvas, BigIdBox{ box.x, box.y, text_w, box.h }, lines);
}

void labelDrawBigId(lv_obj_t* canvas, const BigIdBox& box, const BigIdContent& c) {
  char id[LB_ID_LEN] = "";
  if (c.d->id > 0) snprintf(id, sizeof(id), "%d", c.d->id);
  // Nothing beside the number: it takes the whole label either way.
  const bool any = c.n > 0 || (labelLayoutHas(*c.layout, LF_VENDOR) && c.d->vendor[0]) ||
                   (labelLayoutHas(*c.layout, LF_MATERIAL) && c.d->material[0]) ||
                   (labelLayoutHas(*c.layout, LF_NAME) && c.d->name[0]);
  if (c.layout->preset == LABEL_PRESET_BIG_ID_SIDE && any) drawOnSide(canvas, box, c, id);
  else drawOnTop(canvas, box, c, id);
}
