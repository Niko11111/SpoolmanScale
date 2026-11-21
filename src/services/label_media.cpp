#include "services/label_media.h"

// Checked: measured in the simulator and printed on paper. 40 x 30 and 50 x 30
// on the M220 for 0.8.0 (Nikolai, 26.09.2026); 60 x 30 for the 3 inch heads
// (M220, M200, M221, PM245-BT), asked for on Discord (13.11.2026). 12 x 40 is
// the D110's tape, which only it takes.
const LabelMediaSize LABEL_MEDIA_SIZES[] = {
  {40, 30}, {50, 30}, {60, 30}, {12, 40},
};
const int LABEL_MEDIA_SIZE_COUNT = sizeof(LABEL_MEDIA_SIZES) / sizeof(LABEL_MEDIA_SIZES[0]);

// Rolls sold for the M220, the B1 and the M2 that nobody has printed on yet.
// 60 x 40 and 70 x 80 come with the M220 kit (issue #92); a printer that
// cannot take one does not show it.
const LabelMediaSize LABEL_MEDIA_SUGGESTED[] = {
  {40, 20}, {50, 50}, {60, 40}, {70, 80},
};
const int LABEL_MEDIA_SUGGESTED_COUNT = sizeof(LABEL_MEDIA_SUGGESTED) / sizeof(LABEL_MEDIA_SUGGESTED[0]);

// As a ratio so the rounding stays exact: at 203 dpi the 8 dots to the
// millimetre the M220 was measured with (label_printer.cpp does the same).
uint16_t labelMediaDots(uint16_t dpi, uint16_t mm) {
  return (uint16_t)((uint32_t(mm) * dpi * 10 + 127) / 254);
}

// A roll wider than the head prints the head's width of it.
uint32_t labelMediaCanvasBytes(const LabelMediaRange& range, uint16_t width_mm, uint16_t length_mm) {
  uint32_t across = labelMediaDots(range.dpi, width_mm);
  if (range.max_row_dots && across > range.max_row_dots) across = range.max_row_dots;
  return across * labelMediaDots(range.dpi, length_mm) * LABEL_CANVAS_BYTES_PER_DOT;
}

static bool inList(const LabelMediaSize* list, int count, uint16_t width_mm, uint16_t length_mm) {
  for (int i = 0; i < count; i++)
    if (list[i].width_mm == width_mm && list[i].length_mm == length_mm) return true;
  return false;
}

bool labelMediaChecked(uint16_t width_mm, uint16_t length_mm) {
  return inList(LABEL_MEDIA_SIZES, LABEL_MEDIA_SIZE_COUNT, width_mm, length_mm);
}

bool labelMediaSuggested(uint16_t width_mm, uint16_t length_mm) {
  return inList(LABEL_MEDIA_SUGGESTED, LABEL_MEDIA_SUGGESTED_COUNT, width_mm, length_mm);
}

LabelMediaStatus labelMediaStatus(const LabelMediaRange& range, uint16_t width_mm, uint16_t length_mm) {
  if (!range.dpi || width_mm < range.min_width_mm || width_mm > range.max_width_mm ||
      length_mm < range.min_length_mm || length_mm > range.max_length_mm)
    return LABEL_MEDIA_OUT_OF_RANGE;
  if (labelMediaCanvasBytes(range, width_mm, length_mm) > LABEL_CANVAS_MAX_BYTES)
    return LABEL_MEDIA_TOO_LARGE;
  return labelMediaChecked(width_mm, length_mm) ? LABEL_MEDIA_CHECKED : LABEL_MEDIA_UNCHECKED;
}
