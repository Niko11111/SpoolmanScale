#pragma once

#include <stdint.h>

// ============================================================
//  WHICH LABEL SIZES THE SCALE PRINTS
//
//  Any size the printer takes prints, as long as its canvas fits
//  the memory set aside for it. A size someone measured in the
//  simulator and printed on paper is checked; every other one is
//  unchecked: it prints, its line budget is computed, and the
//  pages say to look at the preview first. The sizes are millimetres
//  as printed on the roll: width across the head, length along the
//  feed. Pure: numbers in, a verdict out.
// ============================================================

// Width across the head by length along the feed, in mm.
struct LabelMediaSize { uint8_t width_mm, length_mm; };

// The checked sizes, in the order the printer screen offers them.
extern const LabelMediaSize LABEL_MEDIA_SIZES[];
extern const int LABEL_MEDIA_SIZE_COUNT;
// Rolls on sale for these printers that nobody has printed on yet: offered
// as unchecked cards, so the common ones need no typing.
extern const LabelMediaSize LABEL_MEDIA_SUGGESTED[];
extern const int LABEL_MEDIA_SUGGESTED_COUNT;

enum LabelMediaStatus : uint8_t {
  LABEL_MEDIA_CHECKED = 0,     // measured in the simulator and printed on paper
  LABEL_MEDIA_UNCHECKED,       // the printer takes it; its line budget is computed
  LABEL_MEDIA_OUT_OF_RANGE,    // narrower, wider, shorter or longer than the printer takes
  LABEL_MEDIA_TOO_LARGE,       // its canvas would not fit the memory set aside for it
  LABEL_MEDIA_TOO_SMALL,       // no arrangement keeps the header and one fact line on it
};

// What a printer takes, from its profile: the stock in mm, the head's
// resolution and the widest print row in dots.
struct LabelMediaRange {
  uint16_t min_width_mm, max_width_mm;
  uint16_t min_length_mm, max_length_mm;
  uint16_t dpi;
  uint16_t max_row_dots;
};

// The canvas a label is drawn on before it is packed for the head: LVGL true
// colour, 16 bits a dot (LV_COLOR_DEPTH in lv_conf.h).
#define LABEL_CANVAS_BYTES_PER_DOT 2
// What a label's canvas may take of the PSRAM. 70 x 80 at 203 dpi takes
// 717 kB; the M220's longest stock, 75 x 150, would take 1.4 MB of the 2 MB
// the board has, next to the screenshots and the AMS state that live there.
#define LABEL_CANVAS_MAX_BYTES (1024u * 1024u)

// Millimetres to dots at this resolution, rounded as the printer code does.
uint16_t labelMediaDots(uint16_t dpi, uint16_t mm);
// The bytes the canvas of a label of this size takes on this printer.
uint32_t labelMediaCanvasBytes(const LabelMediaRange& range, uint16_t width_mm, uint16_t length_mm);
// Whether the size is one of the checked ones.
bool labelMediaChecked(uint16_t width_mm, uint16_t length_mm);
// Whether the size is one of the suggested rolls.
bool labelMediaSuggested(uint16_t width_mm, uint16_t length_mm);
// What the scale makes of this size on this printer. TOO_SMALL is not decided
// here: that takes a measurement (labelMediaStatusFor() in label_capacity.h).
LabelMediaStatus labelMediaStatus(const LabelMediaRange& range, uint16_t width_mm, uint16_t length_mm);
