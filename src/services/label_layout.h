#pragma once

#include <stdint.h>

// ============================================================
//  WHAT A SPOOL LABEL SHOWS
//
//  The one template the label editor in the browser sets: an
//  arrangement, which fields go on the label and a few options.
//  The renderer reads it, nothing else decides. The default is
//  the label as it printed before the editor existed, bit for
//  bit, so a scale that never opens the editor prints as before.
//
//  Built to grow: a field or an option is a bit, a new one goes
//  at the end, none is ever renumbered or reused (the bits are
//  NVS content). LABEL_LAYOUT_VERSION is stored alongside, so a
//  later version can tell a mask saved before a field existed
//  from one that switched it off.
// ============================================================

#define LABEL_LAYOUT_VERSION 1

// Where the blocks go. NVS content like the bits below.
enum LabelPreset : uint8_t {
  LABEL_PRESET_STANDARD = 0,   // maker large on top, band, title, facts beside the code
  LABEL_PRESET_COMPACT  = 1,   // no large maker: it joins the facts, the code grows
  LABEL_PRESET_BIG_QR   = 2,   // the code takes the full height, the text a column
  LABEL_PRESET_COUNT
};

enum LabelField : uint8_t {
  LF_VENDOR = 0, LF_MATERIAL = 1, LF_NAME = 2, LF_SPOOL_ID = 3,
  LF_COLOR = 4, LF_DATE = 5, LF_QR = 6, LF_BRAND = 7,
  // Off by default: the default stays the label from before, and a mask
  // saved before the field existed has the bit clear already.
  LF_ARTICLE = 8,
  LABEL_FIELD_COUNT
};

enum LabelOption : uint8_t {
  LO_MATERIAL_PLAIN = 0,   // the material as a line, not white on a black band
  LO_DATE_ADDED     = 1,   // the day the spool was added, never the first use
  LABEL_OPTION_COUNT
};

struct LabelLayout {
  uint8_t  preset;
  uint32_t fields;    // bit n set: LabelField n is on the label
  uint32_t options;   // bit n set: LabelOption n applies
};

// The fields of the label from before on, no option, the standard arrangement.
LabelLayout labelLayoutDefault();
// Known bits only, a known arrangement: what the browser sent may be anything.
LabelLayout labelLayoutSanitized(const LabelLayout& in);
bool labelLayoutHas(const LabelLayout& layout, LabelField field);
bool labelLayoutOption(const LabelLayout& layout, LabelOption option);

// Cached after the first read; every write goes through the save.
LabelLayout labelLayoutLoad();
bool labelLayoutSave(const LabelLayout& layout);
