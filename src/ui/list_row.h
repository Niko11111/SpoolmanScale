#pragma once

#include <lvgl.h>

// The rows of the long lists: spools to link or copy, their materials and
// makers, and the locations. Every row of a kind is built from the same
// shared styles, so they look alike wherever they appear and a row costs no
// local style properties: with 17 of them a row of a 100 spool list held
// about 100 bytes of the LVGL pool for its looks alone.
//
// Geometry (size, position, text width) stays with the caller; the look
// lives here. A highlight is a second shared style added after the base,
// so it wins where both say something.

// The frame of a row.
enum ListRowFrame : uint8_t {
  LR_FRAME_SPOOL,      // surface fill, soft line, no padding
  LR_FRAME_LOCATION,   // chip fill, divider line, a little room below the text
};

// What a label in a row shows, which fixes its font and colour.
enum ListRowText : uint8_t {
  LR_TEXT_ID,          // the spool number
  LR_TEXT_NAME,        // material and name
  LR_TEXT_WEIGHT,      // what is left on the spool
  LR_TEXT_MATERIAL,    // a material group
  LR_TEXT_MAKER,       // a maker
  LR_TEXT_COUNT,       // how many spools a group holds, "3 x"
  LR_TEXT_LOCATION,    // a location, centred
  LR_TEXT_KINDS
};

// A button in `list`, nullptr when LVGL had no room for it.
lv_obj_t* listRowCreate(lv_obj_t* list, ListRowFrame frame, lv_coord_t w, lv_coord_t h);
lv_obj_t* listRowLabel(lv_obj_t* row, ListRowText kind, const char* text);
// The 14 px colour square, painted from a "#RRGGBB" or "RRGGBBAA" string.
lv_obj_t* listRowSwatch(lv_obj_t* row, const char* color_hex);

// A spool whose article number matched: a 2 px frame in the house green.
void listRowMarkHit(lv_obj_t* row);
// A weight that matches the scale, in the house green.
void listRowLabelHit(lv_obj_t* label);
// The location the spool is in now: its row and its text in the accent.
void listRowMarkCurrent(lv_obj_t* row, lv_obj_t* label);
