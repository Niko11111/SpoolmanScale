#pragma once

#include <lvgl.h>

// ============================================================
//  AN EMPTY SPOOL TAKEN OFF BY HAND
//
//  For a spool that has no tag and no entry: hold Tare, pick the empty spool
//  from the same lists a new spool gets (spool_options_popup.h) or type its
//  weight, and every reading after that leaves it out (g_spool_offset_g).
//  The pad reads minus that weight while it is empty. A tap on Tare zeroes as
//  always, and the offset goes with it. The button shows it under its word
//  TARE.
// ============================================================

// Adds the hold and the mark to the Tare button. Without a load cell there is
// no button, and nothing happens.
void tareOffsetAttach(lv_obj_t* tare_button);
// True once for the click LVGL sends when a hold is let go: Tare's own
// handler returns on it instead of taring.
bool tareOffsetTookClick();
// From the loop: the mark follows the offset, which a tare anywhere may clear.
void tareOffsetTick();
