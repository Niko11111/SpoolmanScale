#pragma once
// ============================================================================
//  ams_mark.h - the corner badge of a bay that is in the printer
//
//  One small label: the hotend letter on a dual-nozzle printer, the play sign
//  on any other. Filled while the printer feeds from the bay, outlined on the
//  bay the other hotend holds. The AMS grid puts it on a tile, the detail
//  card on its swatch, so both say the same thing the same way.
// ============================================================================

#include <lvgl.h>

#include "services/ams_slots.h"

// Puts the badge in the top right corner of parent. nullptr when the LVGL
// pool ran out; the bay then simply goes unmarked.
lv_obj_t* amsMarkBadge(lv_obj_t* parent, AmsHotend hotend, bool feeding);
