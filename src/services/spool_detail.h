#pragma once

#include <stdint.h>

#include "services/ams_slots.h"

// ============================================================
//  SPOOL DETAIL
//
//  Everything the detail card behind an AMS bay shows, in one
//  shape. Kept as dependency free as ams_slots.h and for the
//  same reason: the view that draws it must not know which
//  backend filled it, and the backend that fills it must not
//  know LVGL.
//
//  Two sources write into one struct, in this order:
//
//    amsDetailFromTray()      what the AMS answer already knows
//                             about the bay - colour, percentage,
//                             nozzle range, the partner bay
//    backendGetSpoolDetail()  what the database knows about the
//                             spool - name, vendor, weights,
//                             location, dates
//
//  The second lays over the first and only touches the fields it
//  has, so a bay whose spool is not in the database still shows
//  everything the printer reported.
//
//  Deliberately NOT the sm_* globals in app_state.h. Those hold
//  the spool on the pad, and filling them from here would
//  overwrite the scan the user is in the middle of.
// ============================================================

// "Matte - Charcoal (11101)" fits, which is the longest designation on the
// test instance.
#define SD_NAME_MAX      40
#define SD_VENDOR_MAX    24
#define SD_MATERIAL_MAX  24
#define SD_COLOR_MAX     24
#define SD_LOCATION_MAX  32
// "2026-09-16" plus the terminator. Dates are stored as the local ISO day,
// not in the user's display format: the service that fills them has no
// business knowing how the screen writes a date, and date_display.h turns
// one into the other at the point of drawing.
#define SD_DATE_MAX      12
// "AMS B - Fach 2" and "Externer Halter 1" both fit.
#define SD_BAY_MAX       24

// Weight that was never recorded. Distinct from 0 g, which is a spool that
// has been used up - the difference the whole detail card exists to show.
#define SD_WEIGHT_NA     (-1.0f)

struct AmsSpoolDetail {
  char     bay[SD_BAY_MAX];           // built by the view, already translated
  char     name[SD_NAME_MAX];         // filament.name, the trade name
  char     vendor[SD_VENDOR_MAX];     // filament.vendor.name
  char     material[SD_MATERIAL_MAX]; // "PETG HF": type and subgroup
  char     color_name[SD_COLOR_MAX];  // already cleaned, never a hex code
  char     location[SD_LOCATION_MAX];
  char     last_dried[SD_DATE_MAX];   // local ISO day, "2026-09-16"
  char     last_used[SD_DATE_MAX];
  char     backup_of[AMS_LABEL_MAX];  // the bay holding the same filament
  uint32_t color;                     // 0xRRGGBB
  float    remaining_g;               // SD_WEIGHT_NA when unknown
  float    total_g;                   // SD_WEIGHT_NA when unknown
  int      spool_id;                  // 0 when the bay has no spool on file
  int      status_id;                 // FilaMan 1..6, 0 elsewhere
  int16_t  nozzle_min;                // AMS_REMAIN_NA when unknown
  int16_t  nozzle_max;
  int8_t   remain_pct;                // AMS_REMAIN_NA when unknown
  bool     has_color;
  bool     tag_linked;                // a tag is bound to this spool
  bool     archived;
  // The backend answered for this spool. False means the card shows only what
  // the printer reported, and says so rather than leaving blanks.
  bool     found;
};

// Kept in BSS by its one holder, never on the stack: the loop task has 16 kB
// and already warns about its high water mark.
static_assert(sizeof(AmsSpoolDetail) <= 260,
              "AmsSpoolDetail outgrew its budget, check where it is stored");
