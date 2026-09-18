#pragma once

#include <ctype.h>
#include <stdint.h>
#include <string.h>

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
//  One field the second never touches: printer_type, the printer's
//  own word for the material. Once both have written, the view
//  holds it against the database's material and sets
//  type_conflict - see sdMaterialContradicts() below.
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
// The composed title, "<unit> - Fach N": a unit name of the user's choosing
// (AMS_NAME_MAX) plus the bay, with room to spare. 24 held "AMS 1 - Fach 2"
// and cut "Werkstatt AMS oben - Fach 3" to "Werkstatt AMS oben - F", without
// a word, because snprintf truncates in silence.
#define SD_BAY_MAX       40

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
  // What the printer itself calls the material in the bay, empty when the
  // backend does not pass it on. Never overwritten by the database: it is the
  // one field that says what is physically there.
  char     printer_type[AMS_TYPE_MAX];
  SpoolColor color;                   // the bay's, see AmsSlotTray::color
  float    remaining_g;               // SD_WEIGHT_NA when unknown
  float    total_g;                   // SD_WEIGHT_NA when unknown
  int      spool_id;                  // 0 when the bay has no spool on file
  int      status_id;                 // FilaMan 1..6, 0 elsewhere
  int16_t  nozzle_min;                // AMS_REMAIN_NA when unknown
  int16_t  nozzle_max;
  int8_t   remain_pct;                // AMS_REMAIN_NA when unknown
  bool     tag_linked;                // a tag is bound to this spool
  bool     archived;
  // The backend answered for this spool. False means the card shows only what
  // the printer reported, and says so rather than leaving blanks.
  bool     found;
  // The printer reports another material than the spool on file has: the
  // assignment has most likely outlived the spool it was made for. The card
  // still shows the spool the database names - that is what the backend
  // believes and what a write would go to - and says that the two disagree.
  bool     type_conflict;
};

// Kept in BSS by its one holder, never on the stack: the loop task has 16 kB
// and already warns about its high water mark.
static_assert(sizeof(AmsSpoolDetail) <= 260,
              "AmsSpoolDetail outgrew its budget, check where it is stored");

// ------------------------------------------------------------
//  Does the bay hold what the database says it holds?
//
//  BamBuddy resolves a bay to a spool through its assignment list. With
//  Spoolman behind it, nothing ever checks that list against the printer: a
//  spool without a Bambu tag that replaces another one inherits the old
//  assignment, and the card then showed the PLA spool that had been taken
//  out over a bay the grid rightly called PETG.
//
//  The answer leans towards "no contradiction". A material is free text on
//  the server - "PLA+", "HTPLA", "PolyTerra PLA", "PETG HF" - and a warning
//  on every one of those would teach the user to ignore it. So it takes two
//  materials neither of which names the other's family: PETG against PLA,
//  ABS against ASA. An empty side is never a contradiction, it is a backend
//  that did not say.
// ------------------------------------------------------------

// Longest family name that has to fit: "NYLON" and "PETG" do with room to
// spare, and a longer word is cut, which only makes it match more easily.
#define SD_FAMILY_MAX  12

// The family a material belongs to: the leading run of letters and digits,
// upper-cased. "PETG" of "PETG-CF", "PLA" of "PLA+", "PA6" of "PA6-GF".
static inline void sdMaterialFamily(const char* s, char* out, size_t n) {
  if (!out || n == 0) return;
  out[0] = '\0';
  if (!s) return;
  size_t k = 0;
  while (*s == ' ') s++;
  while (*s && isalnum((unsigned char)*s) && k + 1 < n) {
    out[k++] = (char)toupper((unsigned char)*s++);
  }
  out[k] = '\0';
  // Nylon is PA by another name, to the printer and to BamBuddy alike.
  if (n >= 3 && strcmp(out, "NYLON") == 0) strcpy(out, "PA");
}

// Whether needle, already upper-cased, occurs anywhere in hay.
static inline bool sdContainsNoCase(const char* hay, const char* needle) {
  if (!hay || !needle) return false;
  const size_t len = strlen(needle);
  if (len == 0) return false;
  for (; *hay; hay++) {
    size_t i = 0;
    while (i < len && hay[i] && toupper((unsigned char)hay[i]) == needle[i]) i++;
    if (i == len) return true;
  }
  return false;
}

static inline bool sdMaterialContradicts(const char* printer_type,
                                         const char* db_material) {
  char p[SD_FAMILY_MAX], d[SD_FAMILY_MAX];
  sdMaterialFamily(printer_type, p, sizeof(p));
  sdMaterialFamily(db_material, d, sizeof(d));
  if (!p[0] || !d[0]) return false;
  // Either side may carry the other's family anywhere in it: "HTPLA" and
  // "Silk PLA" are PLA, and a printer's "PA6-CF" is the database's "PA-CF".
  return !sdContainsNoCase(db_material, p) && !sdContainsNoCase(printer_type, d);
}

// The unit a card's bay belongs to, when the card may offer to record a
// drying for every spool in it (an AMS 2 Pro, see amsUnitOffersDriedAll()).
// Kept apart from AmsSpoolDetail: that one describes a spool and is copied
// around with the card, this one describes the unit and only the drying
// question reads it.
#define SD_UNIT_NAME_MAX  (AMS_NAME_MAX + 8)

struct AmsUnitSpools {
  char    name[SD_UNIT_NAME_MAX];   // "AMS 1", as the card's title writes it
  // Bays that physically hold a spool and have one on file, packed from the
  // front. Not indexed by bay: the question counts them and the worker walks
  // them, and neither cares which bay a spool is in.
  int     spool_id[AMS_MAX_TRAYS];
  int     printer_id;
  uint8_t ams_id;
  uint8_t count;                    // 0 = nothing to offer
};

static_assert(sizeof(AmsUnitSpools) <= 64,
              "AmsUnitSpools outgrew its budget, check where it is stored");
