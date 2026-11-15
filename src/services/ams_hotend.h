#pragma once

#include "services/ams_slots.h"

// ============================================================
//  HOTENDS OF A DUAL-NOZZLE PRINTER
//
//  tray_now is one number for the whole printer. On an H2D or H2C with
//  both hotends loaded it names only the one in use, and on an H2D it can
//  be a bare bay without its AMS. BamBuddy reports per hotend which bay
//  feeds it (extruder_slots, read from device.extruder.info[].snow) and
//  which hotend is in use (active_extruder). This puts both onto the bays.
//
//  Pure logic on the slot model, no JSON: the parser reads the numbers,
//  this decides what they mean, and the host test checks it on its own.
//  The H3C needs none of it - every bay of its AMS 3H is a hotend, and
//  tray_now already names the one in use.
// ============================================================

// Bambu numbers the hotends 0 = right (the main one) and 1 = left.
#define AMS_HOTENDS        2
#define AMS_EXT_MAIN_ID    255   // external bay of the right hotend
#define AMS_EXT_DEPUTY_ID  254   // external bay of the left hotend

// FilaMan's display API names the hotend per bay in words, from the version
// that carries the field on; an older one leaves it out, which is "none".
static inline AmsHotend amsHotendFromWord(const char* word) {
  if (!word) return AMS_HOTEND_NONE;
  if (strcmp(word, "right") == 0) return AMS_HOTEND_RIGHT;
  if (strcmp(word, "left") == 0)  return AMS_HOTEND_LEFT;
  return AMS_HOTEND_NONE;
}

// What one hotend is fed from. ams_id below 0 when it holds nothing.
struct AmsHotendFeed {
  int ams_id;
  int tray_id;
};

// The bay a hotend reports. An external spool is named by its holder id
// (254 or 255) as the AMS, slot 0, and BamBuddy stores that bay under the
// same number, so it is looked up by that id rather than by its slot.
static inline AmsSlotTray* amsHotendTray(AmsSlotState& s, const AmsHotendFeed& f) {
  if (f.ams_id < 0 || f.tray_id < 0) return nullptr;
  const bool external = (f.ams_id == AMS_EXT_MAIN_ID || f.ams_id == AMS_EXT_DEPUTY_ID);
  for (int u = 0; u < s.unit_count && u < AMS_UNITS_TOTAL; u++) {
    AmsSlotUnit& unit = s.unit[u];
    if (unit.is_ext != external) continue;
    if (!external && unit.ams_id != f.ams_id) continue;
    // An AMS HT has one bay, and firmware numbers it 0 or 1 (FilaMan's display
    // service accepts both too): its only bay is the one meant either way.
    if (unit.is_ht && unit.tray_count == 1 && f.tray_id <= 1) return &unit.tray[0];
    const int want = external ? f.ams_id : f.tray_id;
    for (int t = 0; t < unit.tray_count && t < AMS_MAX_TRAYS; t++) {
      if (unit.tray[t].tray_id == want) return &unit.tray[t];
    }
  }
  return nullptr;
}

// Marks each loaded bay with its hotend, and makes the bay of the hotend in
// use the active one. A hotend whose bay is not on the page changes nothing,
// so tray_now stays the answer then rather than leaving no bay active.
// Returns false, and touches nothing, unless both hotends were reported:
// a single-nozzle X1C sends the extruder block too, with one entry.
static inline bool amsApplyHotends(AmsSlotState& s, const AmsHotendFeed* feed,
                                   int feed_count, int active_hotend) {
  if (!feed || feed_count != AMS_HOTENDS) return false;
  AmsSlotTray* in_use = nullptr;
  for (int h = 0; h < AMS_HOTENDS; h++) {
    AmsSlotTray* t = amsHotendTray(s, feed[h]);
    if (!t) continue;
    t->hotend = (h == 0) ? AMS_HOTEND_RIGHT : AMS_HOTEND_LEFT;
    if (h == active_hotend) in_use = t;
  }
  if (!in_use) return true;
  for (int u = 0; u < s.unit_count && u < AMS_UNITS_TOTAL; u++) {
    for (int t = 0; t < s.unit[u].tray_count && t < AMS_MAX_TRAYS; t++) {
      s.unit[u].tray[t].active = false;
    }
  }
  in_use->active = true;
  return true;
}
