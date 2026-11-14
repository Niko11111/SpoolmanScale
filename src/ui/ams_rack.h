#pragma once
// ============================================================================
//  ams_rack.h - the AMS 3H of an H3C, drawn the way it stands in the printer
//
//  Nine bays in two rows: four at the back (labels 2, 4, 6, 8; tray ids 1, 3,
//  5, 7), offset by half a bay over the five at the front (labels 1 to 9 odd;
//  ids 0, 2, 4, 6, 8). The back row is drawn on top, as BamBuddy does. The
//  bays of the heated chamber (the unit's dryer_mask, ids 5 and 7 on the
//  H3C) get a frame with the chamber's own readings to their right, amber
//  with a flame while it dries.
//
//  The AMS view owns the tiles; this file places them and draws the chamber
//  around them.
// ============================================================================

#include <lvgl.h>

#include "services/ams_slots.h"

// Builds one tile at x, y, w wide; nullptr when the LVGL pool ran out.
typedef lv_obj_t* (*AmsRackTileFn)(const AmsSlotUnit& unit,
                                   const AmsSlotTray& tray, int x, int y, int w);

// Where the unit goes: its parent, the free width between left and right,
// and the top of the back row.
struct AmsRackArea {
  lv_obj_t* body;
  int       left;
  int       right;
  int       top;
  int       tile_h;
  int       gap;
};

// Whether a unit is drawn as a rack rather than as one row of bays.
bool amsUnitIsRack(const AmsSlotUnit& unit);

// Lays out the nine bays and the chamber. Returns the height from area.top
// to the bottom of the front row, -1 when the pool ran out; tiles counts the
// tiles built.
int amsRackBuild(const AmsRackArea& area, const AmsSlotUnit& unit,
                 AmsRackTileFn tile, int& tiles);
