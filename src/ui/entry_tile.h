#pragma once

#include <lvgl.h>

// ============================================================
//  THE TILES OF AN ENTRY POPUP
//
//  "New / Copy" and "Link spool" ask which way to go. The ways people take
//  most are tiles of the same size and the same neutral look, a symbol above
//  its caption, none pushed over the others: the active spools, the archived
//  ones and a new one on New / Copy, the list on Link. The rare way, the
//  spool ID, and Cancel sit in one low row under them, the same on both.
// ============================================================

struct EntryRect {
  lv_coord_t x, y, w, h;
};

// Tile i of n in the row of tiles, all of one width.
EntryRect entryTileRect(int i, int n);

// A tile: the symbol over the caption, both centred, the caption wrapped to
// the tile's width. Every tile's caption starts on the same line, one of one
// line and one of two alike.
lv_obj_t* entryTile(lv_obj_t* parent, const EntryRect& r, const char* symbol,
                    const char* caption, lv_event_cb_t cb);

// The low row: the spool ID on the left, Cancel on the right.
void entryBottomRow(lv_obj_t* parent, const char* id_caption, lv_event_cb_t id_cb,
                    lv_event_cb_t cancel_cb);
