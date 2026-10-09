#pragma once

#include <lvgl.h>

// ============================================================
//  NEW SPOOL FROM THE FILAMENT DATABASE: THE PICKER
//
//  For a spool without a maker's chip. A blank NTAG lies on the pad, "New /
//  Copy" offers "New from database", and three taps find the filament:
//  maker (those of the inventory first, then A-Z), material, colour. The
//  colour comes in two steps where a list is long - its family first, then
//  the entry - so a list never runs to the 148 of Bambu Lab PLA. A filament
//  that comes in several sizes asks which one. Then the card of a new spool
//  from a tag (tag_create_popup.h) takes over: price, create, link the tag.
//
//  The data is services/filament_db.h, loaded on its own task; this file
//  only draws it. Every tap is parked and carried out by dbPickTick() on
//  the next loop pass: a list is rebuilt there, never inside the callback
//  of a button that sits on it.
// ============================================================

// Whether the copy popup should offer the picker for the tag on the pad: a
// tag that is not a Bambu one, and a backend with a filament database.
bool dbPickOffered();

// The tap on the copy popup's tile. Parks the open; dbPickTick() opens the
// picker.
void dbPickEntryTap(lv_event_t* e);

// Every loop pass, from the spool flow's deferred actions.
void dbPickTick();

void dbPickClose();

// The picker's screen while it is open, for hiding it with the link overlays.
lv_obj_t* dbPickScreen();
