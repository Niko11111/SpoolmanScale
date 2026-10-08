#pragma once

#include <lvgl.h>

// ============================================================
//  NEW SPOOL FROM A TAG: THE CARD
//
//  One card for all three backends. It opens at once, says what the tag is
//  (colour, product, article, weight) and looks the filament up on the next
//  loop pass: there, or created along with the spool, or not possible. The
//  answer row creates; the result goes to the main screen the way a copy
//  does (finishCopyFlow). The work is in services/backend_api.h.
// ============================================================

// Whether the tag that was scanned last can become a new spool: one an input
// file of services/tag_create.cpp recognises (an NTAG carries no material,
// and every backend needs one) and a backend with a way to do it.
bool tagCreateOffered();

// The entry to the card on the copy and the link popup: full width, in the
// colour of going ahead. Raises newtag_open_pending; the loop closes the
// popup it sits on and opens the card.
lv_obj_t* tagCreateEntryButton(lv_obj_t* parent, int w, int h, int y);

// Builds the card for the tag that was scanned last. Loop task only.
void showTagCreatePopup();

// The same card for a filament picked from the backend's database
// (db_pick_screen.h) rather than read off a tag. The tag on the pad is
// linked to the new spool all the same. Loop task only.
struct TagCreateInput;
void showTagCreatePopupFor(const TagCreateInput& in);

// The lookup and the creation, one loop pass after the card or its button
// asked for them, so the card is drawn before the loop stands still.
void tagCreatePopupTick();

void closeTagCreatePopup();

// The card's screen while it is open, for hiding it with the link overlays.
lv_obj_t* tagCreatePopupScreen();
