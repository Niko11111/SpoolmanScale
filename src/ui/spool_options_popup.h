#pragma once

#include <lvgl.h>

#include "services/spool_choice.h"

// ============================================================
//  OPTIONS OF A CARD THAT CREATES A SPOOL
//
//  The button between Create and Cancel on the card for a new spool (from a
//  tag, from the database) and on the copy card. Behind it a popup of the
//  large size (UI_POPUP_LARGE_W x _H) with what can be set for the one spool
//  being created: its price, its empty spool, its full weight where the card
//  offers it, and its density where the card lacks one. Every step under it - the price pad, the empty spool lists, the
//  pad for a typed weight - has the same size, so nothing jumps between them;
//  each leads back to the Options, and Done leads back to the card. Cancel
//  is the card's alone.
//
//  The card hands over its values by pointer and gets them back changed. Built
//  from the loop only (spoolOptionsTick()), one page at a time: a page is
//  deleted and the next one built in the same pass, and the card stays hidden
//  underneath meanwhile.
// ============================================================

struct SpoolOptionsSpec {
  lv_obj_t*    card;          // hidden while the Options stand
  float*       price;         // the card's price, 0 for none; changed in place
  SpoolChoice* choice;        // the card's empty spool; changed in place
  int          auto_tare_g;   // what Automatic weighs against, 0 when unknown
  int          auto_from;     // STR_ id: where that comes from ("from the tag")
  const char*  maker;         // the spool's maker, shown first among the makers; "" for none
  // STR_ id of the first tile when it is not "Automatic" (the Tare hold says
  // "No offset"), 0 for Automatic.
  int          auto_name;
  bool         density;       // the card lacks a density: offer the row
  // The full weight typed in, 0 for none; changed in place. Null: no row (the
  // copy card files its template's). full_auto_g is what the card files
  // without one, full_assumed whether nothing named it.
  int*         full_g;
  int          full_auto_g;
  bool         full_assumed;
  // Done or the density row: the card is shown again with its new values. With
  // `density` set the card opens its density pad next.
  void (*on_close)(bool density);
  // The close X: whatever the pages were opened from goes as well (the weight
  // popup's Options). Null where that is the card itself: then on_close(false).
  void (*on_dismiss)();
};

// From the card's button. The popup goes up on the loop's next pass.
void showSpoolOptions(const SpoolOptionsSpec& spec);
// The empty spool lists alone, for a spool that exists (the weight popup's
// Options): they open on "Which empty spool?", and a pick, Automatic or Back
// ends them with on_close(false), the close X with on_dismiss() where it is
// set. `price` may be null; the caller sees in
// *choice whether one was picked.
void showSpoolPickList(const SpoolOptionsSpec& spec);
bool spoolOptionsOpen();
// With the card's own close: the Options and whatever step stands go too.
void closeSpoolOptions();
// From the loop: answers parked by the pages, and the page that comes next.
void spoolOptionsTick();
