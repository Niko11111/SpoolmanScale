#pragma once

#include <lvgl.h>

#include "services/spool_detail.h"

// ============================================================
//  AMS DETAIL POPUP
//
//  What the backend knows about the spool in one AMS bay, as a
//  card over the AMS view. The view stays standing behind it:
//  the card answers nothing, it only shows, so there is nothing
//  to come back to.
//
//  It draws a filled AmsSpoolDetail and fetches nothing itself.
//  Whoever opens it has already done the request from the loop -
//  the rule that no HTTP runs inside an LVGL callback holds here
//  as everywhere else.
// ============================================================

// Builds and shows the card. Replaces one that is already up, so a second
// tap cannot stack two. Safe to call with detail.found false: the card then
// shows what the printer reported and says that the database had nothing.
void showAmsDetailPopup(const AmsSpoolDetail& detail);

// Takes the card down. Called by hideAllOverlays() and by the AMS view when
// it closes - without one of those the card would outlive the page under it
// and sit on top of whatever comes next.
void closeAmsDetailPopup();

// Whether the card is up. Joins uiModalWaiting(), so the expensive spool
// lookup stands aside while it is: lv_timer_handler() does not run during a
// blocking request, and its close button would be dead.
bool isAmsDetailPopupOpen();

// Runs the writes the card's buttons park: the drying date and, on FilaMan,
// the status. Must be called from appLoop() - both are HTTP, and the card
// that asked for them is still on screen. The drying date for a whole AMS 2
// Pro is only started here; it runs on a task of its own, see dried_batch.h.
//
// The card is the one place a spool can be handled without taking it out of
// the AMS, which is the whole point: after a drying cycle the bay is tapped
// and the date is recorded, instead of pulling the spool to put it on the pad.
void handleAmsDetailDeferredActions();

// The unit the next card's bay belongs to, when the card may offer to record
// a drying for all of it; nullptr when not. Set by the AMS view right before
// showAmsDetailPopup(), every time, so an earlier unit cannot linger.
void amsDetailSetUnit(const AmsUnitSpools* unit);

// Collects the result of a drying batch the card started, updates the card
// and the spool on the pad, and redraws once nothing stands above the card.
// From appLoop(), every pass: the batch keeps every drying button locked
// until its result has been taken.
void amsDetailBatchTick();
