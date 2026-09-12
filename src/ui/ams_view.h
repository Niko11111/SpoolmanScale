#pragma once

#include <stdint.h>

#include "services/ams_slots.h"

// ============================================================
//  AMS VIEW
//
//  One full page showing the bays of a printer, grouped by unit.
//  Knows no backend and makes no request of its own: it is handed
//  a filled AmsSlotState and draws it. That is what lets the same
//  page serve BamBuddy and FilaMan, and a third backend later.
//
//  Two modes. BROWSE just shows the AMS. PICK adds the weighed
//  spool to the header and turns every bay into a button, for the
//  backends that can pin a spool to a bay.
// ============================================================

enum AmsViewMode : uint8_t {
  AMS_VIEW_BROWSE = 0,
  AMS_VIEW_PICK   = 1
};

// Called with the pair the user tapped, never an index into a list: the list
// can have been rebuilt between the drawing and the answer.
typedef void (*AmsPickCb)(int ams_id, int tray_id);

// Opens the page. Does no work itself beyond raising a flag - the fetch that
// fills it blocks for as long as the server takes, and that must not happen
// inside an LVGL callback.
void requestAmsView(AmsViewMode mode, AmsPickCb cb = nullptr,
                    const char* headline = nullptr);

// Runs the parked work: build, fetch, redraw, close. Called from appLoop().
void handleAmsViewDeferredActions();

// True while the page is up, so the loop knows a fetch may still be running.
bool isAmsViewOpen();

// The printer the page last read, or 0. The pick callback needs it: the bay
// is only half an address, and the view is what resolved the other half.
int amsViewPrinterId();

// Hides the page without freeing it, for hideAllOverlays(). Every other
// overlay is treated the same way there: hidden on the way past, freed in
// showMainScreen(). An overlay in neither list stays on screen while the
// rest of the interface navigates away.
void hideAmsViewOverlays();

// Frees the page and clears every pointer into it, for showMainScreen().
void destroyAmsView();
