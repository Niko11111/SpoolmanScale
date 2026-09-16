#pragma once

#include <lvgl.h>

// ============================================================
//  FILAMAN STATUS: THE CHIP AND THE PICKER
//
//  One spool status, one look. Both used to live inside
//  more_info_screen.cpp as statics; the AMS detail card then
//  needed the same two controls and got its own, smaller pair -
//  which is how the same concept came to look like two things.
//  Moved here whole rather than copied, so there is one grid,
//  one set of measurements and one archive warning colour.
//
//  What stayed with each caller is what differs: which spool is
//  meant, and what happens to the answer. The archive branch in
//  particular belongs to the More Info screen, which tears its
//  own detail view down before it runs.
// ============================================================

// The chip's footprint, shared with the headers that lay out around it.
#define STATUS_CHIP_W 150
#define STATUS_CHIP_H 44

// The answer, delivered from the loop. 0 means the picker was dismissed
// without a choice.
typedef void (*StatusPickCb)(int status_id);

// The chip that shows a status, as a button when cb is given and as a plain
// chip when it is null. 150x44, sized for the free half of a 52 px header,
// so it costs no height on either screen.
lv_obj_t* buildStatusChip(lv_obj_t* parent, int x, int y, int status_id,
                          lv_event_cb_t cb);

// Opens the six statuses as a 2x3 grid. Six fixed values do not earn a scroll
// list, and a grid saves the mis-tap a narrow row invites on a touchscreen.
//
// Safe to call from an event callback: it only creates. The answer arrives
// through cb one loop pass after the picker is gone, so a caller's blocking
// write never runs with the overlay still on screen.
void showStatusPicker(int current_status_id, StatusPickCb cb);

// Takes the picker down without an answer. For hideAllOverlays() and for a
// caller that is being torn down.
void closeStatusPicker();

bool isStatusPickerOpen();

// Releases the overlay and, one pass later, delivers the answer. Call from
// appLoop() before the handlers of the screens that use the picker.
void handleStatusPickerDeferredActions();
