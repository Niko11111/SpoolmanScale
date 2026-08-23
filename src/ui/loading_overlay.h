#pragma once

#include <stddef.h>

// ============================================================
//  "SOMETHING IS HAPPENING" WHILE THE SCALE IS BUSY
//
//  Loading a full inventory blocks for seconds, and the list
//  flows do it from inside a button callback. That is why the
//  earlier attempts at feedback showed nothing: LVGL never got
//  back to drawing between setting a label and the blocking
//  call, so the text existed but was never on screen.
//
//  This draws itself. loadingOverlayShow() paints immediately,
//  and the tick below repaints as the response comes in, so
//  the indicator keeps moving through the transfer and the
//  JSON parse - which is the long part.
//
//  It never calls lv_timer_handler(). That would be re-entrant
//  from a callback and would process touches mid-load, which
//  could start a second request on top of the running one.
//  lv_refr_now() only redraws: no timers, no input, no
//  re-entrancy, and no need to lock the touchscreen.
// ============================================================

// Puts the overlay up and paints it before returning. Safe to call twice; the
// second call only replaces the text.
void loadingOverlayShow(const char* text);

// Replaces the caption and repaints. For the phases the caller already has:
// fetching, then filtering.
void loadingOverlaySetText(const char* text);

// Advances the indicator and repaints, at most every LOADING_TICK_MS. Cheap to
// call often - it is wired to the response reader, which calls it far more
// than there are frames to draw.
void loadingOverlayTick();

// Same, as the progress hook signature. `bytes_read` is shown alongside the
// indicator so a slow network looks slow rather than stuck.
void loadingOverlayProgress(size_t bytes_read);

// Takes it down. Must be called on every path out of the work, including the
// ones that fail early, or it stays on top of whatever is built next.
void loadingOverlayHide();
