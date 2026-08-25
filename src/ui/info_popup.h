#pragma once

#include <lvgl.h>

// Explanation modal for a single setting: title, wrapped body text, one way
// back. Nothing is decided here - it only tells the user what the setting they
// are looking at actually does.
//
// Both strings are taken from the T() table by id rather than by pointer,
// because the handler that opens this runs long after the caller's local
// buffers have gone out of scope.
//
// The same modal also reports the outcome of something the user set in motion,
// and that has to look different from a help text or it reads as an
// explanation rather than an answer. Those two tones carry a glyph, take the
// colours of the question that preceded them, and end in OK rather than Back -
// there is nothing to go back to.
enum InfoPopupTone : uint8_t {
  INFO_PLAIN = 0,   // help text behind a settings row
  INFO_WARN,        // something did not work
  INFO_DONE,        // something worked
};

void showInfoPopup(int title_id, int text_id, uint8_t tone = INFO_PLAIN);

// Ready-made LV_EVENT_CLICKED handler. Attach it to the help button that
// makeListBtn() hands back and pass INFO_POPUP_ARG(...) as user_data; no
// per-call-site lambda needed.
void infoPopupEventCb(lv_event_t *e);

// Both ids ride in the single user_data slot. A StringID is a small enum, well
// inside 16 bits, so packing them is safe and saves a heap allocation per row.
#define INFO_POPUP_ARG(title_id, text_id) \
  ((void*)(intptr_t)((((int)(title_id)) << 16) | ((int)(text_id))))
