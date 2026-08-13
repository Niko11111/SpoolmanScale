#pragma once

#include <lvgl.h>

void btn_dried_cb(lv_event_t *e);

// Runs the queued last_dried write. Must be called from appLoop(), never from
// an event callback: in FilaMan mode this is a GET followed by a PATCH.
void handleDriedDeferredAction();
