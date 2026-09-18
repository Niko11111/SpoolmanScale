#pragma once

#include <lvgl.h>

void btn_dried_cb(lv_event_t *e);

// Runs the queued last_dried write. Must be called from appLoop(), never from
// an event callback: in FilaMan mode this is a GET followed by a PATCH.
void handleDriedDeferredAction();

struct DriedBatchResult;

// The AMS card's batch has finished. If the spool on the pad was part of it,
// its label takes the new date. Called from the loop by whoever collects the
// result.
void driedActionApplyBatch(const DriedBatchResult& r);
