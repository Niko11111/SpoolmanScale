#pragma once

#include <stdint.h>

// Numbers behind how the UI feels, for the verbose log. None of this changes
// what the firmware does: it only measures, so that a performance change can
// be judged by a figure instead of by impression.

// Right before the main lv_timer_handler() in appLoop(). The longest distance
// between two of these is how long the UI went without reading the touch.
// The lv_timer_handler() calls inside blocking operations are deliberately
// not marked: this measures the scale while it is being used, not a download.
void perfLoopMark();

// Right after that same lv_timer_handler(). What lies between the two calls is
// the UI's share of a pass: touch, LVGL timers, rendering and flushing.
void perfUiDone();

// One NFC poll: whether it found a tag and how long the call took. How long a
// successful poll takes is what decides how short the poll timeout may be: a
// tag that needs longer than the timeout is never found, because every poll
// starts the search again.
void perfNfcPoll(bool found, uint32_t poll_ms);

// Writes one line with everything gathered since the previous one, then
// starts over. From the heartbeat, so it shares that line's restraint.
void perfLogWindow();
