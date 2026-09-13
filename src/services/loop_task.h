#pragma once

// ============================================================
//  WHICH TASK IS THIS
//
//  Almost everything in this firmware runs on the Arduino loop task, and a
//  few things must: LVGL, the SD card, the stall counters the countdowns
//  read. The web worker runs backend requests on a second task, so the
//  places that must not be touched from there ask this first.
// ============================================================

// Remembers the calling task as the loop task. Called from setup(), which
// runs on the same task loop() does.
void loopTaskRemember();

// True on the loop task, and before it was remembered - so nothing changes
// its behaviour on a build that never calls loopTaskRemember().
bool onLoopTask();
