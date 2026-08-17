#pragma once

// Background firmware update check.
//
// The previous version called the GitHub API straight from the boot path, with
// an eight second timeout and no separate task. lv_timer_handler() did not run
// for the whole request, so the display froze, and the TLS handshake claimed
// around 40 kB of heap at the exact moment the boot needed it most. It was
// switched off for both reasons and never switched back on.
//
// This one runs in its own FreeRTOS task on the other core. A slow, hanging or
// failing request is invisible to loop(), and everything that is not thread
// safe - LVGL, the SD log, NVS - happens in updateCheckTick() on the loop task.
void updateCheckScheduleFirstRun();

// Bring the next check forward, used when the user switches the option back on
// and expects to see a result rather than to wait a day.
void updateCheckScheduleIn(unsigned long delay_ms);

// Call once per loop pass. Starts the task when a check is due and applies the
// result of a finished one.
void updateCheckTick();
